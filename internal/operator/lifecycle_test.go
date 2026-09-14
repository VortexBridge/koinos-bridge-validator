package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReviewedWorkerLifecycleSurvivesOperatorRestart(t *testing.T) {
	root, err := os.MkdirTemp("", "vol-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	binary := filepath.Join(root, "source-validator")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/koinos-bridge-validator")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	digest := hex.EncodeToString(h[:])
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var result interface{}
		switch req.Method {
		case "eth_blockNumber":
			result = "0x0"
		case "chain.get_head_info":
			result = map[string]interface{}{"last_irreversible_block": "0", "head_topology": map[string]interface{}{"height": "0", "id": "0x1220" + strings.Repeat("00", 32)}}
		default:
			t.Errorf("unexpected method %s", req.Method)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer rpc.Close()
	base := filepath.Join(root, "validator")
	os.Mkdir(base, 0700)
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := port.Addr().String()
	port.Close()
	config := []byte(fmt.Sprintf("bridge:\n  instance-id: local-fixture\n  log-level: error\n  api-url: %s\n  ethereum-rpc: %s\n  koinos-rpc: %s\n  ethereum-contract: '0x1111111111111111111111111111111111111111'\n  koinos-contract: '1111111111111111111114oLvT2'\n  ethereum-polling-time: 10\n  koinos-polling-time: 10\n", address, rpc.URL, rpc.URL))
	if err := os.WriteFile(filepath.Join(base, "config.yml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "operator")
	s, err := OpenStore(data)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	if _, err := s.RegisterWorker(base, binary, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong binary digest accepted")
	}
	registration, err := s.RegisterWorker(base, binary, digest)
	if err != nil {
		t.Fatal(err)
	}
	review := registrationDigest(registration)
	// The executable is a snapshot: replacing the source cannot replace the launch target.
	if err := os.WriteFile(binary, []byte("changed source"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartWorker(context.Background(), strings.Repeat("f", 64)); err == nil {
		t.Fatal("stale registration accepted")
	}
	if err := os.WriteFile(filepath.Join(base, "config.yml"), append(config, []byte("  reset: true\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartWorker(context.Background(), review); err == nil {
		t.Fatal("changed/reset config accepted")
	}
	os.WriteFile(filepath.Join(base, "config.yml"), config, 0600)
	if _, err := s.StartWorker(context.Background(), review); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(base, "bridge", ".operator")
	defer func() {
		var health worker.Health
		if worker.Call(context.Background(), control, "GET", "/health", &health) == nil {
			var result map[string]bool
			worker.Call(context.Background(), control, "POST", "/stop", &result, health)
		}
	}()
	var status WorkerStatus
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status = s.WorkerStatus(context.Background())
		if status.State == "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.State != "running" {
		t.Fatalf("worker unavailable: %+v", status)
	}
	s.Close()
	s, err = OpenStore(data)
	if err != nil {
		t.Fatal(err)
	}
	adopted := s.WorkerStatus(context.Background())
	if adopted.State != "running" || adopted.Health.PID != status.Health.PID {
		t.Fatal("operator restart did not adopt independent worker")
	}
	if _, err := s.StopWorker(context.Background(), review, status.Health.PID+1, status.Health.StartedAt); err == nil {
		t.Fatal("stale process identity accepted")
	}
	if _, err := s.StopWorker(context.Background(), review, status.Health.PID, status.Health.StartedAt); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.WorkerStatus(context.Background()).State == "unavailable" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.WorkerStatus(context.Background()).State != "unavailable" {
		t.Fatal("worker did not stop")
	}
	_, _, events := s.Summary()
	if len(events) != 2 || events[0].Action != "worker start requested" || events[1].Action != "worker stop requested" {
		t.Fatalf("missing action history: %+v", events)
	}
}
