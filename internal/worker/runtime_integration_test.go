package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// This starts the actual validator executable, real Badger stores and its Unix
// socket against read-only synthetic chain RPC. It does not run an operator API.
func TestStandaloneObservationRuntime(t *testing.T) {
	root := privateTestDir(t)
	binary := filepath.Join(root, "validator")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/koinos-bridge-validator")
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	var rangeMu sync.Mutex
	firstRanges := 0
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		var result interface{}
		switch req.Method {
		case "eth_blockNumber":
			result = "0x6"
		case "eth_getLogs":
			if r.URL.Path == "/first" {
				rangeMu.Lock()
				firstRanges++
				rangeMu.Unlock()
			}
			result = []interface{}{}
		case "chain.get_head_info":
			result = map[string]interface{}{"last_irreversible_block": "0", "head_topology": map[string]interface{}{"height": "0", "id": "0x12200000000000000000000000000000000000000000000000000000000000000000"}}
		default:
			t.Errorf("unexpected runtime RPC %s", req.Method)
			http.Error(w, "disallowed", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer rpc.Close()
	makeInstance := func(id string) (string, string) {
		d := filepath.Join(root, id)
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		listener.Close()
		cfg := fmt.Sprintf("bridge:\n  instance-id: %s\n  log-level: error\n  api-url: %s\n  ethereum-rpc: %s\n  koinos-rpc: %s\n  ethereum-contract: '0x1111111111111111111111111111111111111111'\n  koinos-contract: '1111111111111111111114oLvT2'\n  ethereum-pk-file: /deliberately-missing-synthetic-key\n  koinos-pk-file: /deliberately-missing-synthetic-key\n  ethereum-confirmations: 1\n  ethereum-polling-time: 10\n  koinos-polling-time: 10\n", id, addr, rpc.URL+"/"+id, rpc.URL+"/"+id)
		if err := os.WriteFile(filepath.Join(d, "config.yml"), []byte(cfg), 0600); err != nil {
			t.Fatal(err)
		}
		return d, addr
	}
	start := func(d string) *exec.Cmd {
		cmd := exec.Command(binary, "--basedir", d, "--observe-only")
		log, err := os.OpenFile(filepath.Join(d, "test.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout = log
		cmd.Stderr = log
		if err := cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() })
		return cmd
	}
	wait := func(d string, pid int) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			var h Health
			err := Call(context.Background(), filepath.Join(d, "bridge", ".operator"), "GET", "/health", &h)
			if err == nil && h.PID == pid && h.Mode == "observation-only" && h.Chains["evm"].Status == "observed" && h.Chains["evm"].Height == 5 && h.Chains["koinos"].Status == "observed" {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		out, _ := os.ReadFile(filepath.Join(d, "test.log"))
		if len(out) > 2000 {
			out = out[len(out)-2000:]
		}
		t.Fatalf("worker did not become observable: %s", out)
	}
	first, addr := makeInstance("first")
	second, _ := makeInstance("second")
	a := start(first)
	b := start(second)
	wait(first, a.Process.Pid)
	wait(second, b.Process.Pid)
	duplicate := exec.Command(binary, "--basedir", first, "--observe-only")
	if out, err := duplicate.CombinedOutput(); err == nil {
		t.Fatalf("duplicate instance ran: %s", out)
	}
	response, err := http.Post("http://"+addr+"/SubmitSignature", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("observer accepted signature exchange")
	}
	// Unclean exit releases the process lock; Badger and the stale socket reopen.
	rangeMu.Lock()
	beforeRestart := firstRanges
	rangeMu.Unlock()
	if err := a.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	restarted := start(first)
	wait(first, restarted.Process.Pid)
	rangeMu.Lock()
	afterRestart := firstRanges
	rangeMu.Unlock()
	if beforeRestart == 0 || afterRestart != beforeRestart {
		t.Fatal("crash restart replayed the durable EVM checkpoint")
	}
	// Stopping one independent directory must not stop the other validator.
	var result map[string]bool
	var firstHealth, secondHealth Health
	if err := Call(context.Background(), filepath.Join(first, "bridge", ".operator"), "GET", "/health", &firstHealth); err != nil {
		t.Fatal(err)
	}
	if err := Call(context.Background(), filepath.Join(second, "bridge", ".operator"), "GET", "/health", &secondHealth); err != nil {
		t.Fatal(err)
	}
	if err := Call(context.Background(), filepath.Join(first, "bridge", ".operator"), "POST", "/stop", &result, firstHealth); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- restarted.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("graceful stop timed out")
	}
	wait(second, b.Process.Pid)
	if err := Call(context.Background(), filepath.Join(second, "bridge", ".operator"), "POST", "/stop", &result, secondHealth); err != nil {
		t.Fatal(err)
	}
	if err := b.Wait(); err != nil {
		t.Fatal(err)
	}
}
