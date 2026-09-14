package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

func instanceRequest(api *Server, method, path string, body interface{}) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "http://127.0.0.1:3021"+path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+api.Token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	return w
}
func TestLocalInstanceScopesPersistAndKeepApprovalAuthoritySeparate(t *testing.T) {
	dir := privateDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	a, err := s.CreateInstance("route-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateInstance("route-b")
	if err != nil {
		t.Fatal(err)
	}
	if a.InstanceID() == b.InstanceID() || a.InstanceID() == s.InstanceID() {
		t.Fatal("instances share approval identity")
	}
	for _, id := range []string{"default", "../escape", "route-a", "UpperCase", "a/b"} {
		if _, err := s.CreateInstance(id); err == nil {
			t.Fatalf("invalid/duplicate slot %q accepted", id)
		}
	}
	api := NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	for i, id := range []string{"route-a", "route-b"} {
		p := vectors(t)[0].Profile
		p.Name = id
		w := instanceRequest(api, "POST", "/v1/instances/"+id+"/config/apply", ApplyConfig{1, "same-request-id", Binding{p, fmt.Sprintf("http://127.0.0.1:%d", 18000+i)}})
		if w.Code != 200 {
			t.Fatalf("scoped apply: %d %s", w.Code, w.Body)
		}
	}
	for _, id := range []string{"route-a", "route-b"} {
		w := instanceRequest(api, "GET", "/v1/instances/"+id+"/status", nil)
		var status struct {
			Profiles []Profile `json:"profiles"`
		}
		if json.Unmarshal(w.Body.Bytes(), &status) != nil || len(status.Profiles) != 1 || status.Profiles[0].Name != id {
			t.Fatal("profile state crossed instances")
		}
	}
	_, rootProfiles, _ := s.Summary()
	if len(rootProfiles) != 0 {
		t.Fatal("child profiles changed root")
	}
	for _, path := range []string{"/v1/instances/missing/status", "/v1/instances/route-a/instances/route-b/status", "/v1/instances/route-a/../route-b/status", "/v1/instances/route-a%2f../route-b/status"} {
		if w := instanceRequest(api, "GET", path, nil); w.Code != 404 {
			t.Fatalf("unscoped route accepted: %s %d", path, w.Code)
		}
	}
	if w := instanceRequest(api, "POST", "/v1/instances", map[string]string{"id": "remote-created"}); w.Code != 404 {
		t.Fatal("HTTP created an instance")
	}
	unauth := httptest.NewRecorder()
	api.ServeHTTP(unauth, httptest.NewRequest("GET", "http://127.0.0.1:3021/v1/instances", nil))
	if unauth.Code != 401 {
		t.Fatal("inventory exposed without token")
	}
	now := time.Now().UTC()
	release, trust := fixtureRelease(t, now)
	verified, err := VerifyRelease(release, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(trust)
	mustBackupWrite(t, filepath.Join(a.dir, "release-trust.json"), raw)
	revision, _, _ := a.Summary()
	approval, err := a.ApproveRelease(ApproveRelease{a.InstanceID(), revision, release, verified.Digest, now, now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if CheckActivation(approval, verified, b.InstanceID(), now) == nil || len(b.ReleaseApprovals()) != 0 || len(s.ReleaseApprovals()) != 0 {
		t.Fatal("approval crossed instance authority")
	}
	aid, bid := a.InstanceID(), b.InstanceID()
	s.Close()
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, _ = s.LocalInstance("route-a")
	b, _ = s.LocalInstance("route-b")
	if a.InstanceID() != aid || b.InstanceID() != bid || len(a.ReleaseApprovals()) != 1 || len(b.ReleaseApprovals()) != 0 {
		t.Fatal("identity/approval lost on operator reopen")
	}
	if len(s.LocalInstances()) != 3 {
		t.Fatal("inventory lost child")
	}
}

func TestLocalInstanceInventoryRefusesIdentityReplacement(t *testing.T) {
	for _, kind := range []string{"missing identity", "changed descriptor", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateDir(t)
			s, err := OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			child, err := s.CreateInstance("route-a")
			if err != nil {
				t.Fatal(err)
			}
			path := child.dir
			s.Close()
			switch kind {
			case "missing identity":
				os.Remove(filepath.Join(path, "instance-id"))
			case "changed descriptor":
				mustBackupWrite(t, filepath.Join(path, "instance.json"), []byte(`{"schemaVersion":1,"id":"other"}`))
			case "symlink":
				os.Rename(path, path+"-original")
				os.Symlink(path+"-original", path)
			}
			reopened, err := OpenStore(dir)
			if err == nil {
				reopened.Close()
				t.Fatal("corrupt instance adopted")
			}
			if kind == "missing identity" {
				if _, err := os.Lstat(filepath.Join(path, "instance-id")); !os.IsNotExist(err) {
					t.Fatal("missing approval identity silently replaced")
				}
			}
		})
	}
}

func TestConcurrentRegistrationCannotClaimOneWorkerTwice(t *testing.T) {
	dir := privateDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.CreateInstance("route-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateInstance("route-b")
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "fixture-worker")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	config := []byte("bridge:\n  instance-id: unique-fixture-worker\n  observation-only: true\n")
	mustBackupWrite(t, filepath.Join(base, "config.yml"), config)
	binary := filepath.Join(dir, "reviewed-fixture")
	content := []byte("synthetic registration fixture; never executed")
	mustBackupWrite(t, binary, content)
	h := sha256.Sum256(content)
	hash := hex.EncodeToString(h[:])
	results := make(chan error, 2)
	for _, child := range []*Store{a, b} {
		go func(child *Store) { _, err := child.RegisterWorker(base, binary, hash); results <- err }(child)
	}
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("expected one registered owner: %v / %v", first, second)
	}
	other, err := s.CreateInstance("route-c")
	if err != nil {
		t.Fatal(err)
	}
	secondBase := filepath.Join(dir, "another-fixture-worker")
	os.Mkdir(secondBase, 0700)
	mustBackupWrite(t, filepath.Join(secondBase, "config.yml"), config)
	if _, err := other.RegisterWorker(secondBase, binary, hash); err == nil {
		t.Fatal("duplicate worker identity accepted with another data directory")
	}
}

func TestTwoConsoleWorkersRemainIndependentAcrossOperatorRestart(t *testing.T) {
	root, err := os.MkdirTemp("", "vmi-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	binary := filepath.Join(root, "validator")
	if out, err := exec.Command("go", "build", "-o", binary, "../../cmd/koinos-bridge-validator").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	hash := hex.EncodeToString(h[:])
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
			t.Errorf("unexpected RPC %s", req.Method)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer rpc.Close()
	data := filepath.Join(root, "operator")
	s, err := OpenStore(data)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	digests := map[string]string{}
	bases := map[string]string{}
	for _, id := range []string{"route-a", "route-b"} {
		child, err := s.CreateInstance(id)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(root, id)
		os.Mkdir(base, 0700)
		bases[id] = base
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := l.Addr().String()
		l.Close()
		cfg := fmt.Sprintf("bridge:\n  instance-id: %s\n  observation-only: true\n  log-level: error\n  api-url: %s\n  ethereum-rpc: %s\n  koinos-rpc: %s\n  ethereum-contract: '0x1111111111111111111111111111111111111111'\n  koinos-contract: '1111111111111111111114oLvT2'\n  ethereum-polling-time: 10\n  koinos-polling-time: 10\n", id, address, rpc.URL, rpc.URL)
		mustBackupWrite(t, filepath.Join(base, "config.yml"), []byte(cfg))
		registration, err := child.RegisterWorker(base, binary, hash)
		if err != nil {
			t.Fatal(err)
		}
		digests[id] = registrationDigest(registration)
	}
	extra, err := s.CreateInstance("duplicate")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extra.RegisterWorker(bases["route-a"], binary, hash); err == nil {
		t.Fatal("same worker directory registered twice")
	}
	api := NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	defer func() {
		for _, base := range bases {
			control := filepath.Join(base, "bridge", ".operator")
			var health worker.Health
			if worker.Call(context.Background(), control, "GET", "/health", &health) == nil {
				var result map[string]bool
				worker.Call(context.Background(), control, "POST", "/stop", &result, health)
			}
		}
	}()
	for _, id := range []string{"route-a", "route-b"} {
		if w := instanceRequest(api, "POST", "/v1/instances/"+id+"/worker/start", map[string]string{"registrationDigest": digests[id]}); w.Code != 202 {
			t.Fatalf("start %s: %d %s", id, w.Code, w.Body)
		}
	}
	wait := func(id string) WorkerStatus {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			w := instanceRequest(api, "GET", "/v1/instances/"+id+"/worker", nil)
			var status WorkerStatus
			if json.Unmarshal(w.Body.Bytes(), &status) == nil && status.State == "running" {
				return status
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("worker %s unavailable", id)
		return WorkerStatus{}
	}
	a, b := wait("route-a"), wait("route-b")
	if a.Health.PID == b.Health.PID {
		t.Fatal("workers share process")
	}
	w := instanceRequest(api, "POST", "/v1/instances/route-b/worker/stop", map[string]interface{}{"registrationDigest": digests["route-a"], "pid": a.Health.PID, "startedAt": a.Health.StartedAt})
	if w.Code != 409 {
		t.Fatal("cross-instance stop accepted")
	}
	s.Close()
	s, err = OpenStore(data)
	if err != nil {
		t.Fatal(err)
	}
	api = NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	if wait("route-a").Health.PID != a.Health.PID || wait("route-b").Health.PID != b.Health.PID {
		t.Fatal("operator restart replaced independent workers")
	}
	w = instanceRequest(api, "POST", "/v1/instances/route-a/worker/stop", map[string]interface{}{"registrationDigest": digests["route-a"], "pid": a.Health.PID, "startedAt": a.Health.StartedAt})
	if w.Code != 202 {
		t.Fatal("scoped stop failed")
	}
	deadline := time.Now().Add(5 * time.Second)
	stopped := false
	for time.Now().Before(deadline) {
		child, _ := s.LocalInstance("route-a")
		if child.WorkerStatus(context.Background()).State == "unavailable" {
			stopped = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !stopped {
		t.Fatal("route-a did not stop")
	}
	if wait("route-b").Health.PID != b.Health.PID {
		t.Fatal("stopping route-a stopped route-b")
	}
	w = instanceRequest(api, "POST", "/v1/instances/route-b/worker/stop", map[string]interface{}{"registrationDigest": digests["route-b"], "pid": b.Health.PID, "startedAt": b.Health.StartedAt})
	if w.Code != 202 {
		t.Fatal("second scoped stop failed")
	}
	deadline = time.Now().Add(5 * time.Second)
	stopped = false
	for time.Now().Before(deadline) {
		child, _ := s.LocalInstance("route-b")
		if child.WorkerStatus(context.Background()).State == "unavailable" {
			stopped = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !stopped {
		t.Fatal("second worker did not stop")
	}
}
