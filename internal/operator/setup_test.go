package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

func setupFixture(t *testing.T) (*Store, SetupInput, string) {
	t.Helper()
	s, err := OpenStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var evm, koinos Profile
	for _, v := range vectors(t) {
		if v.Profile.Family == "evm" {
			evm = v.Profile
		} else {
			koinos = v.Profile
		}
	}
	evm.ID = "evm-setup"
	koinos.ID = "koinos-setup"
	s.data.Bindings = []Binding{{evm, "http://127.0.0.1:1/SYNTHETIC-PRIVATE-RPC"}, {koinos, "http://127.0.0.1:2/SYNTHETIC-PRIVATE-RPC"}}
	binary := filepath.Join(t.TempDir(), "binary")
	raw := []byte("synthetic reviewed bytes never execute in unit tests")
	if err := os.WriteFile(binary, raw, 0500); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if _, err := s.PrepareWorker(binary, hex.EncodeToString(h[:])); err != nil {
		t.Fatal(err)
	}
	input := SetupInput{EVMProfileID: evm.ID, KoinosProfileID: koinos.ID, EVMStartBlock: "5", KoinosStartBlock: "9", EVMConfirmations: "15", APIPort: 13000, Tokens: []SetupToken{{"token", evm.Contract, koinos.Contract}}, Peers: []SetupPeer{{"peer", evm.Contract, koinos.Contract, "https://example.invalid/SYNTHETIC-PRIVATE-PEER"}}}
	return s, input, binary
}
func TestSetupPreviewPublishesPrivateConfigAndRetriesAfterRestart(t *testing.T) {
	s, input, _ := setupFixture(t)
	before, _, _ := s.Summary()
	preview, err := s.PreviewWorkerSetup(input)
	if err != nil {
		t.Fatal(err)
	}
	if s.workerExists() {
		t.Fatal("preview created a worker")
	}
	raw, _ := json.Marshal(preview)
	if strings.Contains(string(raw), "SYNTHETIC-PRIVATE") || strings.Contains(string(raw), "example.invalid") {
		t.Fatal("private endpoint leaked")
	}
	req := CreateWorker{input, preview.Digest, "setup-test"}
	var wg sync.WaitGroup
	receipts := make(chan SetupReceipt, 2)
	failures := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r, err := s.CreateObservationWorker(req); receipts <- r; failures <- err }()
	}
	wg.Wait()
	close(receipts)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	first := <-receipts
	second := <-receipts
	if !reflect.DeepEqual(first, second) {
		t.Fatal("retry changed receipt")
	}
	revision, _, events := s.Summary()
	if revision != before+1 || len(events) != 1 {
		t.Fatal("setup duplicated history")
	}
	r, err := s.registration()
	if err != nil {
		t.Fatal(err)
	}
	config, cfg, err := workerConfig(r.BaseDir)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(config)
	if hex.EncodeToString(h[:]) != preview.ConfigSHA256 || r.ConfigSHA256 != preview.ConfigSHA256 || cfg.Bridge.InstanceID != preview.WorkerID || !cfg.Bridge.ObservationOnly || cfg.Bridge.EthereumPK != "" || cfg.Bridge.KoinosPKFile != "" {
		t.Fatal("published configuration differs from preview")
	}
	if cfg.Bridge.EthereumNetworkID != preview.EVM.NetworkID || cfg.Bridge.KoinosNetworkID != preview.Koinos.NetworkID || !strings.Contains(cfg.Bridge.EthereumRpc, "SYNTHETIC-PRIVATE-RPC") || !strings.Contains(cfg.Bridge.Validators["peer"].ApiUrl, "SYNTHETIC-PRIVATE-PEER") {
		t.Fatal("private config or network pins lost")
	}
	if worker.CheckNetworkBinding(filepath.Join(r.BaseDir, "bridge", ".operator"), networkBinding(cfg), false) != nil {
		t.Fatal("network marker missing")
	}
	if exists, err := worker.HasValidatorData(r.BaseDir); err != nil || exists {
		t.Fatal("setup opened databases")
	}
	if s.WorkerStatus(context.Background()).State != "unavailable" {
		t.Fatal("setup started worker")
	}
	dir := s.dir
	s.Close()
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.CreateObservationWorker(req)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("published retry failed after restart", err)
	}
	req.Input.EVMConfirmations = "16"
	if _, err := reopened.CreateObservationWorker(req); err == nil {
		t.Fatal("changed request replaced a worker")
	}
}

func TestSetupRejectsStaleTamperedAndConflictingInputs(t *testing.T) {
	t.Run("stale and changed preview", func(t *testing.T) {
		s, input, _ := setupFixture(t)
		p, err := s.PreviewWorkerSetup(input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateObservationWorker(CreateWorker{input, strings.Repeat("0", 64), "setup-test"}); err == nil {
			t.Fatal("tampered preview accepted")
		}
		s.mu.Lock()
		s.data.Revision++
		s.mu.Unlock()
		if _, err := s.CreateObservationWorker(CreateWorker{input, p.Digest, "setup-test"}); err == nil {
			t.Fatal("stale preview accepted")
		}
		if s.workerExists() {
			t.Fatal("failed request created state")
		}
	})
	t.Run("prepared bytes", func(t *testing.T) {
		s, input, _ := setupFixture(t)
		p, err := s.PreviewWorkerSetup(input)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(s.dir, "worker-bin", p.BinarySHA256), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(s.dir, "worker-bin", p.BinarySHA256), []byte("changed"), 0500); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateObservationWorker(CreateWorker{input, p.Digest, "setup-test"}); err == nil {
			t.Fatal("changed binary accepted")
		}
	})
	t.Run("existing destination", func(t *testing.T) {
		s, input, _ := setupFixture(t)
		p, err := s.PreviewWorkerSetup(input)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(s.dir, "managed-worker")
		os.Mkdir(base, 0700)
		os.WriteFile(filepath.Join(base, "unrelated"), []byte("preserve"), 0600)
		if _, err := s.CreateObservationWorker(CreateWorker{input, p.Digest, "setup-test"}); err == nil {
			t.Fatal("existing data replaced")
		}
		if raw, err := os.ReadFile(filepath.Join(base, "unrelated")); err != nil || string(raw) != "preserve" {
			t.Fatal("unrelated data lost")
		}
	})
	for _, field := range []string{"start", "port", "duplicate-token", "peer-endpoint", "family"} {
		t.Run(field, func(t *testing.T) {
			s, input, _ := setupFixture(t)
			switch field {
			case "start":
				input.EVMStartBlock = "01"
			case "port":
				input.APIPort = 0
			case "duplicate-token":
				input.Tokens = append(input.Tokens, input.Tokens[0])
			case "peer-endpoint":
				input.Peers[0].Endpoint = "http://example.invalid"
			case "family":
				input.KoinosProfileID = input.EVMProfileID
			}
			if _, err := s.PreviewWorkerSetup(input); err == nil {
				t.Fatal("invalid setup accepted")
			}
		})
	}
}

func TestProvisionedWorkerActuallyStartsWithBothNetworkPins(t *testing.T) {
	s, input, _ := setupFixture(t)
	binary := filepath.Join(t.TempDir(), "validator")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/koinos-bridge-validator")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %v %s", err, out)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	// New store for the real prepared artifact; never replace an existing preparation.
	real, err := OpenStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	if _, err := real.PrepareWorker(binary, hex.EncodeToString(h[:])); err != nil {
		t.Fatal(err)
	}
	real.data.Bindings = append([]Binding{}, s.data.Bindings...)
	id := real.data.Bindings[1].Profile.NetworkID
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var result interface{}
		switch req.Method {
		case "eth_chainId":
			result = "0x7a69"
		case "chain.get_chain_id":
			result = map[string]string{"chain_id": id}
		case "eth_blockNumber":
			result = "0x0"
		case "chain.get_head_info":
			result = map[string]interface{}{"last_irreversible_block": "0", "head_topology": map[string]string{"height": "0", "id": "0x1220" + strings.Repeat("00", 32)}}
		default:
			t.Errorf("unexpected RPC %s", req.Method)
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer rpc.Close()
	for i := range real.data.Bindings {
		real.data.Bindings[i].RPC = rpc.URL
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	input.APIPort = listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	preview, err := real.PreviewWorkerSetup(input)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := real.CreateObservationWorker(CreateWorker{input, preview.Digest, "setup-actual"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := real.StartWorker(context.Background(), receipt.RegistrationDigest); err != nil {
		t.Fatal(err)
	}
	defer func() {
		status := real.WorkerStatus(context.Background())
		if status.Health != nil {
			real.StopWorker(context.Background(), status.RegistrationDigest, status.Health.PID, status.Health.StartedAt)
		}
	}()
	deadline := time.Now().Add(8 * time.Second)
	for {
		status := real.WorkerStatus(context.Background())
		if status.Health != nil && status.Health.Chains["evm"].Status == "observed" && status.Health.Chains["koinos"].Status == "observed" {
			if status.Health.NetworkBinding == nil || status.Health.NetworkBinding.EVMNetworkID != preview.EVM.NetworkID || status.Health.NetworkBinding.KoinosNetworkID != preview.Koinos.NetworkID {
				t.Fatal("pins absent")
			}
			if status.Health.Chains["evm"].Height != 4 || status.Health.Chains["koinos"].Height != 8 {
				t.Fatal("scan starts not applied")
			}
			if _, err := real.StopWorker(context.Background(), status.RegistrationDigest, status.Health.PID, status.Health.StartedAt); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(filepath.Join(real.dir, "worker.log"))
			if len(log) > 3000 {
				log = log[len(log)-3000:]
			}
			t.Fatal("provisioned runtime did not observe", status, string(log))
		}
		time.Sleep(20 * time.Millisecond)
	}
	for time.Now().Before(deadline) {
		if real.WorkerStatus(context.Background()).State == "unavailable" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("provisioned worker did not stop")
}

func TestSetupHTTPScopesPreparationAndRejectsHostInputs(t *testing.T) {
	s, input, _ := setupFixture(t)
	child, err := s.CreateInstance("other")
	if err != nil {
		t.Fatal(err)
	}
	api := NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	r := instanceRequest(api, "GET", "/v1/instances/other/worker/setup", nil)
	var info map[string]interface{}
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &info) != nil || info["prepared"] != false {
		t.Fatal("preparation leaked across slots")
	}
	r = instanceRequest(api, "POST", "/v1/instances/other/worker/setup/preview", input)
	if r.Code != 409 || child.workerExists() {
		t.Fatal("unprepared slot accepted setup")
	}
	r = instanceRequest(api, "POST", "/v1/worker/setup/preview", map[string]interface{}{"workerBase": "/arbitrary/path"})
	if r.Code != 400 {
		t.Fatal("arbitrary host path accepted")
	}
	r = instanceRequest(api, "POST", "/v1/worker/setup/preview", input)
	var preview SetupPreview
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &preview) != nil {
		t.Fatal(r.Body.String())
	}
	r = instanceRequest(api, "POST", "/v1/worker/setup/create", CreateWorker{input, preview.Digest, "setup-http"})
	if r.Code != 201 {
		t.Fatal(r.Body.String())
	}
	r = instanceRequest(api, "GET", "/v1/worker/setup", nil)
	if r.Code != 200 || strings.Contains(r.Body.String(), "SYNTHETIC-PRIVATE") {
		t.Fatal("setup receipt leaked private config")
	}
	request := httptest.NewRequest("POST", "http://127.0.0.1:3021/v1/worker/setup/create", strings.NewReader("{}"))
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal("unauthenticated setup accepted")
	}
}
