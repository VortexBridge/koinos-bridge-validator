package operator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"gopkg.in/yaml.v2"
)

func TestDoctorBothChainsAndConcurrentConfigurationChange(t *testing.T) {
	evm := fakeEVM(t, "0x7a69")
	defer evm.Close()
	s, base, cfg := doctorFixture(t, evm.URL)
	var p Profile
	for _, v := range vectors(t) {
		if v.Profile.Family == "koinos" {
			p = v.Profile
			break
		}
	}
	var change int32
	koinos := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params struct {
				EntryPoint uint32 `json:"entry_point"`
			} `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("invalid request")
			w.WriteHeader(400)
			return
		}
		var result interface{}
		switch req.Method {
		case "chain.get_chain_id":
			result = map[string]string{"chain_id": p.NetworkID}
			if atomic.SwapInt32(&change, 0) == 1 {
				s.mu.Lock()
				s.data.Revision++
				s.mu.Unlock()
			}
		case "chain.get_head_info":
			result = map[string]interface{}{"head_topology": map[string]string{"id": "synthetic-fixed-head", "height": "0"}, "last_irreversible_block": "0"}
		case "chain.read_contract":
			h := sha256.Sum256([]byte("get_metadata"))
			metadataEP := uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
			h = sha256.Sum256([]byte("get_validators"))
			validatorsEP := uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
			var raw []byte
			if req.Params.EntryPoint == metadataEP {
				raw = fieldUint(fieldUint(fieldUint(nil, 1, 1), 2, 4), 3, uint64(p.BridgeChainID))
			} else if req.Params.EntryPoint != validatorsEP {
				t.Error("unexpected getter")
				w.WriteHeader(400)
				return
			}
			result = map[string]string{"result": base64.URLEncoding.EncodeToString(raw)}
		default:
			t.Error("unexpected RPC method")
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	defer koinos.Close()
	cfg.Bridge.KoinosRpc = koinos.URL
	cfg.Bridge.KoinosNetworkID = p.NetworkID
	cfg.Bridge.KoinosContract = p.Contract
	raw, _ := yaml.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(base, "config.yml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	r, _ := s.registration()
	h := sha256.Sum256(raw)
	r.ConfigSHA256 = hex.EncodeToString(h[:])
	encoded, _ := json.Marshal(r)
	if err := atomicFile(s.dir, "worker.json", encoded); err != nil {
		t.Fatal(err)
	}
	evmProfile := vectors(t)[0].Profile
	evmProfile.CodeHash = hex.EncodeToString(crypto.Keccak256([]byte{0x60, 0x00}))
	s.mu.Lock()
	s.data.Bindings = []Binding{{evmProfile, evm.URL}, {p, koinos.URL}}
	s.mu.Unlock()
	report := s.Doctor(context.Background())
	if report.Status != "checks-passed" || report.SigningReady {
		t.Fatal(report)
	}
	checkStatus(t, report, "koinos-rpc", "passed")
	checkStatus(t, report, "koinos-provenance-finality", "unknown")
	atomic.StoreInt32(&change, 1)
	checkStatus(t, s.Doctor(context.Background()), "snapshot", "failed")
	s.mu.Lock()
	s.data.Bindings = append(s.data.Bindings, Binding{p, koinos.URL})
	s.mu.Unlock()
	checkStatus(t, s.Doctor(context.Background()), "koinos-binding", "failed")
}

func doctorFixture(t *testing.T, endpoint string) (*Store, string, util.YamlConfig) {
	t.Helper()
	s, err := OpenStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	base := filepath.Join(t.TempDir(), "worker")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := util.YamlConfig{Bridge: util.BridgeConfig{InstanceID: "doctor-fixture", ApiUrl: "127.0.0.1:13000", EthereumRpc: endpoint, KoinosRpc: endpoint, EthereumNetworkID: vectors(t)[0].Profile.NetworkID, KoinosNetworkID: "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", EthereumContract: vectors(t)[0].Profile.Contract, KoinosContract: "1111111111111111111114oLvT2", EthereumPKFile: "/missing/synthetic-key-never-read"}}
	raw, _ := yaml.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(base, "config.yml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "binary")
	// Deliberately not executable code: the doctor must hash, never run it.
	raw = []byte("synthetic reviewed bytes, never execute")
	if err := os.WriteFile(binary, raw, 0500); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if _, err := s.RegisterWorker(base, binary, hex.EncodeToString(h[:])); err != nil {
		t.Fatal(err)
	}
	return s, base, cfg
}

func checkStatus(t *testing.T, report DoctorReport, id, expected string) {
	t.Helper()
	for _, c := range report.Checks {
		if c.ID == id {
			if c.Status != expected {
				t.Fatalf("%s: %+v", id, c)
			}
			return
		}
	}
	t.Fatalf("missing %s: %+v", id, report)
}

func TestDoctorReadsRegisteredConfigurationWithoutChangingState(t *testing.T) {
	rpc := fakeEVM(t, "0x7a69")
	defer rpc.Close()
	s, base, _ := doctorFixture(t, rpc.URL)
	p := vectors(t)[0].Profile
	p.CodeHash = hex.EncodeToString(crypto.Keccak256([]byte{0x60, 0x00}))
	s.mu.Lock()
	s.data.Bindings = []Binding{{p, rpc.URL}}
	s.mu.Unlock()
	report := s.Doctor(context.Background())
	for _, id := range []string{"configuration", "binary", "api-listener", "data-mode", "restore-review", "evm-binding", "evm-rpc"} {
		checkStatus(t, report, id, "passed")
	}
	checkStatus(t, report, "koinos-binding", "failed")
	checkStatus(t, report, "signing-readiness", "unknown")
	if report.SigningReady || report.Status != "attention-required" {
		t.Fatal(report)
	}
	if _, err := os.Lstat(filepath.Join(base, "bridge")); !os.IsNotExist(err) {
		t.Fatal("doctor created worker data")
	}
	if revision, _, events := s.Summary(); revision != 0 || len(events) != 0 {
		t.Fatal("doctor mutated history")
	}
	raw, _ := json.Marshal(report)
	for _, private := range []string{base, rpc.URL, "synthetic-key-never-read"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private diagnostics leak")
		}
	}
	// A saved profile for a wrong network must fail fresh identity checks.
	s.mu.Lock()
	s.data.Bindings[0].Profile.NetworkID = "1"
	s.mu.Unlock()
	checkStatus(t, s.Doctor(context.Background()), "evm-binding", "failed")
	// Drift must be caught even when YAML is still valid.
	f, err := os.OpenFile(filepath.Join(base, "config.yml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("\n# changed after registration\n")
	f.Close()
	checkStatus(t, s.Doctor(context.Background()), "configuration", "failed")
}

func TestDoctorRejectsUnsafeLocalStateAndScopeInput(t *testing.T) {
	s, base, cfg := doctorFixture(t, "http://127.0.0.1:1")
	cfg.Bridge.ApiUrl = ":3000"
	raw, _ := yaml.Marshal(cfg)
	os.WriteFile(filepath.Join(base, "config.yml"), raw, 0600)
	// Simulate a local registration of this exact configuration for diagnosis.
	r, _ := s.registration()
	h := sha256.Sum256(raw)
	r.ConfigSHA256 = hex.EncodeToString(h[:])
	encoded, _ := json.Marshal(r)
	if err := atomicFile(s.dir, "worker.json", encoded); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(base, "bridge", ".operator")
	os.MkdirAll(control, 0700)
	os.WriteFile(filepath.Join(control, "data-mode"), []byte("signing"), 0600)
	os.WriteFile(filepath.Join(control, "restore.json"), []byte("invalid"), 0600)
	os.Chmod(filepath.Join(s.dir, "worker-bin", r.BinarySHA256), 0600)
	report := s.Doctor(context.Background())
	for _, id := range []string{"api-listener", "data-mode", "restore-review", "binary"} {
		checkStatus(t, report, id, "failed")
	}
	child, err := s.CreateInstance("empty")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	response := instanceRequest(server, "POST", "/v1/instances/empty/worker/doctor", map[string]string{})
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	var empty DoctorReport
	if json.Unmarshal(response.Body.Bytes(), &empty) != nil || empty.InstanceID != child.InstanceID() {
		t.Fatal("wrong scope")
	}
	checkStatus(t, empty, "registration", "failed")
	response = instanceRequest(server, "POST", "/v1/worker/doctor", map[string]string{"workerBase": base})
	if response.Code != 400 {
		t.Fatal("doctor accepted arbitrary path input")
	}
	request := httptest.NewRequest("POST", "http://127.0.0.1:3021/v1/worker/doctor", strings.NewReader("{}"))
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated doctor")
	}
}
