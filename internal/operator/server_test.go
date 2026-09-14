package operator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "operator")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fakeEVM(t *testing.T, network string) *httptest.Server {
	t.Helper()
	selectors := map[string]string{}
	for method, value := range map[string]string{"chainId()": "2", "nonce()": "4", "paused()": "0", "getValidatorsLength()": "3", "validators(uint256)": "1"} {
		selectors[hex.EncodeToString(crypto.Keccak256([]byte(method))[:4])] = value
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var result interface{}
		switch req.Method {
		case "eth_chainId":
			result = network
		case "eth_getBlockByNumber":
			result = map[string]string{"number": "0x10", "hash": "0x" + strings.Repeat("a", 64)}
		case "eth_getCode":
			result = "0x6000"
		case "eth_call":
			var call map[string]string
			json.Unmarshal(req.Params[0], &call)
			data := call["data"]
			if len(data) < 10 {
				t.Error("short call")
				w.WriteHeader(400)
				return
			}
			v, ok := selectors[data[2:10]]
			if !ok {
				t.Errorf("unexpected selector %s", data)
				w.WriteHeader(400)
				return
			}
			if len(data) > 10 {
				v = fmt.Sprint(int(data[len(data)-1]-'0') + 1)
			}
			result = "0x" + strings.Repeat("0", 64-len(v)) + v
		default:
			t.Errorf("unexpected/non-read RPC method %s", req.Method)
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
}

func TestReadOnlyObservationChecksIdentityAndCode(t *testing.T) {
	rpc := fakeEVM(t, "0x7a69")
	defer rpc.Close()
	p := vectors(t)[0].Profile
	p.CodeHash = hex.EncodeToString(crypto.Keccak256([]byte{0x60, 0x00}))
	p.Reviewed = true
	p.ReviewEvidence = "synthetic local fixture"
	o := Observe(context.Background(), Binding{p, rpc.URL})
	if o.Status != "observed" || !o.GovernanceReady || o.Quorum != 2 || len(o.Validators) != 3 || o.Nonce != "4" {
		t.Fatalf("unexpected observation %+v", o)
	}
	p.CodeHash = strings.Repeat("0", 64)
	o = Observe(context.Background(), Binding{p, rpc.URL})
	if o.Status != "mismatch" || o.GovernanceReady {
		t.Fatalf("accepted wrong code %+v", o)
	}
	p.NetworkID = "1"
	o = Observe(context.Background(), Binding{p, rpc.URL})
	if o.Status != "mismatch" || o.GovernanceReady {
		t.Fatal("accepted wrong chain")
	}
	p.NetworkID = "31337"
	p.Environment = "mainnet"
	p.CodeHash = hex.EncodeToString(crypto.Keccak256([]byte{0x60, 0x00}))
	o = Observe(context.Background(), Binding{p, rpc.URL})
	if o.GovernanceReady {
		t.Fatal("profile flag enabled production governance")
	}
}

func TestStorePersistenceConflictAndExclusiveOwner(t *testing.T) {
	dir := privateDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OpenStore(dir); err == nil {
		other.Close()
		t.Fatal("allowed duplicate owner")
	}
	req := ApplyConfig{0, "request-one", Binding{vectors(t)[0].Profile, "http://127.0.0.1:8545/?token=private-fixture"}}
	revision, err := s.Apply(req)
	if err != nil || revision != 1 {
		t.Fatalf("apply %d %v", revision, err)
	}
	if revision, err = s.Apply(req); err != nil || revision != 1 {
		t.Fatal("idempotent retry failed")
	}
	req.Binding.Profile.Name = "changed"
	if _, err := s.Apply(req); err == nil {
		t.Fatal("key reuse accepted")
	}
	req.IdempotencyKey = "request-two"
	if _, err := s.Apply(req); err == nil {
		t.Fatal("stale revision accepted")
	}
	token, err := s.Token()
	if err != nil || len(token) != 64 {
		t.Fatal("token creation failed")
	}
	s.Close()
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, profiles, _ := s.Summary()
	if r != 1 || len(profiles) != 1 || profiles[0].Name == "changed" {
		t.Fatal("state was not durable or rejected request mutated state")
	}
	restored, _ := s.Token()
	if restored != token {
		t.Fatal("token changed across restart")
	}
}

func TestCorruptOrPublicStateRefused(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		mode       os.FileMode
	}{{"corrupt", "{", 0600}, {"public", `{"schemaVersion":1}`, 0644}, {"unknown schema", `{"schemaVersion":2,"applied":{}}`, 0600}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDir(t)
			os.WriteFile(filepath.Join(dir, "state.json"), []byte(tc.body), tc.mode)
			s, err := OpenStore(dir)
			if err == nil {
				s.Close()
				t.Fatal("accepted invalid state")
			}
			b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
			if string(b) != tc.body {
				t.Fatal("reset state")
			}
		})
	}
}

func TestManagementAuthIsolationAndDurableApply(t *testing.T) {
	s, err := OpenStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	token, _ := s.Token()
	api := NewServer(s, token, "127.0.0.1:3021", []string{"http://127.0.0.1:5173"})
	request := func(method, path, auth, origin, host string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://127.0.0.1:3021"+path, bytes.NewReader(body))
		req.Host = host
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		api.ServeHTTP(res, req)
		return res
	}
	for _, tc := range []struct {
		auth, origin, host string
		status             int
	}{{"", "", "127.0.0.1:3021", 401}, {token, "https://evil.invalid", "127.0.0.1:3021", 403}, {token, "", "evil.invalid", 403}, {token, "http://127.0.0.1:5173", "127.0.0.1:3021", 200}} {
		res := request("GET", "/v1/status", tc.auth, tc.origin, tc.host, nil)
		if res.Code != tc.status {
			t.Fatalf("auth status %d want %d", res.Code, tc.status)
		}
	}
	rpc := fakeEVM(t, "0x7a69")
	defer rpc.Close()
	req := ApplyConfig{0, "first-config", Binding{vectors(t)[0].Profile, rpc.URL + "/?secret=private-fixture"}}
	body, _ := json.Marshal(req)
	res := request("POST", "/v1/config/apply", token, "", "127.0.0.1:3021", body)
	if res.Code != 200 {
		t.Fatal(res.Body.String())
	}
	res = request("POST", "/v1/observations/fixture-evm", token, "", "127.0.0.1:3021", nil)
	if res.Code != 200 || !strings.Contains(res.Body.String(), `"status":"observed"`) {
		t.Fatal(res.Body.String())
	}
	res = request("GET", "/v1/status", token, "", "127.0.0.1:3021", nil)
	if strings.Contains(res.Body.String(), "private-fixture") || strings.Contains(res.Body.String(), rpc.URL) || strings.Contains(res.Body.String(), token) {
		t.Fatal("status leaked private configuration")
	}
	for _, route := range []string{"/v1/sign", "/v1/exec", "/SubmitSignature", "/v1/transactions/send"} {
		if request("POST", route, token, "", "127.0.0.1:3021", nil).Code != 404 {
			t.Fatal("unexpected signing/execution endpoint")
		}
	}
	res = request("POST", "/v1/config/apply", token, "", "127.0.0.1:3021", []byte(`{"unknown":1}`))
	if res.Code != 400 {
		t.Fatal("unknown field accepted")
	}
	api.mu.Lock()
	o := api.observations["fixture-evm"]
	o.ObservedAt = time.Now().Add(-time.Minute)
	o.GovernanceReady = true
	api.observations["fixture-evm"] = o
	api.mu.Unlock()
	res = request("GET", "/v1/status", token, "", "127.0.0.1:3021", nil)
	if !strings.Contains(res.Body.String(), `"status":"stale"`) || strings.Contains(res.Body.String(), `"governanceReady":true`) {
		t.Fatal("stale observation enabled signing")
	}
	// Exercise concurrent status reads under -race.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); request("GET", "/v1/status", token, "", "127.0.0.1:3021", nil) }()
	}
	wg.Wait()
}
