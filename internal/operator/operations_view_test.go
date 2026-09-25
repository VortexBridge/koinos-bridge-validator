package operator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

func managedViewFixture(t *testing.T, journalState string) (*Store, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "host")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	s, err := OpenStore(state)
	if err != nil {
		t.Fatal(err)
	}
	artifact := strings.Repeat("a", 64)
	release := filepath.Join(root, "releases", artifact)
	if err := os.MkdirAll(release, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, name := range []string{"koinos-bridge-validator", "vortex-operator", "vortex-keys", "vortex-candidate-check", "vortex-host", "vortex-operator.service"} {
		path := filepath.Join(release, name)
		if err := os.WriteFile(path, []byte("synthetic-"+name), 0700); err != nil {
			t.Fatal(err)
		}
		digest, err := fileSHA256(path, 1024)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = digest
	}
	installation := managedInstallationRecord{Schema: 1, Instance: "fixture-host", Digest: strings.Repeat("b", 64), Artifact: artifact, Version: "0.0.1-test", Sequence: 1, ConfigSchema: 1, DatabaseSchema: 1, Codec: "fixture", Platform: "linux-amd64", Files: files, Enabled: true, Release: json.RawMessage(`{"fixture":true}`), Approval: json.RawMessage(`{"fixture":true}`)}
	if err := atomicFile(root, "installation.json", mustJSON(t, installation)); err != nil {
		t.Fatal(err)
	}
	profiles := vectors(t)
	evm, koinos := profiles[0].Profile, profiles[12].Profile
	runtime := managedRuntimeRecord{Schema: 1, Instance: "fixture-host", EVM: Binding{Profile: evm, RPC: "http://127.0.0.1:18083"}, Koinos: Binding{Profile: koinos, RPC: "http://127.0.0.1:18081"}, Replica: "http://127.0.0.1:18082", EVMAddress: evm.Contract, KoinosAddress: koinos.Contract, Tokens: map[string]string{evm.Contract: koinos.Contract}, Lifetime: 60000, BlockHints: map[string]uint64{}, Vault: filepath.Join(root, "vault.age"), HostReview: filepath.Join(root, "host-review.json"), Reviewer: filepath.Join(root, "reviewer.pub"), HostEvidence: filepath.Join(root, "host-evidence.json")}
	if err := atomicFile(root, "runtime.json", mustJSON(t, runtime)); err != nil {
		t.Fatal(err)
	}
	sessionDir := filepath.Join(root, "managed-session")
	if err := worker.PrivateDir(sessionDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "session.lock"), []byte("lock"), 0600); err != nil {
		t.Fatal(err)
	}
	id := "evm-to-koinos/" + strings.Repeat("c", 64) + ":0"
	reverseID := "koinos-to-evm/" + strings.Repeat("2", 64) + ":1"
	observed := time.Now().UTC().Add(-time.Second)
	evidence := func(id, family, digest, state, signature, source, destination string, expiry time.Time) managedOperationDisk {
		return managedOperationDisk{ID: id, Family: family, Digest: digest, State: state, Signature: signature, ObservedAt: observed, SourceBlockHash: source, DestinationBlockHash: destination, SourceFinality: "finalized", DestinationFinality: "finalized", ExpiresAt: strconv.FormatInt(expiry.UnixMilli(), 10)}
	}
	journal := managedJournalRecord{Schema: 1, PolicySHA256: strings.Repeat("d", 64), State: journalState, Checkpoint: strings.Repeat("e", 64), Operations: map[string]managedOperationDisk{
		id:        evidence(id, "koinos", strings.Repeat("f", 64), "completed", strings.Repeat("1", 130), strings.Repeat("4", 64), strings.Repeat("5", 64), observed.Add(time.Minute)),
		reverseID: evidence(reverseID, "evm", strings.Repeat("3", 64), "pending", "", strings.Repeat("6", 64), strings.Repeat("7", 64), observed.Add(time.Hour)),
	}}
	if err := atomicFile(sessionDir, "session.json", mustJSON(t, journal)); err != nil {
		t.Fatal(err)
	}
	return s, root
}

func mustJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestManagedLifecycleAndTransferHistoryAreSanitized(t *testing.T) {
	s, root := managedViewFixture(t, "locked")
	defer s.Close()
	lifecycle := s.ManagedLifecycle()
	if !lifecycle.Supported || !lifecycle.Installation.Verified || lifecycle.Signer.State != "locked" || lifecycle.Signer.OperationCount != 2 || len(lifecycle.Routes) != 2 {
		t.Fatalf("unexpected lifecycle: %+v", lifecycle)
	}
	raw, _ := json.Marshal(lifecycle)
	for _, secret := range []string{root, "18081", "18082", "18083", "vault.age", "host-review.json"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("lifecycle leaked private runtime field %q", secret)
		}
	}
	if lifecycle.Authority.BrowserCanUnlock || lifecycle.Authority.BrowserCanSign || !strings.Contains(lifecycle.Authority.Activation, "<private-runtime.json>") {
		t.Fatal("browser authority boundary is unclear")
	}
	history := s.TransferHistory()
	if len(history.Items) != 2 || history.Items[0].Direction != "evm-to-koinos" || history.Items[0].Finality.State != "finalized" || history.Items[0].Quorum.State != "unknown" || history.Items[1].Direction != "koinos-to-evm" || history.Items[1].Finality.State != "pending" {
		t.Fatalf("unexpected transfer history: %+v", history)
	}
}

func TestActiveJournalWithoutProcessRequiresRecovery(t *testing.T) {
	s, _ := managedViewFixture(t, "active")
	defer s.Close()
	lifecycle := s.ManagedLifecycle()
	if lifecycle.Signer.State != "recovery-required" || lifecycle.Signer.Problem == "" {
		t.Fatalf("orphaned active journal was trusted: %+v", lifecycle.Signer)
	}
	incidents := s.IncidentState(t.Context(), true)
	found := false
	for _, incident := range incidents.Current {
		if incident.Category == "duplicate-signer-risk" {
			found = true
		}
	}
	if !found || len(incidents.History) == 0 {
		t.Fatal("duplicate-signer risk was not recorded")
	}
}

func TestMaterialIncidentHistoryFixtures(t *testing.T) {
	s, _ := managedViewFixture(t, "locked")
	defer s.Close()
	now := time.Now().UTC()
	categories := []string{"rpc-disagreement", "wrong-network", "stalled-chain", "disk-pressure", "invalid-peer-data", "failed-persistence", "duplicate-signer-risk"}
	history := make([]Incident, 0, len(categories))
	for index, category := range categories {
		history = append(history, incidentFor(category, "critical", "Synthetic "+category+" evidence for the operator interface fixture.", "Keep authority-changing actions disabled and resolve the reviewed evidence.", now, index))
	}
	if err := atomicFile(s.dir, "incident-history.json", mustJSON(t, incidentDisk{SchemaVersion: 1, CheckedAt: now, History: history})); err != nil {
		t.Fatal(err)
	}
	state := s.IncidentState(t.Context(), false)
	if state.Problem != "" || len(state.History) != len(categories) {
		t.Fatalf("material incident fixtures were not readable: %+v", state)
	}
	for index, incident := range state.History {
		if incident.Category != categories[index] || !strings.Contains(incident.Evidence, "Synthetic") {
			t.Fatalf("incident fixture changed: %+v", incident)
		}
	}
}

func TestManagedLifecycleRejectsIncompleteOrMismatchedEvidence(t *testing.T) {
	t.Run("incomplete bundle inventory", func(t *testing.T) {
		s, root := managedViewFixture(t, "locked")
		defer s.Close()
		var installation managedInstallationRecord
		if err := readStrictPrivate(filepath.Join(root, "installation.json"), 256<<10, &installation); err != nil {
			t.Fatal(err)
		}
		delete(installation.Files, "vortex-keys")
		if err := atomicFile(root, "installation.json", mustJSON(t, installation)); err != nil {
			t.Fatal(err)
		}
		lifecycle := s.ManagedLifecycle()
		if lifecycle.Installation.State != "invalid" || lifecycle.Installation.Verified {
			t.Fatalf("incomplete installed bundle was trusted: %+v", lifecycle.Installation)
		}
	})

	t.Run("operation route mismatch", func(t *testing.T) {
		s, root := managedViewFixture(t, "locked")
		defer s.Close()
		path := filepath.Join(root, "managed-session", "session.json")
		var journal managedJournalRecord
		if err := readStrictPrivate(path, 4<<20, &journal); err != nil {
			t.Fatal(err)
		}
		for id, operation := range journal.Operations {
			if strings.HasPrefix(id, "koinos-to-evm/") {
				operation.Family = "koinos"
				journal.Operations[id] = operation
			}
		}
		if err := atomicFile(filepath.Dir(path), filepath.Base(path), mustJSON(t, journal)); err != nil {
			t.Fatal(err)
		}
		lifecycle := s.ManagedLifecycle()
		if lifecycle.Signer.State != "invalid" || lifecycle.Signer.Problem == "" {
			t.Fatalf("operation route mismatch was trusted: %+v", lifecycle.Signer)
		}
	})
}

func TestLifecycleRoutesRequireExistingAuthenticatedService(t *testing.T) {
	s, root := managedViewFixture(t, "locked")
	defer s.Close()
	token, _ := s.Token()
	api := NewServer(s, token, "127.0.0.1:3021", []string{"http://127.0.0.1:5174"})
	request := func(method, path, auth string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://127.0.0.1:3021"+path, bytes.NewReader(body))
		req.Host = "127.0.0.1:3021"
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res := httptest.NewRecorder()
		api.ServeHTTP(res, req)
		return res
	}
	if request(http.MethodGet, "/v1/lifecycle", "", nil).Code != http.StatusUnauthorized {
		t.Fatal("lifecycle route allowed unauthenticated access")
	}
	for _, path := range []string{"/v1/lifecycle", "/v1/transfers", "/v1/recovery", "/v1/incidents"} {
		res := request(http.MethodGet, path, token, nil)
		if res.Code != http.StatusOK || strings.Contains(res.Body.String(), root) || strings.Contains(res.Body.String(), "18083") {
			t.Fatalf("bad or leaking %s response: %s", path, res.Body.String())
		}
	}
	res := request(http.MethodPost, "/v1/incidents/check", token, []byte(`{}`))
	if res.Code != http.StatusOK {
		t.Fatal(res.Body.String())
	}
	for _, path := range []string{"/v1/unlock", "/v1/sign", "/v1/exec", "/v1/restore"} {
		if request(http.MethodPost, path, token, []byte(`{}`)).Code != http.StatusNotFound {
			t.Fatal("unexpected secret or execution endpoint", path)
		}
	}
}

func TestLifecycleRoutesOverActualLocalHTTPService(t *testing.T) {
	s, root := managedViewFixture(t, "locked")
	defer s.Close()
	token, err := s.Token()
	if err != nil {
		t.Fatal(err)
	}
	api := NewServer(s, token, "pending", []string{"http://127.0.0.1:5174"})
	service := httptest.NewUnstartedServer(api)
	api.Host = service.Listener.Addr().String()
	service.Start()
	defer service.Close()

	request, err := http.NewRequest(http.MethodGet, service.URL+"/v1/lifecycle", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Origin", "http://127.0.0.1:5174")
	response, err := service.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5174" {
		t.Fatalf("local service did not enforce and return the expected browser boundary: %s", response.Status)
	}
	var lifecycle ManagedLifecycleView
	if err := json.NewDecoder(response.Body).Decode(&lifecycle); err != nil || !lifecycle.Installation.Verified || lifecycle.Signer.OperationCount != 2 {
		t.Fatalf("actual local service returned invalid lifecycle: %+v, %v", lifecycle, err)
	}
	raw, _ := json.Marshal(lifecycle)
	if bytes.Contains(raw, []byte(root)) || bytes.Contains(raw, []byte("18083")) {
		t.Fatal("actual local service exposed a private path or RPC")
	}

	blocked, err := http.NewRequest(http.MethodGet, service.URL+"/v1/lifecycle", nil)
	if err != nil {
		t.Fatal(err)
	}
	blocked.Header.Set("Authorization", "Bearer "+token)
	blocked.Header.Set("Origin", "https://untrusted.example")
	blockedResponse, err := service.Client().Do(blocked)
	if err != nil {
		t.Fatal(err)
	}
	defer blockedResponse.Body.Close()
	if blockedResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("untrusted browser origin was accepted: %s", blockedResponse.Status)
	}
}
