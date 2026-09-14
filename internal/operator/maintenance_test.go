package operator

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type maintenanceFixture struct {
	stores []*Store
	policy MaintenancePolicy
	plan   MaintenancePlan
	now    time.Time
}

func newMaintenanceFixture(t *testing.T) maintenanceFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	f := maintenanceFixture{now: now, policy: MaintenancePolicy{SchemaVersion: 1, ID: "synthetic-route-policy", ExpiresAt: now.Add(24 * time.Hour)}}
	release, trust := fixtureRelease(t, now)
	verified, err := VerifyRelease(release, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s, err := OpenStore(privateDir(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		member, err := s.InitializeMaintenance()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(trust)
		if err := os.WriteFile(filepath.Join(s.dir, "release-trust.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = s.ApproveRelease(ApproveRelease{s.InstanceID(), 0, release, verified.Digest, now, now.Add(2 * time.Hour)}, now)
		if err != nil {
			t.Fatal(err)
		}
		f.stores = append(f.stores, s)
		f.policy.Members = append(f.policy.Members, member)
	}
	var evm, koinos Profile
	for _, v := range vectors(t) {
		if v.Profile.Family == "evm" {
			evm = v.Profile
		} else {
			koinos = v.Profile
		}
	}
	route := MaintenanceRoute{ID: "synthetic-route", EVM: evm, Koinos: koinos, Evidence: "Synthetic declared threshold fixture; not a contract execution result"}
	ids := []string{}
	for _, s := range f.stores {
		ids = append(ids, s.InstanceID())
	}
	for _, stage := range []string{"evm-contract", "koinos-contract", "peer", "api", "frontend"} {
		route.Stages = append(route.Stages, MaintenanceStage{stage, 2, ids})
	}
	f.policy.Routes = []MaintenanceRoute{route}
	f.plan = MaintenancePlan{SchemaVersion: 1, ID: "synthetic-update", PolicyDigest: MaintenancePolicyDigest(f.policy), CreatedAt: now}
	for i, s := range f.stores {
		start := now.Add(time.Duration(10+i*20) * time.Minute)
		f.plan.Windows = append(f.plan.Windows, MaintenanceWindow{s.InstanceID(), verified.Digest, start, start.Add(10 * time.Minute)})
	}
	f.savePolicy(t)
	return f
}
func (f maintenanceFixture) savePolicy(t *testing.T) {
	t.Helper()
	raw, _ := json.Marshal(f.policy)
	for _, s := range f.stores {
		if err := os.WriteFile(filepath.Join(s.dir, "maintenance-policy.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func (f maintenanceFixture) endorse(t *testing.T, i int, p MaintenancePlan) MaintenanceEndorsement {
	t.Helper()
	s := f.stores[i]
	rev, _, _ := s.Summary()
	e, err := s.EndorseMaintenance(p, maintenanceDigest(p), rev, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestMaintenanceUnanimousPortableScheduleSurvivesRestart(t *testing.T) {
	f := newMaintenanceFixture(t)
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		e := f.endorse(t, i, f.plan)
		envelope.Endorsements = append(envelope.Endorsements, e)
		report, err := VerifyMaintenance(envelope, f.policy, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if report.ActivationReady || (report.State == "reserved") != (i == 2) {
			t.Fatal("schedule votes granted activation or accepted incomplete consent")
		}
	}
	s := f.stores[0]
	dir := s.dir
	s.Close()
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	repeated, err := reopened.EndorseMaintenance(f.plan, maintenanceDigest(f.plan), 0, f.now)
	if err != nil || !reflect.DeepEqual(repeated, envelope.Endorsements[0]) {
		t.Fatal("durable retry failed", err)
	}
	changed := f.plan
	changed.ID = "conflicting-plan"
	revision, _, _ := reopened.Summary()
	if _, err := reopened.EndorseMaintenance(changed, maintenanceDigest(changed), revision, f.now); err == nil {
		t.Fatal("restart forgot outstanding reservation")
	}
	// Completed earlier windows must not invalidate a still-running schedule.
	if _, err := VerifyMaintenance(envelope, f.policy, f.now.Add(35*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMaintenance(envelope, f.policy, f.now.Add(61*time.Minute)); err == nil {
		t.Fatal("accepted expired plan")
	}
	b, _ := json.Marshal(envelope)
	if strings.Contains(string(b), "seed") || strings.Contains(string(b), "PRIVATE") {
		t.Fatal("private identity exported")
	}
}
func TestMaintenanceRefusesContradictoryCoordinatorPlans(t *testing.T) {
	f := newMaintenanceFixture(t)
	a, b := f.plan, f.plan
	b.ID = "coordinator-fork"
	first := f.endorse(t, 0, a)
	second := f.endorse(t, 1, b)
	s := f.stores[2]
	revision, _, _ := s.Summary()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, p := range []MaintenancePlan{a, b} {
		wg.Add(1)
		go func(p MaintenancePlan) {
			defer wg.Done()
			_, err := s.EndorseMaintenance(p, maintenanceDigest(p), revision, f.now)
			results <- err
		}(p)
	}
	wg.Wait()
	close(results)
	passed := 0
	for err := range results {
		if err == nil {
			passed++
		}
	}
	if passed != 1 {
		t.Fatal("concurrent conflicting plans both endorsed or neither persisted")
	}
	for i, p := range []MaintenancePlan{b, a} {
		rev, _, _ := f.stores[i].Summary()
		if _, err := f.stores[i].EndorseMaintenance(p, maintenanceDigest(p), rev, f.now); err == nil {
			t.Fatal("coordinator gained a conflicting vote")
		}
	}
	for _, e := range []MaintenanceEnvelope{{a, []MaintenanceEndorsement{first}}, {b, []MaintenanceEndorsement{second}}} {
		r, err := VerifyMaintenance(e, f.policy, f.now)
		if err != nil || r.State == "reserved" {
			t.Fatal("partial coordinator branch accepted")
		}
	}
}
func TestMaintenanceValidationAndLocalAuthority(t *testing.T) {
	for _, name := range []string{"overlap", "threshold", "unknown-stage", "policy-change", "duplicate-key", "digest", "revoked", "stale-revision", "late-endorsement", "journal-missing", "journal-corrupt", "wrong-instance"} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenanceFixture(t)
			s := f.stores[0]
			plan := f.plan
			revision, _, _ := s.Summary()
			now := f.now
			digest := maintenanceDigest(plan)
			switch name {
			case "overlap":
				plan.Windows[1].Start = plan.Windows[0].Start
			case "threshold":
				f.policy.Routes[0].Stages[2].Required = 3
				f.savePolicy(t)
				plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
			case "unknown-stage":
				f.policy.Routes[0].Stages[2].Name = "unknown"
				f.savePolicy(t)
				plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
			case "policy-change":
				f.policy.ID = "changed-policy"
				f.savePolicy(t)
			case "duplicate-key":
				f.policy.Members[1].PublicKey = f.policy.Members[0].PublicKey
				f.savePolicy(t)
				plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
			case "digest":
				digest = strings.Repeat("a", 64)
			case "revoked":
				if err := s.RevokeRelease(plan.Windows[0].ReleaseDigest, revision, now); err != nil {
					t.Fatal(err)
				}
				revision, _, _ = s.Summary()
			case "stale-revision":
				revision++
			case "late-endorsement":
				now = plan.Windows[0].Start
			case "journal-missing":
				os.Remove(filepath.Join(s.dir, "maintenance", "journal.json"))
			case "journal-corrupt":
				os.WriteFile(filepath.Join(s.dir, "maintenance", "journal.json"), []byte(`{}`), 0600)
			case "wrong-instance":
				f.policy.Members[0].InstanceID = "another-instance"
				f.savePolicy(t)
				plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
			}
			if name != "digest" {
				digest = maintenanceDigest(plan)
			}
			if _, err := s.EndorseMaintenance(plan, digest, revision, now); err == nil {
				t.Fatal("unsafe maintenance endorsement accepted")
			}
			if name == "journal-missing" || name == "journal-corrupt" {
				if _, err := s.InitializeMaintenance(); err == nil {
					t.Fatal("initialization erased missing reservation history")
				}
			}
		})
	}
}
func TestMaintenanceRejectsChangedAndDuplicateSignatures(t *testing.T) {
	f := newMaintenanceFixture(t)
	e := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		e.Endorsements = append(e.Endorsements, f.endorse(t, i, f.plan))
	}
	for _, name := range []string{"payload", "duplicate", "signature", "identity", "digest"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(e)
			var bad MaintenanceEnvelope
			json.Unmarshal(raw, &bad)
			switch name {
			case "payload":
				bad.Plan.ID = "changed"
			case "duplicate":
				bad.Endorsements[1] = bad.Endorsements[0]
			case "signature":
				bad.Endorsements[0].Signature = strings.Repeat("0", 128)
			case "identity":
				bad.Endorsements[0].InstanceID = "unknown"
			case "digest":
				bad.Endorsements[0].PlanDigest = strings.Repeat("0", 64)
			}
			if _, err := VerifyMaintenance(bad, f.policy, f.now); err == nil {
				t.Fatal("invalid envelope verified")
			}
		})
	}
}

func TestMaintenanceHTTPScopesAndAuthentication(t *testing.T) {
	f := newMaintenanceFixture(t)
	s := f.stores[0]
	child, err := s.CreateInstance("other-route")
	if err != nil {
		t.Fatal(err)
	}
	api := NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	r := httptest.NewRequest("GET", "http://127.0.0.1:3021/v1/maintenance", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("unauthenticated maintenance access")
	}
	envelope := MaintenanceEnvelope{Plan: f.plan}
	if w := instanceRequest(api, "POST", "/v1/maintenance/verify", envelope); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	rev, _, _ := s.Summary()
	req := EndorseMaintenanceRequest{envelope, maintenanceDigest(f.plan), rev}
	if w := instanceRequest(api, "POST", "/v1/instances/other-route/maintenance/endorse", req); w.Code != 409 {
		t.Fatal("root identity leaked into another slot", w.Code)
	}
	if w := instanceRequest(api, "POST", "/v1/maintenance/endorse", req); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := instanceRequest(api, "POST", "/v1/maintenance/endorse", map[string]string{"keyFile": "/unrelated/path"}); w.Code != 400 {
		t.Fatal("accepted arbitrary key path")
	}
	w = instanceRequest(api, "GET", "/v1/maintenance", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "seed") || !strings.Contains(w.Body.String(), req.Digest) {
		t.Fatal("public maintenance history unavailable or private identity leaked")
	}
	if child.MaintenanceState(f.now)["initialized"] != false {
		t.Fatal("other instance initialized implicitly")
	}
}
func TestMaintenancePortableCLI(t *testing.T) {
	f := newMaintenanceFixture(t)
	binary := filepath.Join(t.TempDir(), "operator")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/vortex-operator")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	envelope := MaintenanceEnvelope{Plan: f.plan}
	file := filepath.Join(t.TempDir(), "envelope.json")
	run := func(s *Store, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"--data", s.dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal(err, string(out))
		}
		return out
	}
	for _, s := range f.stores {
		revision, _, _ := s.Summary()
		s.Close()
		raw, _ := json.Marshal(envelope)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		var member MaintenanceMember
		if json.Unmarshal(run(s, "maintenance-init"), &member) != nil || member.InstanceID != s.InstanceID() {
			t.Fatal("CLI changed initialized identity")
		}
		out := run(s, "--maintenance-file", file, "--maintenance-digest", maintenanceDigest(f.plan), "--maintenance-revision", fmt.Sprint(revision), "maintenance-endorse")
		if err := json.Unmarshal(out, &envelope); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(envelope)
	os.WriteFile(file, raw, 0600)
	var report MaintenanceVerification
	if json.Unmarshal(run(f.stores[0], "--maintenance-file", file, "maintenance-verify"), &report) != nil || report.State != "reserved" || report.ActivationReady {
		t.Fatal("CLI portable unanimous plan failed")
	}
}
