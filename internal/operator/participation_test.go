package operator

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func participationFixture(t *testing.T) (maintenanceFixture, ParticipationRequest, []SignedParticipationObservation) {
	t.Helper()
	f := newMaintenanceFixture(t)
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	revision, _, _ := f.stores[0].Summary()
	request, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"probe-a", revision, envelope}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	reports := []SignedParticipationObservation{}
	for _, s := range f.stores {
		report, err := s.ObserveParticipation(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	return f, request, reports
}
func TestParticipationAuthenticatedUnavailableIsNotQuorum(t *testing.T) {
	f, req, reports := participationFixture(t)
	report, err := f.stores[0].CheckParticipation(reports, time.Now().UTC())
	if err != nil || !report.AllResponded || report.ActivationReady || len(report.Members) != 3 {
		t.Fatal(report, err)
	}
	for _, m := range report.Members {
		if m.State != "unavailable" {
			t.Fatal(m)
		}
	}
	partial, err := VerifyParticipation(req, reports[:1], f.policy, time.Now().UTC())
	if err != nil || partial.AllResponded || len(partial.Missing) != 2 {
		t.Fatal(partial, err)
	}
	// Exact challenge retries remain stable across an operator restart.
	dir := f.stores[0].dir
	f.stores[0].Close()
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retry, err := reopened.BeginParticipation(BeginParticipationRequest{req.Probe.Challenge.ID, 0, req.Envelope}, time.Now().UTC())
	if err != nil || !reflect.DeepEqual(req, retry) {
		t.Fatal("challenge changed on retry", err)
	}
	if _, err := reopened.CheckParticipation(reports, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	revision, _, _ := reopened.Summary()
	if _, err := reopened.BeginParticipation(BeginParticipationRequest{"another", revision, req.Envelope}, time.Now().UTC()); err == nil {
		t.Fatal("replaced active challenge")
	}
	if err := reopened.RevokeRelease(req.Probe.Challenge.ReleaseDigest, revision, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.CheckParticipation(reports, time.Now().UTC()); err == nil {
		t.Fatal("accepted revoked approval")
	}
}
func TestParticipationRejectsReplayTamperingAndStaleReports(t *testing.T) {
	f, req, reports := participationFixture(t)
	for _, name := range []string{"changed-report", "duplicate", "unknown", "wrong-probe", "stale", "future", "wrong-plan", "wrong-release", "expired-probe", "changed-policy", "wrong-domain"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(reports)
			var copy []SignedParticipationObservation
			json.Unmarshal(raw, &copy)
			request := req
			policy := f.policy
			now := time.Now().UTC()
			switch name {
			case "changed-report":
				copy[0].Observation.Problem = "healthy"
			case "duplicate":
				copy[1] = copy[0]
			case "unknown":
				copy[0].Observation.InstanceID = "unknown"
			case "wrong-probe":
				copy[0].Observation.ProbeDigest = strings.Repeat("f", 64)
			case "stale":
				now = copy[0].Observation.ObservedAt.Add(30 * time.Second)
			case "future":
				now = copy[0].Observation.ObservedAt.Add(-time.Nanosecond)
			case "wrong-plan":
				request.Probe.Challenge.PlanDigest = strings.Repeat("f", 64)
			case "wrong-release":
				request.Probe.Challenge.ReleaseDigest = strings.Repeat("f", 64)
			case "expired-probe":
				now = req.Probe.Challenge.ExpiresAt
			case "changed-policy":
				policy.ID = "changed-policy"
			case "wrong-domain":
				_, key, _ := f.stores[0].maintenanceIdentity()
				copy[0].Signature = hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-PROBE-V1", copy[0].Observation)))
			}
			if _, err := VerifyParticipation(request, copy, policy, now); err == nil {
				t.Fatal("accepted", name)
			}
		})
	}
	// A new locally generated nonce cannot accept old responses, even for the same plan.
	now := req.Probe.Challenge.ExpiresAt.Add(time.Second)
	revision, _, _ := f.stores[0].Summary()
	next, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"probe-b", revision, req.Envelope}, now)
	if err != nil || next.Probe.Challenge.Nonce == req.Probe.Challenge.Nonce {
		t.Fatal(next, err)
	}
	if _, err := VerifyParticipation(next, reports, f.policy, now); err == nil {
		t.Fatal("replayed old responses")
	}
}
func TestParticipationRequiresLocalReservationAndStrictHTTP(t *testing.T) {
	f, req, _ := participationFixture(t)
	api := NewServer(f.stores[1], strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	if w := instanceRequest(api, "POST", "/v1/maintenance/participation/respond", map[string]interface{}{"probe": req.Probe, "envelope": req.Envelope, "snapshot": "supplied-health"}); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := instanceRequest(api, "POST", "/v1/maintenance/participation/respond", req); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := os.Remove(filepath.Join(f.stores[1].dir, "maintenance", "journal.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.stores[1].ObserveParticipation(context.Background(), req); err == nil {
		t.Fatal("signed without local reservation history")
	}
}
func TestParticipationPortableCLI(t *testing.T) {
	f, req, _ := participationFixture(t)
	root := privateDir(t)
	binary := filepath.Join(root, "operator")
	command := exec.Command("go", "build", "-o", binary, "../../cmd/vortex-operator")
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	path := filepath.Join(root, "request.json")
	raw, _ := json.Marshal(req)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var reports []SignedParticipationObservation
	for _, s := range f.stores {
		s.Close()
		out, err := exec.Command(binary, "--data", s.dir, "--participation-file", path, "participation-respond").CombinedOutput()
		if err != nil {
			t.Fatalf("respond: %v %s", err, out)
		}
		var report SignedParticipationObservation
		if json.Unmarshal(out, &report) != nil {
			t.Fatal("invalid response")
		}
		reports = append(reports, report)
	}
	raw, _ = json.Marshal(reports)
	path = filepath.Join(root, "responses.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(binary, "--data", f.stores[0].dir, "--participation-file", path, "participation-verify").CombinedOutput()
	if err != nil {
		t.Fatalf("verify: %v %s", err, out)
	}
	var result ParticipationVerification
	if json.Unmarshal(out, &result) != nil || !result.AllResponded || result.ActivationReady {
		t.Fatal(string(out))
	}
}

func TestParticipationCapturesLiveWorkerWithoutClaimingQuorum(t *testing.T) {
	f := newMaintenanceFixture(t)
	reporter, _ := progressStoreFixture(t)
	member, err := reporter.InitializeMaintenance()
	if err != nil {
		t.Fatal(err)
	}
	old := f.stores[1].InstanceID()
	f.stores[1] = reporter
	f.policy.Members[1] = member
	// Only the requester has a planned outage in this synthetic observation test.
	f.plan.Windows = f.plan.Windows[:1]
	snapshot, err := reporter.captureProgress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	binding := snapshot.Worker.Health.NetworkBinding
	route := &f.policy.Routes[0]
	route.EVM.NetworkID = binding.EVMNetworkID
	route.EVM.Contract = binding.EVMContract
	route.Koinos.NetworkID = binding.KoinosNetworkID
	route.Koinos.Contract = binding.KoinosContract
	for i := range route.Stages {
		for j, id := range route.Stages[i].Participants {
			if id == old {
				route.Stages[i].Participants[j] = member.InstanceID
			}
		}
	}
	f.plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
	f.savePolicy(t)
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	rev, _, _ := f.stores[0].Summary()
	req, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"live-worker", rev, envelope}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := reporter.ObserveParticipation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Observation.Snapshot == nil || signed.Observation.Problem != "" {
		t.Fatal(signed)
	}
	result, err := VerifyParticipation(req, []SignedParticipationObservation{signed}, f.policy, time.Now().UTC())
	if err != nil || result.Members[0].State != "observation-only" || result.ActivationReady {
		t.Fatal(result, err)
	}
	// A valid scheduling signature cannot turn a different route into accepted
	// evidence. Nor can stale counters be hidden behind a fresh outer timestamp.
	_, key, _ := reporter.maintenanceIdentity()
	for _, test := range []string{"wrong-route", "old-snapshot", "incomplete"} {
		raw, _ := json.Marshal(signed)
		var bad SignedParticipationObservation
		json.Unmarshal(raw, &bad)
		switch test {
		case "wrong-route":
			bad.Observation.Snapshot.Worker.Health.NetworkBinding.EVMNetworkID = "1"
		case "old-snapshot":
			bad.Observation.Snapshot.SampledAt = req.Probe.Challenge.IssuedAt.Add(-time.Second)
		case "incomplete":
			a := bad.Observation.Snapshot.Worker.Health.Activity["evm-to-koinos"]
			a.Complete = false
			bad.Observation.Snapshot.Worker.Health.Activity["evm-to-koinos"] = a
		}
		bad.Signature = hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", bad.Observation)))
		if _, err := VerifyParticipation(req, []SignedParticipationObservation{bad}, f.policy, time.Now().UTC()); err == nil {
			t.Fatal("accepted", test)
		}
	}
}

func TestParticipationStoredChallengeAndSupersededApproval(t *testing.T) {
	f, req, reports := participationFixture(t)
	approvals := f.stores[0].ReleaseApprovals()
	if !currentParticipationApproval(req.Envelope, approvals, f.stores[0].InstanceID()) {
		t.Fatal("fixture approval missing")
	}
	newer := approvals[0]
	newer.Sequence++
	newer.Digest = strings.Repeat("f", 64)
	newer.Revoked = true
	if currentParticipationApproval(req.Envelope, append(approvals, newer), f.stores[0].InstanceID()) {
		t.Fatal("superseded release still current")
	}
	req.Probe.Challenge.ExpiresAt = req.Probe.Challenge.IssuedAt.Add(time.Second)
	raw, _ := json.Marshal(req)
	if err := os.WriteFile(filepath.Join(f.stores[0].dir, "maintenance", "participation.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	revision, _, _ := f.stores[0].Summary()
	if _, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"replacement", revision, req.Envelope}, req.Probe.Challenge.ExpiresAt.Add(time.Minute)); err == nil {
		t.Fatal("replaced corrupted challenge")
	}
	if _, err := f.stores[0].CheckParticipation(reports, time.Now().UTC()); err == nil {
		t.Fatal("accepted modified stored challenge")
	}
}
