package operator

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

func waveProgressFixture(instanceID string, release InstalledRelease, route MaintenanceRoute, window MaintenanceWindow) ProgressWindow {
	before, after, oldNow := progressPair()
	target := window.Start.Add(91 * time.Second)
	shift := target.Sub(oldNow)
	for _, snapshot := range []*ProgressSnapshot{&before, &after} {
		snapshot.SampledAt = snapshot.SampledAt.Add(shift)
		snapshot.Worker.InstanceID = "synthetic-wave-worker"
		snapshot.Worker.RegistrationDigest = release.RegistrationDigest
		snapshot.Worker.BinarySHA256 = release.ArtifactSHA256
		snapshot.Worker.ConfigSHA256 = release.RegisteredConfigSHA256
		snapshot.Worker.Health.InstanceID = snapshot.Worker.InstanceID
		snapshot.Worker.Health.Mode = "signing"
		snapshot.Worker.Health.StartedAt = snapshot.Worker.Health.StartedAt.Add(shift)
		snapshot.Worker.Health.NetworkBinding = &worker.NetworkBinding{SchemaVersion: 1, EVMNetworkID: route.EVM.NetworkID, KoinosNetworkID: route.Koinos.NetworkID, EVMContract: route.EVM.Contract, KoinosContract: route.Koinos.Contract}
		for name, chain := range snapshot.Worker.Health.Chains {
			chain.UpdatedAt = chain.UpdatedAt.Add(shift)
			snapshot.Worker.Health.Chains[name] = chain
		}
		for name, activity := range snapshot.Worker.Health.Activity {
			activity.StartedAt = activity.StartedAt.Add(shift)
			activity.LastWriteAt = activity.LastWriteAt.Add(shift)
			snapshot.Worker.Health.Activity[name] = activity
		}
	}
	progress := ProgressWindow{SchemaVersion: 1, ID: "wave-progress", InstanceID: instanceID, MinimumSeconds: 30, Baseline: before, Final: &after}
	progress.EarliestFinish = before.SampledAt.Add(30 * time.Second)
	progress.ExpiresAt = progress.EarliestFinish.Add(5 * time.Minute)
	progress.Evaluation = EvaluateProgress(before, after, 30*time.Second, after.SampledAt)
	return progress
}

func signedWaveFixture(t *testing.T, f maintenanceFixture, wave int) (MaintenanceEnvelope, SignedWaveResult) {
	t.Helper()
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	window := f.plan.Windows[wave]
	release := InstalledRelease{
		SchemaVersion: 1, InstanceID: window.InstanceID, Digest: window.ReleaseDigest, Component: "validator",
		Version: "1.0.1", Sequence: 2, Platform: "linux-arm64", ArtifactSHA256: strings.Repeat("b", 64),
		SourceCommit: strings.Repeat("a", 40), ConfigSchema: 1, DatabaseSchema: 1, SigningCodec: "fixture-v1",
		MixedVersionsSafe: true, RegistrationDigest: strings.Repeat("a", 64), RegisteredConfigSHA256: strings.Repeat("c", 64),
		RecordedAt: window.Start.Add(10 * time.Second), State: "installed",
	}
	progress := waveProgressFixture(window.InstanceID, release, f.policy.Routes[0], window)
	claim := WaveResultClaim{
		SchemaVersion: 1, ID: "wave-result", InstanceID: window.InstanceID,
		PlanDigest: maintenanceDigest(envelope.Plan), PolicyDigest: MaintenancePolicyDigest(f.policy), Wave: wave,
		Release: release, Progress: progress, RecordedAt: progress.Final.SampledAt.Add(time.Second), State: "reported-progress",
		Notice: "Synthetic authenticated operator report; not production evidence.",
	}
	claim.RequestDigest = maintenanceDigest(waveResultRequestIdentity{claim.ID, claim.PlanDigest, progress.ID})
	_, key, err := f.stores[wave].maintenanceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedWaveResult{Claim: claim, Signature: hex.EncodeToString(ed25519.Sign(key, CanonicalWaveResult(claim)))}
	return envelope, signed
}

func resignWave(t *testing.T, s *Store, signed *SignedWaveResult) {
	t.Helper()
	_, key, err := s.maintenanceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = hex.EncodeToString(ed25519.Sign(key, CanonicalWaveResult(signed.Claim)))
}

func TestWaveResultVerifiesExactInstalledSigningProgress(t *testing.T) {
	f := newMaintenanceFixture(t)
	envelope, signed := signedWaveFixture(t, f, 0)
	verified, err := VerifyWaveResult(signed, envelope, f.policy, signed.Claim.RecordedAt)
	if err != nil || verified.State != "verified-progress" || verified.Wave != 0 || verified.InstanceID != signed.Claim.InstanceID || verified.ReleaseDigest != signed.Claim.Release.Digest {
		t.Fatal(verified, err)
	}

	for _, name := range []string{"signature", "request", "wave", "release", "bootstrap", "observation-mode", "one-direction", "route", "installation-time", "progress-time", "result-time"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(signed)
			var changed SignedWaveResult
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "signature":
				changed.Signature = strings.Repeat("0", 128)
			case "request":
				changed.Claim.RequestDigest = strings.Repeat("f", 64)
			case "wave":
				changed.Claim.Wave = 1
			case "release":
				changed.Claim.Release.Digest = strings.Repeat("f", 64)
			case "bootstrap":
				changed.Claim.Release.State = "adopted-existing"
			case "observation-mode":
				changed.Claim.Progress.Baseline.Worker.Health.Mode = "observation-only"
				changed.Claim.Progress.Final.Worker.Health.Mode = "observation-only"
				changed.Claim.Progress.Evaluation = EvaluateProgress(changed.Claim.Progress.Baseline, *changed.Claim.Progress.Final, 30*time.Second, changed.Claim.Progress.Final.SampledAt)
			case "one-direction":
				changed.Claim.Progress.Evaluation.BothLocalSignaturesChanged = false
			case "route":
				changed.Claim.Progress.Baseline.Worker.Health.NetworkBinding.EVMNetworkID = "1"
				changed.Claim.Progress.Final.Worker.Health.NetworkBinding.EVMNetworkID = "1"
				changed.Claim.Progress.Evaluation = EvaluateProgress(changed.Claim.Progress.Baseline, *changed.Claim.Progress.Final, 30*time.Second, changed.Claim.Progress.Final.SampledAt)
			case "installation-time":
				changed.Claim.Release.RecordedAt = envelope.Plan.Windows[0].Start.Add(-time.Second)
			case "progress-time":
				changed.Claim.Progress.Final.SampledAt = envelope.Plan.Windows[0].End.Add(time.Second)
			case "result-time":
				changed.Claim.RecordedAt = envelope.Plan.Windows[0].End.Add(time.Second)
			}
			if name != "signature" {
				resignWave(t, f.stores[0], &changed)
			}
			if _, err := VerifyWaveResult(changed, envelope, f.policy, changed.Claim.RecordedAt); err == nil {
				t.Fatal("accepted changed wave evidence")
			}
		})
	}
}

func installWaveFixture(t *testing.T, f maintenanceFixture, envelope MaintenanceEnvelope) (InstalledRelease, ProgressWindow, time.Time) {
	t.Helper()
	s := f.stores[0]
	release, _ := fixtureRelease(t, f.now)
	base := filepath.Join(t.TempDir(), "validator")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	config := []byte("bridge:\n  instance-id: synthetic-wave-worker\n  observation-only: true\n")
	if err := os.WriteFile(filepath.Join(base, "config.yml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("synthetic artifact, not executable")
	artifactPath := filepath.Join(t.TempDir(), "validator")
	if err := os.WriteFile(artifactPath, artifact, 0500); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(artifact)
	if _, err := s.RegisterWorker(base, artifactPath, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	staged, err := s.StageRelease(release, "linux-arm64", artifactPath, f.now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.AdoptInstalledRelease(staged.Digest, staged.Platform, f.now)
	if err != nil {
		t.Fatal(err)
	}
	current.State = "installed"
	current.RecordedAt = envelope.Plan.Windows[0].Start.Add(10 * time.Second)
	raw, _ := json.Marshal(current)
	if err := atomicFile(s.dir, installedReleaseFile, raw); err != nil {
		t.Fatal(err)
	}
	progress := waveProgressFixture(s.InstanceID(), *current, f.policy.Routes[0], envelope.Plan.Windows[0])
	raw, _ = json.Marshal(progress)
	if err := atomicFile(s.dir, "progress-window.json", raw); err != nil {
		t.Fatal(err)
	}
	return *current, progress, progress.Final.SampledAt.Add(time.Second)
}

func TestRecordWaveResultIsPrivateImmutableAndHTTPScoped(t *testing.T) {
	f := newMaintenanceFixture(t)
	envelope, _ := signedWaveFixture(t, f, 0)
	current, progress, now := installWaveFixture(t, f, envelope)
	s := f.stores[0]
	revision, _, _ := s.Summary()
	req := RecordWaveResultRequest{ID: "local-wave-result", ExpectedRevision: revision, Envelope: envelope, ProgressID: progress.ID}
	recorded, err := s.RecordWaveResult(req, now)
	if err != nil || recorded.Claim.Release.Digest != current.Digest || recorded.Claim.Progress.ID != progress.ID {
		t.Fatal(recorded, err)
	}
	retry, err := s.RecordWaveResult(req, now.Add(time.Second))
	if err != nil || retry.Signature != recorded.Signature || !retry.Claim.RecordedAt.Equal(recorded.Claim.RecordedAt) {
		t.Fatal("exact retry changed durable result", err)
	}
	changed := req
	changed.ProgressID = "different-progress"
	if _, err := s.RecordWaveResult(changed, now); err == nil {
		t.Fatal("reused wave result ID for different evidence")
	}
	info, err := os.Stat(waveResultPath(s, req.ID))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("wave result is not private")
	}
	inventory := s.WaveResultInventory()
	if len(inventory.Results) != 1 || inventory.Results[0].Claim.ID != req.ID || inventory.Problem != "" {
		t.Fatal(inventory)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "maintenance", "wave-results", "broken.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	inventory = s.WaveResultInventory()
	if len(inventory.Results) != 1 || inventory.Problem == "" {
		t.Fatal("corrupt result hid valid evidence or was not reported", inventory)
	}

	api := NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	success := instanceRequest(api, http.MethodPost, "/v1/maintenance/wave-result", req)
	var throughHTTP SignedWaveResult
	if success.Code != http.StatusCreated || json.Unmarshal(success.Body.Bytes(), &throughHTTP) != nil || throughHTTP.Signature != recorded.Signature {
		t.Fatal("HTTP did not return the durable local result", success.Code, success.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:3021/v1/maintenance/wave-result", strings.NewReader(`{"id":"unknown-fields","progressId":"wave-progress","envelope":{},"expectedRevision":0,"claim":"caller-supplied"}`))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatal("HTTP accepted caller-supplied result evidence", response.Code, response.Body.String())
	}
}

func TestConcurrentWaveResultIDCannotBindDifferentEvidence(t *testing.T) {
	f := newMaintenanceFixture(t)
	envelope, _ := signedWaveFixture(t, f, 0)
	_, progress, now := installWaveFixture(t, f, envelope)
	s := f.stores[0]
	second := progress
	second.ID = "second-wave-progress"
	history := filepath.Join(s.dir, "progress-history")
	if err := worker.PrivateDir(history); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(second)
	if err := atomicFile(history, second.ID+".json", raw); err != nil {
		t.Fatal(err)
	}
	revision, _, _ := s.Summary()
	requests := []RecordWaveResultRequest{
		{ID: "contended-wave-result", ExpectedRevision: revision, Envelope: envelope, ProgressID: progress.ID},
		{ID: "contended-wave-result", ExpectedRevision: revision, Envelope: envelope, ProgressID: second.ID},
	}
	type outcome struct {
		result SignedWaveResult
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, len(requests))
	var group sync.WaitGroup
	for _, req := range requests {
		group.Add(1)
		go func(req RecordWaveResultRequest) {
			defer group.Done()
			<-start
			result, err := s.RecordWaveResult(req, now)
			outcomes <- outcome{result: result, err: err}
		}(req)
	}
	close(start)
	group.Wait()
	close(outcomes)

	succeeded := 0
	failed := 0
	for result := range outcomes {
		if result.err == nil {
			succeeded++
			if result.result.Claim.Progress.ID != progress.ID && result.result.Claim.Progress.ID != second.ID {
				t.Fatal("winner recorded unexpected progress evidence")
			}
		} else {
			failed++
		}
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("expected one immutable winner and one refusal, got %d successes and %d failures", succeeded, failed)
	}
	recorded, err := s.readLocalWaveResult("contended-wave-result")
	if err != nil || (recorded.Claim.Progress.ID != progress.ID && recorded.Claim.Progress.ID != second.ID) {
		t.Fatal("durable result did not retain the single winning binding", err)
	}
}

func participationReportsAt(t *testing.T, f maintenanceFixture, request ParticipationRequest, at time.Time) []SignedParticipationObservation {
	t.Helper()
	reports := make([]SignedParticipationObservation, 0, len(f.stores))
	for _, s := range f.stores {
		observation := ParticipationObservation{SchemaVersion: 1, InstanceID: s.InstanceID(), ProbeDigest: maintenanceDigest(request.Probe.Challenge), ObservedAt: at, Problem: "synthetic worker unavailable"}
		_, key, err := s.maintenanceIdentity()
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, SignedParticipationObservation{Observation: observation, Signature: hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", observation)))})
	}
	return reports
}

func TestUpdateReadinessRequiresTheImmediatelyPrecedingSignedWave(t *testing.T) {
	f := newMaintenanceFixture(t)
	envelope, prior := signedWaveFixture(t, f, 0)
	s := f.stores[1]
	now := envelope.Plan.Windows[1].Start
	revision, _, _ := s.Summary()
	participation, err := s.BeginParticipation(BeginParticipationRequest{ID: "second-wave-probe", ExpectedRevision: revision, Envelope: envelope}, now)
	if err != nil {
		t.Fatal(err)
	}
	reports := participationReportsAt(t, f, participation, now)
	revision, _, _ = s.Summary()
	request := UpdateReadinessRequest{ID: "second-wave-readiness", ExpectedRevision: revision, ReleaseDigest: envelope.Plan.Windows[1].ReleaseDigest, Platform: "linux-arm64", ParticipationResponses: reports, PriorWaveResult: &prior}
	receipt, err := s.CheckUpdateReadiness(context.Background(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if check, ok := readinessCheck(receipt, "prior-wave"); !ok || check.State != "passed" {
		t.Fatal("valid immediate predecessor result did not pass", check)
	}

	changed := prior
	changed.Claim.Release.Digest = strings.Repeat("f", 64)
	resignWave(t, f.stores[0], &changed)
	request.ID = "changed-prior-readiness"
	request.PriorWaveResult = &changed
	receipt, err = s.CheckUpdateReadiness(context.Background(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if check, ok := readinessCheck(receipt, "prior-wave"); !ok || check.State != "blocked" {
		t.Fatal("changed predecessor result passed", check)
	}
}

func TestWaveResultPortableCLIVerification(t *testing.T) {
	f := newMaintenanceFixture(t)
	clock := f.now
	f.plan.CreatedAt = clock.Add(-20 * time.Minute)
	for i := range f.plan.Windows {
		start := clock.Add(time.Duration(-15+i*20) * time.Minute)
		f.plan.Windows[i].Start = start
		f.plan.Windows[i].End = start.Add(10 * time.Minute)
		f.stores[i].data.Approvals[0].WindowStart = clock.Add(-30 * time.Minute)
	}
	f.now = clock.Add(-21 * time.Minute)
	envelope, signed := signedWaveFixture(t, f, 0)
	root := privateDir(t)
	binary := filepath.Join(root, "operator")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/vortex-operator")
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	envelopePath := filepath.Join(root, "maintenance.json")
	resultPath := filepath.Join(root, "wave-result.json")
	for path, value := range map[string]interface{}{envelopePath: envelope, resultPath: signed} {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := f.stores[2]
	s.Close()
	command := exec.Command(binary, "--data", s.dir, "--maintenance-file", envelopePath, "--wave-result-file", resultPath, "wave-result-verify")
	output, err := command.CombinedOutput()
	var verified WaveResultVerification
	if err != nil || json.Unmarshal(output, &verified) != nil || verified.State != "verified-progress" || verified.InstanceID != signed.Claim.InstanceID {
		t.Fatal(err, string(output))
	}
}
