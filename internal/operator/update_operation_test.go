package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

type scriptedUpdateDriver struct {
	calls       []string
	fail        map[string]int
	activeOwner string
}

func (d *scriptedUpdateDriver) result(action, state, artifact, registration string) (UpdateExecutionEvidence, error) {
	d.calls = append(d.calls, action)
	if d.fail[action] > 0 {
		d.fail[action]--
		return UpdateExecutionEvidence{}, errors.New("synthetic " + action + " failure")
	}
	return UpdateExecutionEvidence{At: time.Now().UTC(), Action: action, State: state, ArtifactSHA256: artifact, RegistrationDigest: registration, Message: "Synthetic isolated " + action + " evidence."}, nil
}
func (d *scriptedUpdateDriver) Drain(_ context.Context, o UpdateOperation) (UpdateExecutionEvidence, error) {
	return d.result("drain", "passed", o.PriorRelease.ArtifactSHA256, o.PriorRelease.RegistrationDigest)
}
func (d *scriptedUpdateDriver) Stop(_ context.Context, o UpdateOperation) (UpdateExecutionEvidence, error) {
	d.activeOwner = ""
	return d.result("stop", "locked", o.PriorRelease.ArtifactSHA256, o.PriorRelease.RegistrationDigest)
}
func (d *scriptedUpdateDriver) Install(_ context.Context, o UpdateOperation, staged StagedRelease) (UpdateExecutionEvidence, error) {
	if d.activeOwner != "" {
		return UpdateExecutionEvidence{}, errors.New("synthetic old binary still owns the signing fence")
	}
	d.activeOwner = o.ID + ":candidate"
	return d.result("install", "installed", staged.Artifact.SHA256, strings.Repeat("a", 64))
}
func (d *scriptedUpdateDriver) Verify(_ context.Context, o UpdateOperation) (UpdateExecutionEvidence, error) {
	return d.result("verify", "verified", o.CandidateArtifactSHA256(), strings.Repeat("b", 64))
}
func (d *scriptedUpdateDriver) Rollback(_ context.Context, o UpdateOperation) (UpdateExecutionEvidence, error) {
	d.activeOwner = ""
	return d.result("rollback", "recovered", o.PriorRelease.ArtifactSHA256, o.PriorRelease.RegistrationDigest)
}
func (d *scriptedUpdateDriver) ForwardRecover(_ context.Context, o UpdateOperation, staged StagedRelease) (UpdateExecutionEvidence, error) {
	d.activeOwner = o.ID + ":recovery"
	return d.result("forward-recover", "recovered", staged.Artifact.SHA256, strings.Repeat("c", 64))
}

func writeCandidateResult(t *testing.T, s *Store, staged StagedRelease, now time.Time) {
	t.Helper()
	checks := []string{"pinned-networks-and-both-direction-transfer-records", "observation-produced-zero-signatures", "signature-exchange-refused", "duplicate-process-excluded", "network-mismatch-pauses-and-recovers", "crash-restart-checkpoints-and-records-retained", "graceful-stop", "only-read-rpc-methods"}
	result := CandidateResult{ReleaseDigest: staged.Digest, Platform: staged.Platform, ArtifactSHA256: staged.Artifact.SHA256, CheckerSHA256: strings.Repeat("1", 64), StartedAt: now.Add(-2 * time.Minute), FinishedAt: now.Add(-time.Minute), Report: CandidateReport{SchemaVersion: 2, Scope: "isolated-observation-transfer-v2", ArtifactSHA256: staged.Artifact.SHA256, State: "checks-passed", Checks: checks}, Isolation: "synthetic-isolated-update-state-machine", Notice: "Synthetic fixture without production keys or endpoints."}
	raw, _ := json.Marshal(result)
	if err := atomicFile(filepath.Join(s.dir, "releases", staged.Digest, staged.Platform), "candidate-result.json", raw); err != nil {
		t.Fatal(err)
	}
}

func stageUpdateRelease(t *testing.T, s *Store, base ReleaseManifest, now time.Time, id, version string, sequence uint64, content []byte, mutate func(*ReleaseManifest)) StagedRelease {
	t.Helper()
	manifest := base
	manifest.ID, manifest.Version, manifest.Sequence = id, version, sequence
	manifest.CreatedAt = now.Add(-time.Hour).Format(time.RFC3339)
	manifest.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339)
	manifest.CompatibleFrom = []string{base.Version}
	hash := sha256.Sum256(content)
	manifest.Artifacts = []ReleaseArtifact{{Platform: "linux-arm64", SHA256: hex.EncodeToString(hash[:]), Size: uint64(len(content))}}
	if mutate != nil {
		mutate(&manifest)
	}
	release := signedFixtureManifest(t, manifest)
	path := filepath.Join(t.TempDir(), "validator")
	if err := os.WriteFile(path, content, 0500); err != nil {
		t.Fatal(err)
	}
	staged, err := s.StageRelease(release, "linux-arm64", path, now)
	if err != nil {
		t.Fatal(err)
	}
	writeCandidateResult(t, s, staged, now)
	revision, _, _ := s.Summary()
	verified, err := VerifyRelease(release, mustReleaseTrust(t, s), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRelease(ApproveRelease{InstanceID: s.InstanceID(), ExpectedRevision: revision, Release: release, Digest: verified.Digest, WindowStart: now, WindowEnd: now.Add(2 * time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	return staged
}

func writeReadyReceipt(t *testing.T, s *Store, staged StagedRelease, id string, now time.Time) UpdateReadinessReceipt {
	t.Helper()
	revision, _, _ := s.Summary()
	checks := make([]UpdateReadinessCheck, 0, len(requiredUpdateReadinessChecks))
	for _, checkID := range requiredUpdateReadinessChecks {
		checks = append(checks, updateCheck(checkID, "passed", "Synthetic isolated acceptance evidence for "+checkID+"."))
	}
	receipt := UpdateReadinessReceipt{SchemaVersion: 1, ID: id, InstanceID: s.InstanceID(), RequestDigest: strings.Repeat("d", 64), Revision: revision, ReleaseDigest: staged.Digest, Platform: staged.Platform, CurrentVersion: "1.0.1", CandidateVersion: staged.Release.Manifest.Version, CheckedAt: now, ExpiresAt: now.Add(30 * time.Second), State: "ready", ActivationReady: true, Checks: checks, Notice: "Synthetic ready receipt used only to exercise the isolated execution journal."}
	if err := validateUpdateReadinessReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(s.dir, "update-readiness")
	if err := workerPrivateDir(root); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(receipt)
	if err := atomicFile(root, id+".json", raw); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func workerPrivateDir(path string) error {
	return os.MkdirAll(path, 0700)
}

func updateFixture(t *testing.T, migration bool) (*Store, StagedRelease, UpdateReadinessReceipt, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	return updateFixtureAt(t, now, migration)
}

func updateFixtureAt(t *testing.T, now time.Time, migration bool) (*Store, StagedRelease, UpdateReadinessReceipt, time.Time) {
	t.Helper()
	s, release, digest := installedFixture(t, now)
	if _, err := s.AdoptInstalledRelease(digest, "linux-arm64", now); err != nil {
		t.Fatal(err)
	}
	mutate := func(manifest *ReleaseManifest) {}
	if migration {
		mutate = func(manifest *ReleaseManifest) {
			manifest.ConfigSchema = 2
			manifest.DatabaseSchema = 2
			manifest.SigningCodec = "fixture-v2"
			manifest.MixedVersionsSafe = false
		}
	}
	staged := stageUpdateRelease(t, s, release.Manifest, now, "candidate-update", "1.1.0", 3, []byte("isolated candidate executable bytes"), mutate)
	receipt := writeReadyReceipt(t, s, staged, "ready-candidate", now)
	return s, staged, receipt, now
}

type controlledLocalDriver struct {
	local      *LocalUpdateDriver
	failVerify int
}

func (d *controlledLocalDriver) Drain(ctx context.Context, operation UpdateOperation) (UpdateExecutionEvidence, error) {
	return d.local.Drain(ctx, operation)
}
func (d *controlledLocalDriver) Stop(ctx context.Context, operation UpdateOperation) (UpdateExecutionEvidence, error) {
	return d.local.Stop(ctx, operation)
}
func (d *controlledLocalDriver) Install(ctx context.Context, operation UpdateOperation, staged StagedRelease) (UpdateExecutionEvidence, error) {
	return d.local.Install(ctx, operation, staged)
}
func (d *controlledLocalDriver) Verify(_ context.Context, operation UpdateOperation) (UpdateExecutionEvidence, error) {
	if d.failVerify > 0 {
		d.failVerify--
		return UpdateExecutionEvidence{}, errors.New("synthetic post-install identity failure")
	}
	return UpdateExecutionEvidence{At: time.Now().UTC(), Action: "verify", State: "verified", ArtifactSHA256: operation.CandidateArtifactSHA256(), RegistrationDigest: strings.Repeat("e", 64), Message: "Synthetic isolated validator identity and fencing verification passed."}, nil
}
func (d *controlledLocalDriver) Rollback(ctx context.Context, operation UpdateOperation) (UpdateExecutionEvidence, error) {
	return d.local.Rollback(ctx, operation)
}
func (d *controlledLocalDriver) ForwardRecover(ctx context.Context, operation UpdateOperation, staged StagedRelease) (UpdateExecutionEvidence, error) {
	return d.local.ForwardRecover(ctx, operation, staged)
}

func writeSyntheticPostUpdateProgress(t *testing.T, s *Store, operation UpdateOperation) string {
	t.Helper()
	current, err := s.CurrentRelease()
	if err != nil {
		t.Fatal(err)
	}
	baselineAt := operation.UpdatedAt.Add(time.Second)
	finalAt := baselineAt.Add(31 * time.Second)
	startedAt := baselineAt.Add(-time.Minute)
	binding := worker.NetworkBinding{SchemaVersion: 1, EVMNetworkID: "31337", KoinosNetworkID: "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", EVMContract: "0x1111111111111111111111111111111111111111", KoinosContract: "1aqHtNRDkiAZeFtuM8fRFuurcje6eHqF8"}
	snapshot := func(at time.Time, count uint64) ProgressSnapshot {
		health := &worker.Health{InstanceID: "synthetic-updated-signer", PID: 4242, StartedAt: startedAt, Mode: "signing", NetworkBinding: &binding, Chains: map[string]worker.ChainHealth{}, Activity: map[string]store.TransactionActivity{}}
		for _, chain := range []string{"evm", "koinos"} {
			health.Chains[chain] = worker.ChainHealth{Height: count, Status: "observed", UpdatedAt: at}
		}
		for _, direction := range progressDirections {
			health.Activity[direction] = store.TransactionActivity{Enabled: true, Complete: true, StartedAt: startedAt.Add(time.Second), LastWriteAt: at, Writes: count, NewRecords: count, LocalSignatureChanges: count, CompletionTransitions: count}
		}
		return ProgressSnapshot{SampledAt: at, Worker: WorkerStatus{Registered: true, RegistrationDigest: current.RegistrationDigest, BinarySHA256: current.ArtifactSHA256, ConfigSHA256: current.RegisteredConfigSHA256, InstanceID: health.InstanceID, State: "running", Health: health}}
	}
	baseline, final := snapshot(baselineAt, 1), snapshot(finalAt, 2)
	id := "post-update-" + operation.ID
	window := ProgressWindow{SchemaVersion: 1, ID: id, InstanceID: s.InstanceID(), MinimumSeconds: 30, Baseline: baseline, Final: &final}
	window.EarliestFinish = baselineAt.Add(30 * time.Second)
	window.ExpiresAt = window.EarliestFinish.Add(5 * time.Minute)
	window.Evaluation = EvaluateProgress(baseline, final, 30*time.Second, finalAt)
	if !validProgressReceipt(window) || window.Evaluation.State != "recorded-progress" || !window.Evaluation.BothLocalSignaturesChanged {
		t.Fatal("synthetic post-update progress is invalid", window)
	}
	raw, _ := json.Marshal(window)
	if err := atomicFile(s.dir, "progress-window.json", raw); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestUpdateOperationPersistsIntentAcrossRestart(t *testing.T) {
	s, staged, receipt, now := updateFixture(t, false)
	req := BeginUpdateRequest{ID: "rolling-a", ExpectedRevision: receipt.Revision, ReadinessID: receipt.ID, ReleaseDigest: staged.Digest, Platform: staged.Platform, Mode: "rolling"}
	operation, err := s.BeginUpdate(req, now.Add(time.Second))
	if err != nil || operation.State != "prepared" {
		t.Fatal("could not prepare isolated update", operation, err)
	}
	if repeated, err := s.BeginUpdate(req, now.Add(2*time.Second)); err != nil || repeated.RequestDigest != operation.RequestDigest {
		t.Fatal("exact start retry was not idempotent", err)
	}
	driver := &scriptedUpdateDriver{fail: map[string]int{}}
	operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(2*time.Second))
	if err != nil || operation.State != "drained" {
		t.Fatal("drain did not persist", operation, err)
	}
	dir := s.dir
	s.Close()
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if current := reopened.UpdateOperationState(); current.Operation == nil || current.Operation.State != "drained" {
		t.Fatal("restart lost the durable update phase", current)
	}
	for _, want := range []string{"stopped", "installed", "verified"} {
		operation, err = reopened.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(3*time.Second))
		if err != nil || operation.State != want {
			t.Fatalf("wanted %s after restart, got %+v: %v", want, operation, err)
		}
	}
	if _, err := reopened.ConfirmUpdateProgress(operation.ID, "missing-progress", now.Add(4*time.Second)); err == nil {
		t.Fatal("verified bytes resumed signing without fresh two-direction progress")
	}
	if _, err := reopened.ArchiveUpdate(operation.ID); err == nil {
		t.Fatal("nonterminal verified update was archived")
	}
}

func TestUpdateFailureRollsBackAndArchivesExactEvidence(t *testing.T) {
	s, staged, receipt, now := updateFixture(t, false)
	operation, err := s.BeginUpdate(BeginUpdateRequest{ID: "rollback-a", ExpectedRevision: receipt.Revision, ReadinessID: receipt.ID, ReleaseDigest: staged.Digest, Platform: staged.Platform, Mode: "rolling"}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	driver := &scriptedUpdateDriver{fail: map[string]int{"verify": 1}}
	for i := 0; i < 4; i++ {
		operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(time.Duration(2+i)*time.Second))
	}
	if err == nil || operation.State != "failed" || operation.Recovery != "rollback" {
		t.Fatal("post-install failure did not halt for rollback", operation, err)
	}
	operation, err = s.RollbackUpdate(context.Background(), operation.ID, driver, now.Add(7*time.Second))
	if err != nil || operation.State != "rolled-back" || operation.Recovery != "" {
		t.Fatal("compatible rollback did not complete", operation, err)
	}
	if _, err := s.ArchiveUpdate(operation.ID); err != nil {
		t.Fatal(err)
	}
	inventory := s.UpdateOperationState()
	if inventory.Operation != nil || len(inventory.History) != 1 || inventory.History[0].State != "rolled-back" {
		t.Fatal("terminal rollback evidence was not retained", inventory)
	}
}

func TestLocalUpdateDriverInstallsExactBytesAndRestoresPriorFence(t *testing.T) {
	s, staged, receipt, now := updateFixture(t, false)
	prior, err := s.CurrentRelease()
	if err != nil {
		t.Fatal(err)
	}
	operation, err := s.BeginUpdate(BeginUpdateRequest{ID: "local-driver-a", ExpectedRevision: receipt.Revision, ReadinessID: receipt.ID, ReleaseDigest: staged.Digest, Platform: staged.Platform, Mode: "rolling"}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	driver := NewLocalUpdateDriver(s)
	for _, want := range []string{"drained", "stopped", "installed"} {
		operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(2*time.Second))
		if err != nil || operation.State != want {
			t.Fatalf("local driver did not reach %s: %+v %v", want, operation, err)
		}
	}
	installed, err := s.CurrentRelease()
	if err != nil || installed.Digest != staged.Digest || installed.ArtifactSHA256 != staged.Artifact.SHA256 {
		t.Fatal("local driver did not bind the exact staged bytes", installed, err)
	}
	operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(3*time.Second))
	if err == nil || operation.State != "failed" || operation.Recovery != "rollback" {
		t.Fatal("non-runnable synthetic candidate did not fail closed", operation, err)
	}
	operation, err = s.RollbackUpdate(context.Background(), operation.ID, driver, now.Add(4*time.Second))
	if err != nil || operation.State != "rolled-back" {
		t.Fatal("local rollback failed", operation, err)
	}
	restored, err := s.CurrentRelease()
	if err != nil || restored.Digest != prior.Digest || restored.ArtifactSHA256 != prior.ArtifactSHA256 {
		t.Fatal("rollback did not restore the exact prior identity", restored, err)
	}
	registration, err := s.registration()
	if err != nil || registration.BinarySHA256 != prior.ArtifactSHA256 {
		t.Fatal("rollback left the candidate registration active", registration, err)
	}
	if status := s.WorkerStatus(context.Background()); status.State == "running" {
		t.Fatal("old and candidate binaries were able to run after recovery", status)
	}
}

func TestUpdateHaltsBeforeInstallWhenDrainFails(t *testing.T) {
	s, staged, receipt, now := updateFixture(t, false)
	operation, err := s.BeginUpdate(BeginUpdateRequest{ID: "halt-a", ExpectedRevision: receipt.Revision, ReadinessID: receipt.ID, ReleaseDigest: staged.Digest, Platform: staged.Platform, Mode: "rolling"}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	driver := &scriptedUpdateDriver{fail: map[string]int{"drain": 1}}
	operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(2*time.Second))
	if err == nil || operation.State != "halted" || len(driver.calls) != 1 || driver.calls[0] != "drain" {
		t.Fatal("failed drain reached a later phase", operation, driver.calls, err)
	}
}

func TestUpdateRechecksLocalApprovalBeforeInstall(t *testing.T) {
	s, staged, receipt, now := updateFixture(t, false)
	operation, err := s.BeginUpdate(BeginUpdateRequest{ID: "revoked-before-install", ExpectedRevision: receipt.Revision, ReadinessID: receipt.ID, ReleaseDigest: staged.Digest, Platform: staged.Platform, Mode: "rolling"}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	driver := &scriptedUpdateDriver{fail: map[string]int{}}
	for _, want := range []string{"drained", "stopped"} {
		operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(2*time.Second))
		if err != nil || operation.State != want {
			t.Fatal(operation, err)
		}
	}
	revision, _, _ := s.Summary()
	if err := s.RevokeRelease(staged.Digest, revision, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(4*time.Second))
	if err == nil || operation.State != "halted" || !strings.Contains(operation.Failure, "approval") {
		t.Fatal("revoked approval still installed a candidate", operation, err)
	}
	for _, call := range driver.calls {
		if call == "install" {
			t.Fatal("install driver ran after local approval was revoked")
		}
	}
}

func TestMigrationRequiresForwardRecoveryAndReverification(t *testing.T) {
	s, staged, receipt, now := updateFixture(t, true)
	request := BeginUpdateRequest{ID: "migration-a", ExpectedRevision: receipt.Revision, ReadinessID: receipt.ID, ReleaseDigest: staged.Digest, Platform: staged.Platform, Mode: "migration"}
	if _, err := s.BeginUpdate(request, now.Add(time.Second)); err == nil {
		t.Fatal("forward-only migration started without explicit confirmation")
	}
	request.ConfirmForwardOnly = true
	operation, err := s.BeginUpdate(request, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	driver := &scriptedUpdateDriver{fail: map[string]int{"verify": 1}}
	for i := 0; i < 4; i++ {
		operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(time.Duration(2+i)*time.Second))
	}
	if err == nil || operation.State != "failed" || operation.Recovery != "forward" {
		t.Fatal("failed migration offered unsafe rollback", operation, err)
	}
	recovery := stageUpdateRelease(t, s, staged.Release.Manifest, now.Add(7*time.Second), "migration-recovery", "1.1.1", 4, []byte("isolated forward recovery bytes"), func(manifest *ReleaseManifest) {
		manifest.CompatibleFrom = []string{staged.Release.Manifest.Version}
	})
	operation, err = s.ForwardRecoverUpdate(context.Background(), operation.ID, ForwardRecoveryRequest{ReleaseDigest: recovery.Digest, Platform: recovery.Platform}, driver, now.Add(8*time.Second))
	if err != nil || operation.State != "forward-recovered" || operation.ReleaseDigest != recovery.Digest {
		t.Fatal("forward recovery did not retain a verification gate", operation, err)
	}
	operation, err = s.AdvanceUpdate(context.Background(), operation.ID, driver, now.Add(9*time.Second))
	if err != nil || operation.State != "verified" {
		t.Fatal("forward recovery was not reverified", operation, err)
	}
	if _, err := s.ConfirmUpdateProgress(operation.ID, "missing-progress", now.Add(10*time.Second)); err == nil {
		t.Fatal("forward recovery completed without new signing progress")
	}
}

func TestUpdateHTTPRequiresAuthenticationAndTypedLocalRequests(t *testing.T) {
	s, staged, receipt, now := updateFixture(t, false)
	token := strings.Repeat("a", 64)
	server := NewServer(s, token, "operator.test", nil)
	call := func(path string, value interface{}, authenticated bool) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(value)
		req := httptest.NewRequest(http.MethodPost, "http://operator.test"+path, bytes.NewReader(raw))
		req.Host = "operator.test"
		req.Header.Set("Content-Type", "application/json")
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, req)
		return response
	}
	request := BeginUpdateRequest{ID: "http-update", ExpectedRevision: receipt.Revision, ReadinessID: receipt.ID, ReleaseDigest: staged.Digest, Platform: staged.Platform, Mode: "rolling"}
	if response := call("/v1/updates/start", request, false); response.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated update start was accepted", response.Code)
	}
	if response := call("/v1/updates/start", map[string]interface{}{"id": request.ID, "expectedRevision": request.ExpectedRevision, "readinessId": request.ReadinessID, "releaseDigest": request.ReleaseDigest, "platform": request.Platform, "mode": request.Mode, "command": "curl production.invalid"}, true); response.Code != http.StatusBadRequest {
		t.Fatal("HTTP update accepted an arbitrary command field", response.Code, response.Body.String())
	}
	if response := call("/v1/updates/start", request, true); response.Code != http.StatusCreated {
		t.Fatal("typed authenticated update start failed", response.Code, response.Body.String())
	}
	if response := call("/v1/updates/archive", map[string]string{"id": request.ID, "path": "/tmp/discard"}, true); response.Code != http.StatusBadRequest {
		t.Fatal("archive endpoint accepted a caller-supplied path", response.Code, response.Body.String())
	}
	operation := s.UpdateOperationState().Operation
	if operation == nil || operation.ID != request.ID || operation.StartedAt.Before(now) {
		t.Fatal("HTTP start did not persist the exact operation", operation)
	}
}

func TestPrompt07ThreeValidatorStagedRolloutAcceptance(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	type validatorFixture struct {
		store   *Store
		staged  StagedRelease
		receipt UpdateReadinessReceipt
		driver  *controlledLocalDriver
	}
	validators := make([]validatorFixture, 3)
	instanceIDs := map[string]bool{}
	for i := range validators {
		s, staged, receipt, _ := updateFixtureAt(t, now, false)
		if instanceIDs[s.InstanceID()] {
			t.Fatal("synthetic validators shared an operator identity")
		}
		instanceIDs[s.InstanceID()] = true
		validators[i] = validatorFixture{s, staged, receipt, &controlledLocalDriver{local: NewLocalUpdateDriver(s)}}
		if i > 0 && staged.Digest != validators[0].staged.Digest {
			t.Fatal("validators did not stage the same exact signed release")
		}
	}

	// The first attempted wave fails after installation. Later validators must
	// remain untouched, and exact prior bytes must be restored before retry.
	first := &validators[0]
	first.driver.failVerify = 1
	failed, err := first.store.BeginUpdate(BeginUpdateRequest{ID: "pilot-wave-failed", ExpectedRevision: first.receipt.Revision, ReadinessID: first.receipt.ID, ReleaseDigest: first.staged.Digest, Platform: first.staged.Platform, Mode: "rolling"}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		failed, err = first.store.AdvanceUpdate(context.Background(), failed.ID, first.driver, now.Add(time.Duration(2+i)*time.Second))
	}
	if err == nil || failed.State != "failed" {
		t.Fatal("first failed wave did not halt", failed, err)
	}
	for i := 1; i < 3; i++ {
		if validators[i].store.UpdateOperationState().Operation != nil {
			t.Fatalf("later validator %d started after a failed wave", i)
		}
	}
	failed, err = first.store.RollbackUpdate(context.Background(), failed.ID, first.driver, now.Add(7*time.Second))
	if err != nil || failed.State != "rolled-back" {
		t.Fatal("failed first wave did not restore exact prior bytes", failed, err)
	}
	if _, err := first.store.ArchiveUpdate(failed.ID); err != nil {
		t.Fatal(err)
	}

	// A registry or coordinator is not consulted after local staging. Each wave
	// uses only its own retained artifact, receipt and explicit local actions.
	// The first validator gets a fresh local receipt after rollback.
	first.receipt = writeReadyReceipt(t, first.store, first.staged, "ready-retry", now.Add(8*time.Second))
	completed := make([]UpdateOperation, 0, 3)
	for i := range validators {
		fixture := &validators[i]
		id := "pilot-wave-" + string(rune('a'+i))
		operation, err := fixture.store.BeginUpdate(BeginUpdateRequest{ID: id, ExpectedRevision: fixture.receipt.Revision, ReadinessID: fixture.receipt.ID, ReleaseDigest: fixture.staged.Digest, Platform: fixture.staged.Platform, Mode: "rolling"}, now.Add(time.Duration(9+i)*time.Second))
		if err != nil {
			t.Fatalf("wave %d could not start: %v", i, err)
		}
		for _, want := range []string{"drained", "stopped", "installed", "verified"} {
			operation, err = fixture.store.AdvanceUpdate(context.Background(), operation.ID, fixture.driver, now.Add(time.Duration(10+i)*time.Second))
			if err != nil || operation.State != want {
				t.Fatalf("wave %d wanted %s, got %+v: %v", i, want, operation, err)
			}
		}
		progressID := writeSyntheticPostUpdateProgress(t, fixture.store, operation)
		operation, err = fixture.store.ConfirmUpdateProgress(operation.ID, progressID, operation.UpdatedAt.Add(33*time.Second))
		if err != nil || operation.State != "complete" {
			t.Fatalf("wave %d completed without valid progress: %+v %v", i, operation, err)
		}
		completed = append(completed, operation)
		if i+1 < len(validators) && validators[i+1].store.UpdateOperationState().Operation != nil {
			t.Fatalf("wave %d began before wave %d completed", i+1, i)
		}
	}
	for i, operation := range completed {
		if operation.ProgressID == "" || operation.ReleaseDigest != validators[i].staged.Digest || operation.CandidateArtifactSHA256() != validators[i].staged.Artifact.SHA256 {
			t.Fatalf("wave %d lost exact release or progress evidence: %+v", i, operation)
		}
		if status := validators[i].store.WorkerStatus(context.Background()); status.State == "running" {
			t.Fatalf("wave %d left a synthetic old binary running alongside the recorded candidate", i)
		}
	}
}
