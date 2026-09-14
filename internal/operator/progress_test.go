package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

func progressPair() (ProgressSnapshot, ProgressSnapshot, time.Time) {
	now := time.Date(2026, 9, 14, 20, 0, 0, 0, time.UTC)
	start := now.Add(-time.Minute)
	binding := worker.NetworkBinding{SchemaVersion: 1, EVMNetworkID: "31337", KoinosNetworkID: "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", EVMContract: "0x1111111111111111111111111111111111111111", KoinosContract: "1aqHtNRDkiAZeFtuM8fRFuurcje6eHqF8"}
	makeSnapshot := func(at time.Time, count uint64) ProgressSnapshot {
		health := &worker.Health{InstanceID: "fixture-worker", PID: 123, StartedAt: start, Mode: "observation-only", NetworkBinding: &binding, Chains: map[string]worker.ChainHealth{}, Activity: map[string]store.TransactionActivity{}}
		for _, chain := range []string{"evm", "koinos"} {
			health.Chains[chain] = worker.ChainHealth{Height: count, Status: "observed", UpdatedAt: at}
		}
		for _, direction := range progressDirections {
			health.Activity[direction] = store.TransactionActivity{Enabled: true, Complete: true, StartedAt: start.Add(time.Second), LastWriteAt: at, Writes: count, NewRecords: count, LocalSignatureChanges: count, CompletionTransitions: count}
		}
		return ProgressSnapshot{at, WorkerStatus{Registered: true, RegistrationDigest: strings.Repeat("a", 64), BinarySHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), InstanceID: "fixture-worker", State: "running", Health: health}}
	}
	return makeSnapshot(now.Add(-31*time.Second), 1), makeSnapshot(now, 2), now
}
func TestProgressComparisonBindsWindowAndProcess(t *testing.T) {
	before, after, now := progressPair()
	result := EvaluateProgress(before, after, 30*time.Second, now)
	if result.State != "recorded-progress" || !result.BothDirectionsRecorded || !result.BothLocalSignaturesChanged || result.ActivationReady || result.Directions["evm-to-koinos"].NewRecords != 1 {
		t.Fatal(result)
	}
	for _, name := range []string{"pid", "process-start", "artifact", "configuration", "network", "identity", "mode", "signer", "stale-chain", "future-chain", "stale-snapshot", "short-window", "tracking-start", "missing-direction", "incomplete", "counter-regression", "counter-time", "write-contradiction", "chain-regression"} {
		t.Run(name, func(t *testing.T) {
			a, b, clock := progressPair()
			change := b.Worker.Health.Activity["evm-to-koinos"]
			switch name {
			case "pid":
				b.Worker.Health.PID++
			case "process-start":
				b.Worker.Health.StartedAt = b.Worker.Health.StartedAt.Add(-time.Second)
			case "artifact":
				b.Worker.BinarySHA256 = strings.Repeat("d", 64)
			case "configuration":
				b.Worker.ConfigSHA256 = strings.Repeat("d", 64)
			case "network":
				copy := *b.Worker.Health.NetworkBinding
				copy.EVMNetworkID = "1"
				b.Worker.Health.NetworkBinding = &copy
			case "identity":
				b.Worker.InstanceID = "other"
				b.Worker.Health.InstanceID = "other"
			case "mode":
				b.Worker.Health.Mode = "signing"
			case "signer":
				b.Worker.Health.KoinosAddress = "another"
			case "stale-chain":
				c := b.Worker.Health.Chains["evm"]
				c.UpdatedAt = clock.Add(-31 * time.Second)
				b.Worker.Health.Chains["evm"] = c
			case "future-chain":
				c := b.Worker.Health.Chains["evm"]
				c.UpdatedAt = clock.Add(time.Second)
				b.Worker.Health.Chains["evm"] = c
			case "stale-snapshot":
				clock = clock.Add(31 * time.Second)
			case "short-window":
				a.SampledAt = b.SampledAt.Add(-time.Second)
			case "tracking-start":
				change.StartedAt = change.StartedAt.Add(time.Second)
			case "missing-direction":
				delete(b.Worker.Health.Activity, "koinos-to-evm")
			case "incomplete":
				change.Complete = false
			case "counter-regression":
				change.Writes = 0
			case "counter-time":
				change.LastWriteAt = a.SampledAt
			case "write-contradiction":
				change.Writes = 1
				change.NewRecords = 1
				change.CompletionTransitions = 1
				change.LocalSignatureChanges = 2
			case "chain-regression":
				c := b.Worker.Health.Chains["evm"]
				c.Height = 0
				b.Worker.Health.Chains["evm"] = c
			}
			b.Worker.Health.Activity["evm-to-koinos"] = change
			if r := EvaluateProgress(a, b, 30*time.Second, clock); r.State != "invalid" {
				t.Fatal("invalid progress accepted", r)
			}
		})
	}
}
func TestProgressDoesNotCountPollingOrDuplicateWrites(t *testing.T) {
	before, after, now := progressPair()
	for _, direction := range progressDirections {
		a := after.Worker.Health.Activity[direction]
		a.NewRecords = 1
		a.LocalSignatureChanges = 1
		a.CompletionTransitions = 1
		after.Worker.Health.Activity[direction] = a
	}
	r := EvaluateProgress(before, after, 30*time.Second, now)
	if r.State != "no-recorded-progress" || r.BothDirectionsRecorded || r.BothLocalSignaturesChanged || r.ActivationReady {
		t.Fatal("duplicate writes accepted as transfer progress", r)
	}
}
func progressStoreFixture(t *testing.T) (*Store, *worker.Monitor) {
	t.Helper()
	s, input, _ := setupFixture(t)
	preview, err := s.PreviewWorkerSetup(input)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateObservationWorker(CreateWorker{input, preview.Digest, "progress-setup"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.registration()
	if err != nil {
		t.Fatal(err)
	}
	_, cfg, err := workerConfig(r.BaseDir)
	if err != nil {
		t.Fatal(err)
	}
	monitor := worker.NewMonitor(r.InstanceID, true, "", "")
	monitor.SetNetworkBinding(networkBinding(cfg))
	a, b := store.NewTransactionsStore(store.NewMapBackend()), store.NewTransactionsStore(store.NewMapBackend())
	a.EnableActivity("")
	b.EnableActivity("")
	monitor.SetActivitySource(func() map[string]store.TransactionActivity {
		return map[string]store.TransactionActivity{"evm-to-koinos": a.Activity(), "koinos-to-evm": b.Activity()}
	})
	monitor.Progress("evm", 1)
	monitor.Progress("koinos", 1)
	dir := filepath.Join(r.BaseDir, "bridge", ".operator")
	lease, err := worker.Acquire(dir, "process.lock")
	if err != nil {
		t.Fatal(err)
	}
	control, err := worker.StartControl(dir, monitor, func() {})
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	cleanup := func() { control.Close(); lease.Close() }
	t.Cleanup(cleanup)
	return s, monitor
}
func TestProgressWindowCapturesLocallyAndPersistsAcrossRestart(t *testing.T) {
	s, _ := progressStoreFixture(t)
	revision, _, _ := s.Summary()
	req := StartProgressWindow{"window-a", revision, 30}
	first, err := s.BeginProgressWindow(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Evaluation.State != "collecting" || first.Baseline.Worker.Health == nil {
		t.Fatal("missing local snapshot")
	}
	if _, err := s.FinishProgressWindow(context.Background(), first.ID); err == nil {
		t.Fatal("finished early")
	}
	if _, err := s.BeginProgressWindow(context.Background(), StartProgressWindow{"window-b", revision, 30}); err == nil {
		t.Fatal("replaced collecting baseline")
	}
	dir := s.dir
	s.Close()
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.BeginProgressWindow(context.Background(), req)
	if err != nil || !again.Baseline.SampledAt.Equal(first.Baseline.SampledAt) {
		t.Fatal("retry replaced baseline", err)
	}
	// Corruption must not silently reset or replace the active window.
	os.WriteFile(filepath.Join(dir, "progress-window.json"), []byte(`{}`), 0600)
	if _, err := reopened.BeginProgressWindow(context.Background(), req); err == nil {
		t.Fatal("corrupt window reset")
	}
}
func TestProgressHTTPRejectsSuppliedSnapshotsAndCrossInstanceAccess(t *testing.T) {
	s, _ := progressStoreFixture(t)
	_, err := s.CreateInstance("other")
	if err != nil {
		t.Fatal(err)
	}
	api := NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	rev, _, _ := s.Summary()
	req := StartProgressWindow{"http-window", rev, 30}
	if w := instanceRequest(api, "POST", "/v1/instances/other/worker/progress/start", req); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w := instanceRequest(api, "POST", "/v1/worker/progress/start", map[string]interface{}{"id": "http-window", "snapshot": "coordinator-asserted-ready"}); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w := instanceRequest(api, "POST", "/v1/worker/progress/start", req)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var window ProgressWindow
	if json.Unmarshal(w.Body.Bytes(), &window) != nil || window.Baseline.Worker.Health == nil {
		t.Fatal("no runtime evidence")
	}
	if strings.Contains(w.Body.String(), "SYNTHETIC-PRIVATE") || strings.Contains(w.Body.String(), "control-token") {
		t.Fatal("private configuration exported")
	}
}

// The elapsed interval is real: a healthy process which only polls must finish
// with no recorded progress. Durable retries must never take a new final sample.
func TestProgressRealWindowFinishAndArchive(t *testing.T) {
	s, monitor := progressStoreFixture(t)
	revision, _, _ := s.Summary()
	first, err := s.BeginProgressWindow(context.Background(), StartProgressWindow{"elapsed-window", revision, 30})
	if err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	deadline := time.NewTimer(time.Until(first.EarliestFinish) + 20*time.Millisecond)
	defer deadline.Stop()
wait:
	for {
		select {
		case <-ticker.C:
			monitor.Progress("evm", 2)
			monitor.Progress("koinos", 2)
		case <-deadline.C:
			break wait
		}
	}
	final, err := s.FinishProgressWindow(context.Background(), first.ID)
	if err != nil || final.Evaluation.State != "no-recorded-progress" || final.Evaluation.ActivationReady {
		t.Fatal(final.Evaluation, err)
	}
	dir := s.dir
	s.Close()
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	retry, err := s.FinishProgressWindow(context.Background(), first.ID)
	a, _ := json.Marshal(final)
	b, _ := json.Marshal(retry)
	if err != nil || string(a) != string(b) {
		t.Fatal("finished receipt changed after restart", err)
	}
	revision, _, _ = s.Summary()
	if _, err := s.BeginProgressWindow(context.Background(), StartProgressWindow{"next-window", revision - 1, 30}); err == nil {
		t.Fatal("accepted stale revision")
	}
	if _, err := os.Lstat(filepath.Join(dir, "progress-history")); !os.IsNotExist(err) {
		t.Fatal("stale start archived a receipt")
	}
	if _, err := s.BeginProgressWindow(context.Background(), StartProgressWindow{"next-window", revision, 30}); err != nil {
		t.Fatal(err)
	}
	archived, err := worker.ReadPrivateFile(filepath.Join(dir, "progress-history", first.ID+".json"), 128<<10)
	if err != nil || string(archived) != string(a) {
		t.Fatal("archive changed receipt", err)
	}
	if _, err := s.BeginProgressWindow(context.Background(), StartProgressWindow{first.ID, revision, 30}); err == nil {
		t.Fatal("reused archived ID")
	}

	// Reuse the actual elapsed baseline to exercise failed artifact capture without
	// another thirty-second wait. This is a test-only journal fixture.
	failed := first
	failed.ID = "capture-failure"
	raw, _ := json.Marshal(failed)
	if err := atomicFile(dir, "progress-window.json", raw); err != nil {
		t.Fatal(err)
	}
	registration, err := s.registration()
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "worker-bin", registration.BinarySHA256)
	// Pinned artifacts are read-only. Simulate a privileged local modification.
	if err := os.Chmod(artifact, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("changed synthetic artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	failure, err := s.FinishProgressWindow(context.Background(), failed.ID)
	if err != nil || failure.Evaluation.State != "invalid" || failure.Final != nil || !strings.Contains(failure.Evaluation.Reason, "artifact changed") {
		t.Fatal(failure, err)
	}
	if _, err := s.readProgressWindow(); err != nil {
		t.Fatal("failed capture receipt invalid", err)
	}
}

func TestProgressReceiptRejectsChangedResult(t *testing.T) {
	before, after, now := progressPair()
	window := ProgressWindow{MinimumSeconds: 30, Baseline: before, Final: &after, ExpiresAt: now.Add(time.Minute), Evaluation: EvaluateProgress(before, after, 30*time.Second, now)}
	if !validProgressReceipt(window) {
		t.Fatal("valid receipt refused")
	}
	window.Evaluation.ActivationReady = true
	if validProgressReceipt(window) {
		t.Fatal("accepted activation claim")
	}
	window.Evaluation.ActivationReady = false
	window.Evaluation.Directions["evm-to-koinos"] = DirectionProgress{NewRecords: 100}
	if validProgressReceipt(window) {
		t.Fatal("accepted changed counter result")
	}
	window.Evaluation = ProgressEvaluation{State: "collecting", Reason: "collecting"}
	if validProgressReceipt(window) {
		t.Fatal("collecting window accepted a final snapshot")
	}
	window.Final = nil
	if !validProgressReceipt(window) {
		t.Fatal("valid collecting baseline refused")
	}
	window.Evaluation.State = "ready"
	if validProgressReceipt(window) {
		t.Fatal("accepted unknown state")
	}
}

func TestProgressExpiredWindowIsDurableFailure(t *testing.T) {
	s, _ := progressStoreFixture(t)
	before, _, clock := progressPair()
	shift := time.Now().UTC().Add(-10 * time.Minute).Sub(clock)
	before.SampledAt = before.SampledAt.Add(shift)
	before.Worker.Health.StartedAt = before.Worker.Health.StartedAt.Add(shift)
	for key, c := range before.Worker.Health.Chains {
		c.UpdatedAt = c.UpdatedAt.Add(shift)
		before.Worker.Health.Chains[key] = c
	}
	for key, a := range before.Worker.Health.Activity {
		a.StartedAt = a.StartedAt.Add(shift)
		a.LastWriteAt = a.LastWriteAt.Add(shift)
		before.Worker.Health.Activity[key] = a
	}
	window := ProgressWindow{SchemaVersion: 1, ID: "expired-window", InstanceID: s.InstanceID(), MinimumSeconds: 30, Baseline: before, EarliestFinish: before.SampledAt.Add(30 * time.Second), Evaluation: ProgressEvaluation{State: "collecting", Reason: "Collecting", Directions: map[string]DirectionProgress{}}}
	window.ExpiresAt = window.EarliestFinish.Add(5 * time.Minute)
	raw, _ := json.Marshal(window)
	if err := atomicFile(s.dir, "progress-window.json", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinishProgressWindow(context.Background(), "wrong-window"); err == nil {
		t.Fatal("finished wrong window")
	}
	finished, err := s.FinishProgressWindow(context.Background(), window.ID)
	if err != nil || finished.Evaluation.State != "invalid" || finished.Final != nil || !strings.Contains(finished.Evaluation.Reason, "expired") {
		t.Fatal(finished, err)
	}
	saved, err := s.readProgressWindow()
	if err != nil || saved.Evaluation.State != "invalid" {
		t.Fatal("failure not retained", err)
	}
	if err := s.archiveProgressWindow(saved); err != nil {
		t.Fatal(err)
	}
	if err := s.archiveProgressWindow(saved); err != nil {
		t.Fatal("idempotent archive refused", err)
	}
	saved.Evaluation.Reason = "different failure"
	if err := s.archiveProgressWindow(saved); err == nil {
		t.Fatal("replaced archived evidence")
	}
}
