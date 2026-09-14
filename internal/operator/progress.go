package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

type ProgressSnapshot struct {
	SampledAt time.Time    `json:"sampledAt"`
	Worker    WorkerStatus `json:"worker"`
}
type DirectionProgress struct {
	NewRecords            uint64 `json:"newRecords,string"`
	LocalSignatureChanges uint64 `json:"localSignatureChanges,string"`
	OtherSignatureChanges uint64 `json:"otherSignatureChanges,string"`
	CompletionTransitions uint64 `json:"completionTransitions,string"`
	Writes                uint64 `json:"writes,string"`
}
type ProgressEvaluation struct {
	State                      string                       `json:"state"`
	Reason                     string                       `json:"reason"`
	Directions                 map[string]DirectionProgress `json:"directions"`
	BothDirectionsRecorded     bool                         `json:"bothDirectionsRecorded"`
	BothLocalSignaturesChanged bool                         `json:"bothLocalSignaturesChanged"`
	ActivationReady            bool                         `json:"activationReady"`
}
type ProgressWindow struct {
	SchemaVersion  int                `json:"schemaVersion"`
	ID             string             `json:"id"`
	InstanceID     string             `json:"instanceId"`
	MinimumSeconds int                `json:"minimumSeconds"`
	EarliestFinish time.Time          `json:"earliestFinish"`
	ExpiresAt      time.Time          `json:"expiresAt"`
	Baseline       ProgressSnapshot   `json:"baseline"`
	Final          *ProgressSnapshot  `json:"final,omitempty"`
	Evaluation     ProgressEvaluation `json:"evaluation"`
}
type StartProgressWindow struct {
	ID               string `json:"id"`
	ExpectedRevision uint64 `json:"expectedRevision"`
	MinimumSeconds   int    `json:"minimumSeconds"`
}

var progressDirections = []string{"evm-to-koinos", "koinos-to-evm"}

func validActivity(a store.TransactionActivity, h *worker.Health, at time.Time) bool {
	if !a.Enabled || !a.Complete || a.Problem != "" || a.StartedAt.Before(h.StartedAt) || a.StartedAt.After(at) || a.NewRecords > a.Writes || a.CompletionTransitions > a.Writes {
		return false
	}
	if a.Writes == 0 {
		return a.LastWriteAt.IsZero() && a.NewRecords == 0 && a.LocalSignatureChanges == 0 && a.OtherSignatureChanges == 0 && a.CompletionTransitions == 0
	}
	return !a.LastWriteAt.Before(a.StartedAt) && !a.LastWriteAt.After(at)
}
func validProgressSnapshot(s ProgressSnapshot) bool {
	w, h := s.Worker, s.Worker.Health
	if !w.Registered || w.State != "running" || !hexHash.MatchString(w.RegistrationDigest) || !hexHash.MatchString(w.BinarySHA256) || !hexHash.MatchString(w.ConfigSHA256) || h == nil || h.InstanceID != w.InstanceID || h.PID <= 0 || (h.Mode != "observation-only" && h.Mode != "signing") || h.StartedAt.IsZero() || h.StartedAt.After(s.SampledAt) || h.NetworkBinding == nil || !h.NetworkBinding.Enabled() || h.NetworkBinding.Validate() != nil {
		return false
	}
	for _, name := range []string{"evm", "koinos"} {
		c, ok := h.Chains[name]
		if !ok || c.Status != "observed" || c.UpdatedAt.Before(h.StartedAt) || c.UpdatedAt.After(s.SampledAt) || s.SampledAt.Sub(c.UpdatedAt) > 30*time.Second {
			return false
		}
	}
	for _, name := range progressDirections {
		a, ok := h.Activity[name]
		if !ok || !validActivity(a, h, s.SampledAt) {
			return false
		}
	}
	return true
}

// EvaluateProgress compares locally collected observations. It reports recorded
// store changes, never signature validity, available quorum or install authority.
func EvaluateProgress(before, after ProgressSnapshot, minimum time.Duration, now time.Time) ProgressEvaluation {
	fail := func(reason string) ProgressEvaluation {
		return ProgressEvaluation{State: "invalid", Reason: reason, Directions: map[string]DirectionProgress{}}
	}
	if minimum < 30*time.Second || minimum > 24*time.Hour || !validProgressSnapshot(before) || !validProgressSnapshot(after) {
		return fail("missing, stale or incomplete worker evidence")
	}
	if !after.SampledAt.After(before.SampledAt) || after.SampledAt.After(now) || now.Sub(after.SampledAt) > 30*time.Second || after.SampledAt.Sub(before.SampledAt) < minimum {
		return fail("observation window is too short, stale or has inconsistent time")
	}
	a, b := before.Worker, after.Worker
	if a.RegistrationDigest != b.RegistrationDigest || a.BinarySHA256 != b.BinarySHA256 || a.ConfigSHA256 != b.ConfigSHA256 || a.InstanceID != b.InstanceID || a.Health.PID != b.Health.PID || !a.Health.StartedAt.Equal(b.Health.StartedAt) || a.Health.Mode != b.Health.Mode || a.Health.EVMAddress != b.Health.EVMAddress || a.Health.KoinosAddress != b.Health.KoinosAddress || !reflect.DeepEqual(a.Health.NetworkBinding, b.Health.NetworkBinding) {
		return fail("worker process, configuration, artifact or network binding changed")
	}
	for _, name := range []string{"evm", "koinos"} {
		first, last := a.Health.Chains[name], b.Health.Chains[name]
		if last.Height < first.Height || last.UpdatedAt.Before(first.UpdatedAt) {
			return fail("chain observation moved backwards")
		}
	}
	result := ProgressEvaluation{State: "no-recorded-progress", Reason: "No transfer or signature changes were recorded; block polling and repeated writes alone are insufficient.", Directions: map[string]DirectionProgress{}, BothDirectionsRecorded: true, BothLocalSignaturesChanged: true}
	for _, name := range progressDirections {
		first, last := a.Health.Activity[name], b.Health.Activity[name]
		if !first.StartedAt.Equal(last.StartedAt) || last.Writes < first.Writes || last.NewRecords < first.NewRecords || last.LocalSignatureChanges < first.LocalSignatureChanges || last.OtherSignatureChanges < first.OtherSignatureChanges || last.CompletionTransitions < first.CompletionTransitions || last.LastWriteAt.Before(first.LastWriteAt) {
			return fail("activity tracking restarted or counters moved backwards")
		}
		delta := DirectionProgress{last.NewRecords - first.NewRecords, last.LocalSignatureChanges - first.LocalSignatureChanges, last.OtherSignatureChanges - first.OtherSignatureChanges, last.CompletionTransitions - first.CompletionTransitions, last.Writes - first.Writes}
		if (delta.Writes == 0 && (!last.LastWriteAt.Equal(first.LastWriteAt) || (delta.NewRecords != 0 || delta.LocalSignatureChanges != 0 || delta.OtherSignatureChanges != 0 || delta.CompletionTransitions != 0))) || (delta.Writes > 0 && !last.LastWriteAt.After(before.SampledAt)) {
			return fail("activity changes contradict write counters or timestamps")
		}
		if delta.NewRecords > delta.Writes || delta.CompletionTransitions > delta.Writes {
			return fail("derived activity exceeds committed writes")
		}
		changed := delta.NewRecords > 0 || delta.LocalSignatureChanges > 0 || delta.OtherSignatureChanges > 0 || delta.CompletionTransitions > 0
		result.Directions[name] = delta
		result.BothDirectionsRecorded = result.BothDirectionsRecorded && changed
		result.BothLocalSignaturesChanged = result.BothLocalSignaturesChanged && delta.LocalSignatureChanges > 0
		if changed {
			result.State = "recorded-progress"
			result.Reason = "Recorded store activity changed. This does not independently verify signatures, finality, participation or update readiness."
		}
	}
	return result
}
func (s *Store) captureProgress(ctx context.Context) (ProgressSnapshot, error) {
	r, err := s.registration()
	if err != nil {
		return ProgressSnapshot{}, errors.New("register a worker before observing progress")
	}
	raw, cfg, err := workerConfig(r.BaseDir)
	hash := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(hash[:]) != r.ConfigSHA256 {
		return ProgressSnapshot{}, errors.New("registered configuration changed")
	}
	raw, err = worker.ReadPrivateFile(filepath.Join(s.dir, "worker-bin", r.BinarySHA256), 256<<20)
	hash = sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(hash[:]) != r.BinarySHA256 {
		return ProgressSnapshot{}, errors.New("registered artifact changed")
	}
	status := s.WorkerStatus(ctx)
	snapshot := ProgressSnapshot{time.Now().UTC(), status}
	expected := networkBinding(cfg)
	if status.RegistrationDigest != registrationDigest(r) || status.Health == nil || status.Health.NetworkBinding == nil || !reflect.DeepEqual(*status.Health.NetworkBinding, expected) || !validProgressSnapshot(snapshot) {
		return snapshot, errors.New("worker must have fresh bound chain observations and complete activity tracking")
	}
	return snapshot, nil
}
func (s *Store) readProgressWindow() (ProgressWindow, error) {
	var window ProgressWindow
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, "progress-window.json"), 128<<10)
	if err != nil || strictJSON(raw, &window) != nil || window.SchemaVersion != 1 || window.InstanceID != s.InstanceID() || !slug.MatchString(window.ID) || window.MinimumSeconds < 30 || window.MinimumSeconds > 86400 || !window.EarliestFinish.Equal(window.Baseline.SampledAt.Add(time.Duration(window.MinimumSeconds)*time.Second)) || !window.ExpiresAt.Equal(window.EarliestFinish.Add(5*time.Minute)) || !validProgressReceipt(window) {
		return window, errors.New("progress window is missing or corrupt; inspect it locally")
	}
	return window, nil
}

func validProgressReceipt(w ProgressWindow) bool {
	if !validProgressSnapshot(w.Baseline) || w.Evaluation.ActivationReady || w.Evaluation.Reason == "" {
		return false
	}
	switch w.Evaluation.State {
	case "collecting", "invalid":
		return (w.Evaluation.State != "collecting" || w.Final == nil) && !w.Evaluation.BothDirectionsRecorded && !w.Evaluation.BothLocalSignaturesChanged && len(w.Evaluation.Directions) == 0
	case "recorded-progress", "no-recorded-progress":
		if w.Final == nil || !w.Final.SampledAt.Before(w.ExpiresAt) {
			return false
		}
		want := EvaluateProgress(w.Baseline, *w.Final, time.Duration(w.MinimumSeconds)*time.Second, w.Final.SampledAt)
		return reflect.DeepEqual(want, w.Evaluation)
	default:
		return false
	}
}
func (s *Store) ProgressWindowState() map[string]interface{} {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	revision, _, _ := s.Summary()
	result := map[string]interface{}{"revision": revision}
	if _, err := os.Lstat(filepath.Join(s.dir, "progress-window.json")); os.IsNotExist(err) {
		return result
	}
	window, err := s.readProgressWindow()
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["window"] = window
	}
	return result
}
func (s *Store) BeginProgressWindow(ctx context.Context, req StartProgressWindow) (ProgressWindow, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	var empty ProgressWindow
	if !slug.MatchString(req.ID) || req.MinimumSeconds < 30 || req.MinimumSeconds > 86400 {
		return empty, errors.New("choose a window ID and duration from 30 to 86400 seconds")
	}
	var prior *ProgressWindow
	archive := filepath.Join(s.dir, "progress-history", req.ID+".json")
	if _, err := os.Lstat(archive); !os.IsNotExist(err) {
		return empty, errors.New("window ID is already archived or unreadable; choose a new ID")
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "progress-window.json")); !os.IsNotExist(err) {
		old, err := s.readProgressWindow()
		if err != nil {
			return empty, err
		}
		if old.ID == req.ID {
			if old.MinimumSeconds != req.MinimumSeconds {
				return empty, errors.New("window ID already has different settings")
			}
			return old, nil
		}
		if old.Evaluation.State == "collecting" {
			return empty, errors.New("finish the existing observation window before starting another")
		}
		prior = &old
	}
	snapshot, err := s.captureProgress(ctx)
	if err != nil {
		return empty, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.ExpectedRevision != s.data.Revision {
		return empty, errors.New("operator revision changed")
	}
	if prior != nil {
		if err := s.archiveProgressWindow(*prior); err != nil {
			return empty, err
		}
	}
	window := ProgressWindow{SchemaVersion: 1, ID: req.ID, InstanceID: s.InstanceID(), MinimumSeconds: req.MinimumSeconds, Baseline: snapshot, EarliestFinish: snapshot.SampledAt.Add(time.Duration(req.MinimumSeconds) * time.Second), Evaluation: ProgressEvaluation{State: "collecting", Reason: "Keep this process running until the minimum observation window has elapsed.", Directions: map[string]DirectionProgress{}}}
	window.ExpiresAt = window.EarliestFinish.Add(5 * time.Minute)
	if err := s.recordLifecycleLocked("progress window started: "+req.ID, ""); err != nil {
		return empty, err
	}
	raw, _ := json.Marshal(window)
	if err := atomicFile(s.dir, "progress-window.json", raw); err != nil {
		return empty, err
	}
	return window, nil
}
func (s *Store) FinishProgressWindow(ctx context.Context, id string) (ProgressWindow, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	window, err := s.readProgressWindow()
	if err != nil {
		return window, err
	}
	if id != window.ID {
		return window, errors.New("progress window ID changed")
	}
	if window.Evaluation.State != "collecting" {
		return window, nil
	}
	now := time.Now().UTC()
	if now.Before(window.EarliestFinish) {
		return window, errors.New("minimum observation window has not elapsed")
	}
	if !now.Before(window.ExpiresAt) {
		window.Evaluation = ProgressEvaluation{State: "invalid", Reason: "The observation window expired before a fresh final snapshot was collected."}
	} else {
		snapshot, err := s.captureProgress(ctx)
		if !snapshot.SampledAt.IsZero() {
			window.Final = &snapshot
		}
		if err == nil && !snapshot.SampledAt.Before(window.ExpiresAt) {
			err = errors.New("final snapshot arrived after window expiry")
		}
		if err != nil {
			window.Evaluation = ProgressEvaluation{State: "invalid", Reason: err.Error()}
		} else {
			window.Evaluation = EvaluateProgress(window.Baseline, snapshot, time.Duration(window.MinimumSeconds)*time.Second, time.Now().UTC())
		}
	}
	if err := s.recordLifecycle("progress window finished: "+id+": "+window.Evaluation.State, ""); err != nil {
		return window, err
	}
	raw, _ := json.Marshal(window)
	if err := atomicFile(s.dir, "progress-window.json", raw); err != nil {
		return window, err
	}
	return window, nil
}

func (s *Store) archiveProgressWindow(window ProgressWindow) error {
	dir := filepath.Join(s.dir, "progress-history")
	if err := worker.PrivateDir(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(window)
	path := filepath.Join(dir, window.ID+".json")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		old, err := worker.ReadPrivateFile(path, 128<<10)
		if err != nil || string(old) != string(raw) {
			return errors.New("archived progress receipt differs or is unreadable")
		}
		return nil
	}
	if len(entries) >= 64 {
		return errors.New("progress history full; reviewed retention required")
	}
	return atomicFile(dir, window.ID+".json", raw)
}
