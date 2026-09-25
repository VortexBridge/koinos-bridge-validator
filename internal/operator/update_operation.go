package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

const updateOperationFile = "update-operation.json"
const maxUpdateHistory = 64

type BeginUpdateRequest struct {
	ID                 string `json:"id"`
	ExpectedRevision   uint64 `json:"expectedRevision"`
	ReadinessID        string `json:"readinessId"`
	ReleaseDigest      string `json:"releaseDigest"`
	Platform           string `json:"platform"`
	Mode               string `json:"mode"`
	ConfirmForwardOnly bool   `json:"confirmForwardOnly"`
}

type ForwardRecoveryRequest struct {
	ReleaseDigest string `json:"releaseDigest"`
	Platform      string `json:"platform"`
}

type UpdateExecutionEvidence struct {
	At                 time.Time `json:"at"`
	Action             string    `json:"action"`
	ArtifactSHA256     string    `json:"artifactSha256,omitempty"`
	RegistrationDigest string    `json:"registrationDigest,omitempty"`
	State              string    `json:"state"`
	Message            string    `json:"message"`
}

type UpdateStep struct {
	At       time.Time                `json:"at"`
	State    string                   `json:"state"`
	Evidence *UpdateExecutionEvidence `json:"evidence,omitempty"`
	Message  string                   `json:"message"`
}

type UpdateOperation struct {
	SchemaVersion   int              `json:"schemaVersion"`
	ID              string           `json:"id"`
	InstanceID      string           `json:"instanceId"`
	RequestDigest   string           `json:"requestDigest"`
	ReadinessID     string           `json:"readinessId"`
	ReleaseDigest   string           `json:"releaseDigest"`
	Platform        string           `json:"platform"`
	Mode            string           `json:"mode"`
	State           string           `json:"state"`
	Recovery        string           `json:"recovery"`
	StartedAt       time.Time        `json:"startedAt"`
	UpdatedAt       time.Time        `json:"updatedAt"`
	PriorRelease    InstalledRelease `json:"priorRelease"`
	Candidate       ReleaseManifest  `json:"candidate"`
	RecoveryRelease *ReleaseManifest `json:"recoveryRelease,omitempty"`
	RecoveryDigest  string           `json:"recoveryDigest,omitempty"`
	Failure         string           `json:"failure,omitempty"`
	ProgressID      string           `json:"progressId,omitempty"`
	Steps           []UpdateStep     `json:"steps"`
}

type UpdateOperationInventory struct {
	Operation *UpdateOperation  `json:"operation,omitempty"`
	History   []UpdateOperation `json:"history"`
	Problem   string            `json:"problem,omitempty"`
	Notice    string            `json:"notice"`
}

type UpdateDriver interface {
	Drain(context.Context, UpdateOperation) (UpdateExecutionEvidence, error)
	Stop(context.Context, UpdateOperation) (UpdateExecutionEvidence, error)
	Install(context.Context, UpdateOperation, StagedRelease) (UpdateExecutionEvidence, error)
	Verify(context.Context, UpdateOperation) (UpdateExecutionEvidence, error)
	Rollback(context.Context, UpdateOperation) (UpdateExecutionEvidence, error)
	ForwardRecover(context.Context, UpdateOperation, StagedRelease) (UpdateExecutionEvidence, error)
}

func validUpdateMode(mode string) bool {
	return mode == "rolling" || mode == "migration" || mode == "emergency"
}

func updateTerminal(state string) bool {
	return state == "complete" || state == "rolled-back" || state == "halted"
}

func validateUpdateEvidence(evidence UpdateExecutionEvidence, action string) error {
	if evidence.At.IsZero() || evidence.Action != action || (evidence.State != "passed" && evidence.State != "locked" && evidence.State != "installed" && evidence.State != "verified" && evidence.State != "recovered") || len(evidence.Message) == 0 || len(evidence.Message) > 2048 || (evidence.ArtifactSHA256 != "" && !hexHash.MatchString(evidence.ArtifactSHA256)) || (evidence.RegistrationDigest != "" && !hexHash.MatchString(evidence.RegistrationDigest)) {
		return errors.New("update driver returned invalid evidence")
	}
	return nil
}

func validateUpdateOperation(operation UpdateOperation) error {
	if operation.SchemaVersion != 1 || !slug.MatchString(operation.ID) || !slug.MatchString(operation.InstanceID) || !hexHash.MatchString(operation.RequestDigest) || !slug.MatchString(operation.ReadinessID) || !hexHash.MatchString(operation.ReleaseDigest) || (operation.RecoveryDigest != "" && !hexHash.MatchString(operation.RecoveryDigest)) || !validUpdateMode(operation.Mode) || operation.StartedAt.IsZero() || operation.UpdatedAt.Before(operation.StartedAt) || operation.PriorRelease.InstanceID != operation.InstanceID || operation.Candidate.Version == "" || len(operation.Steps) == 0 || len(operation.Steps) > 64 || len(operation.Failure) > 2048 {
		return errors.New("invalid update operation")
	}
	states := map[string]bool{"prepared": true, "draining": true, "drained": true, "stopping": true, "stopped": true, "installing": true, "installed": true, "verifying": true, "verified": true, "failed": true, "rolling-back": true, "rolled-back": true, "forward-recovering": true, "forward-recovered": true, "complete": true, "halted": true}
	if !states[operation.State] || (operation.Recovery != "" && operation.Recovery != "rollback" && operation.Recovery != "forward") {
		return errors.New("invalid update operation state")
	}
	if (operation.RecoveryRelease == nil) != (operation.RecoveryDigest == "") {
		return errors.New("invalid forward recovery identity")
	}
	return nil
}

func (s *Store) writeUpdateOperation(operation UpdateOperation) error {
	if err := validateUpdateOperation(operation); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(operation, "", "  ")
	if err != nil || len(raw) > 256<<10 {
		return errors.New("update operation exceeds its durable size limit")
	}
	return atomicFile(s.dir, updateOperationFile, raw)
}

func (s *Store) readUpdateOperation() (UpdateOperation, error) {
	var operation UpdateOperation
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, updateOperationFile), 256<<10)
	if err != nil || strictJSON(raw, &operation) != nil || validateUpdateOperation(operation) != nil || operation.InstanceID != s.InstanceID() {
		return operation, errors.New("update operation is unavailable or invalid")
	}
	return operation, nil
}

func (s *Store) UpdateOperationState() UpdateOperationInventory {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	result := UpdateOperationInventory{History: []UpdateOperation{}, Notice: "Durable local update evidence. Publisher signatures, maintenance coordination and readiness do not replace the explicit local execution request."}
	historyRoot := filepath.Join(s.dir, "update-history")
	historyInfo, historyStatErr := os.Lstat(historyRoot)
	if historyStatErr == nil && (!historyInfo.IsDir() || historyInfo.Mode().Perm()&0077 != 0) {
		result.Problem = "update history is nonprivate or not a regular directory"
	} else if entries, err := os.ReadDir(historyRoot); err == nil {
		if len(entries) > maxUpdateHistory {
			result.Problem = "update history exceeds its reviewed retention limit"
		} else {
			for _, entry := range entries {
				if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
					result.Problem = "update history contains an unexpected entry"
					continue
				}
				raw, readErr := worker.ReadPrivateFile(filepath.Join(historyRoot, entry.Name()), 256<<10)
				var operation UpdateOperation
				if readErr != nil || strictJSON(raw, &operation) != nil || validateUpdateOperation(operation) != nil || !updateTerminal(operation.State) || operation.InstanceID != s.InstanceID() {
					result.Problem = "one or more update history records require local recovery"
					continue
				}
				result.History = append(result.History, operation)
			}
			sort.Slice(result.History, func(i, j int) bool { return result.History[i].UpdatedAt.After(result.History[j].UpdatedAt) })
		}
	} else if !os.IsNotExist(err) {
		result.Problem = "update history is unavailable"
	}
	if _, err := os.Lstat(filepath.Join(s.dir, updateOperationFile)); os.IsNotExist(err) {
		return result
	}
	operation, err := s.readUpdateOperation()
	if err != nil {
		result.Problem = err.Error()
		return result
	}
	result.Operation = &operation
	return result
}

// ArchiveUpdate moves one terminal operation into bounded private history. It
// is explicit so an operator cannot silently discard a failed rollout record.
func (s *Store) ArchiveUpdate(id string) (UpdateOperationInventory, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	operation, err := s.readUpdateOperation()
	if err != nil || operation.ID != id || !updateTerminal(operation.State) {
		return UpdateOperationInventory{}, errors.New("only the exact terminal update can be archived")
	}
	root := filepath.Join(s.dir, "update-history")
	if err := worker.PrivateDir(root); err != nil {
		return UpdateOperationInventory{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) >= maxUpdateHistory {
		return UpdateOperationInventory{}, errors.New("update history is full; reviewed retention is required")
	}
	raw, err := json.MarshalIndent(operation, "", "  ")
	if err != nil {
		return UpdateOperationInventory{}, err
	}
	name := operation.ID + ".json"
	path := filepath.Join(root, name)
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		if err := atomicFile(root, name, raw); err != nil {
			return UpdateOperationInventory{}, errors.New("cannot archive update evidence")
		}
	} else if statErr != nil {
		return UpdateOperationInventory{}, errors.New("existing update history record is unavailable")
	} else if old, readErr := worker.ReadPrivateFile(path, 256<<10); readErr == nil {
		if string(old) != string(raw) {
			return UpdateOperationInventory{}, errors.New("update history ID already binds different evidence")
		}
	} else {
		return UpdateOperationInventory{}, errors.New("existing update history record is unavailable")
	}
	if err := os.Remove(filepath.Join(s.dir, updateOperationFile)); err != nil {
		return UpdateOperationInventory{}, errors.New("archived update remains active; retry local archival")
	}
	return UpdateOperationInventory{History: []UpdateOperation{operation}, Notice: "Terminal update archived locally; a new explicit readiness and execution request is still required."}, nil
}

func schemaChanged(current InstalledRelease, candidate ReleaseManifest) bool {
	return current.ConfigSchema != candidate.ConfigSchema || current.DatabaseSchema != candidate.DatabaseSchema || current.SigningCodec != candidate.SigningCodec
}

func forwardMigrationEligible(current InstalledRelease, candidate ReleaseManifest) bool {
	predecessor := false
	for _, version := range candidate.CompatibleFrom {
		predecessor = predecessor || version == current.Version
	}
	return current.Component == "validator" && candidate.Component == "validator" && candidate.Sequence > current.Sequence && predecessor && schemaChanged(current, candidate) && !candidate.MixedVersionsSafe
}

func (s *Store) BeginUpdate(req BeginUpdateRequest, now time.Time) (UpdateOperation, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if !slug.MatchString(req.ID) || !slug.MatchString(req.ReadinessID) || !hexHash.MatchString(req.ReleaseDigest) || (req.Platform != "linux-amd64" && req.Platform != "linux-arm64" && req.Platform != "darwin-arm64") || !validUpdateMode(req.Mode) {
		return UpdateOperation{}, errors.New("update requires a lowercase ID, exact readiness/release identities, supported platform and reviewed mode")
	}
	if old, err := s.readUpdateOperation(); err == nil {
		if old.ID == req.ID && old.RequestDigest == maintenanceDigest(req) {
			return old, nil
		}
		if !updateTerminal(old.State) {
			return UpdateOperation{}, errors.New("another update or recovery is still active")
		}
		return UpdateOperation{}, errors.New("archive the completed update record locally before starting another operation")
	} else if _, statErr := os.Lstat(filepath.Join(s.dir, updateOperationFile)); !os.IsNotExist(statErr) {
		return UpdateOperation{}, errors.New("existing update operation requires local recovery")
	}
	revision, _, _ := s.Summary()
	if revision != req.ExpectedRevision {
		return UpdateOperation{}, errors.New("operator revision changed; refresh before starting the update")
	}
	receipt, err := s.readUpdateReadiness(req.ReadinessID)
	if err != nil || !receipt.ActivationReady || receipt.State != "ready" || receipt.ReleaseDigest != req.ReleaseDigest || receipt.Platform != req.Platform || receipt.Revision != revision || !receipt.ExpiresAt.After(now) {
		return UpdateOperation{}, errors.New("exact unexpired activation-ready receipt required")
	}
	current, err := s.CurrentRelease()
	if err != nil {
		return UpdateOperation{}, err
	}
	staged, err := s.loadStaged(req.ReleaseDigest, req.Platform, now)
	if err != nil {
		return UpdateOperation{}, err
	}
	compatibility := EvaluateReleaseCompatibility(current, staged.Digest, staged.Release.Manifest)
	switch req.Mode {
	case "rolling":
		if !compatibility.RollingUpdate || req.ConfirmForwardOnly {
			return UpdateOperation{}, errors.New("rolling mode requires an ordinary compatible release")
		}
	case "migration":
		if compatibility.RollingUpdate || !forwardMigrationEligible(*current, staged.Release.Manifest) || !req.ConfirmForwardOnly {
			return UpdateOperation{}, errors.New("migration mode requires an incompatible schema/codec change and explicit forward-only confirmation")
		}
	case "emergency":
		if staged.Release.Manifest.Channel != "emergency" || !compatibility.RollingUpdate || req.ConfirmForwardOnly {
			return UpdateOperation{}, errors.New("emergency mode requires a signed emergency release that remains rollback-compatible")
		}
	}
	operation := UpdateOperation{
		SchemaVersion: 1, ID: req.ID, InstanceID: s.InstanceID(), RequestDigest: maintenanceDigest(req), ReadinessID: req.ReadinessID,
		ReleaseDigest: req.ReleaseDigest, Platform: req.Platform, Mode: req.Mode, State: "prepared", StartedAt: now.UTC(), UpdatedAt: now.UTC(),
		PriorRelease: *current, Candidate: staged.Release.Manifest, Steps: []UpdateStep{{At: now.UTC(), State: "prepared", Message: "Exact staged bytes, local approval, backup, participation and wave order are bound to this local request."}},
	}
	if req.Mode == "migration" {
		operation.Recovery = "forward"
	}
	if err := s.writeUpdateOperation(operation); err != nil {
		return UpdateOperation{}, err
	}
	if err := s.recordLifecycle("update prepared: "+req.ID, ""); err != nil {
		return UpdateOperation{}, err
	}
	return operation, nil
}

func (s *Store) persistUpdateIntent(operation *UpdateOperation, state, message string, now time.Time) error {
	operation.State = state
	operation.UpdatedAt = now.UTC()
	operation.Steps = append(operation.Steps, UpdateStep{At: now.UTC(), State: state, Message: message})
	return s.writeUpdateOperation(*operation)
}

func (s *Store) persistUpdateEvidence(operation *UpdateOperation, state string, evidence UpdateExecutionEvidence, now time.Time) error {
	operation.State = state
	operation.UpdatedAt = now.UTC()
	copy := evidence
	operation.Steps = append(operation.Steps, UpdateStep{At: now.UTC(), State: state, Evidence: &copy, Message: evidence.Message})
	return s.writeUpdateOperation(*operation)
}

func (s *Store) failUpdate(operation *UpdateOperation, phase string, err error, now time.Time) error {
	operation.Failure = phase + ": " + err.Error()
	operation.UpdatedAt = now.UTC()
	if phase == "drain" || phase == "stop" || phase == "staged-artifact" || phase == "install-authorization" {
		operation.State = "halted"
		operation.Recovery = ""
	} else {
		operation.State = "failed"
		if operation.Mode == "migration" {
			operation.Recovery = "forward"
		} else {
			operation.Recovery = "rollback"
		}
	}
	operation.Steps = append(operation.Steps, UpdateStep{At: now.UTC(), State: operation.State, Message: operation.Failure})
	_ = s.writeUpdateOperation(*operation)
	return errors.New("update halted: " + operation.Failure)
}

// AdvanceUpdate executes one durable phase. Every external action is preceded
// by an intent record, so interruption resumes the same idempotent phase.
func (s *Store) AdvanceUpdate(ctx context.Context, id string, driver UpdateDriver, now time.Time) (UpdateOperation, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if driver == nil {
		return UpdateOperation{}, errors.New("local update executor unavailable")
	}
	operation, err := s.readUpdateOperation()
	if err != nil || operation.ID != id {
		return UpdateOperation{}, errors.New("unknown update operation")
	}
	staged, stageErr := s.loadStaged(operation.ReleaseDigest, operation.Platform, now)
	if stageErr != nil && operation.State != "installed" && operation.State != "verifying" && operation.State != "verified" {
		return operation, s.failUpdate(&operation, "staged-artifact", stageErr, now)
	}
	var evidence UpdateExecutionEvidence
	switch operation.State {
	case "prepared", "draining":
		if operation.State == "prepared" {
			if err := s.persistUpdateIntent(&operation, "draining", "Drain and reconcile every retained operation before stopping.", now); err != nil {
				return operation, err
			}
		}
		evidence, err = driver.Drain(ctx, operation)
		if err != nil || validateUpdateEvidence(evidence, "drain") != nil || evidence.ArtifactSHA256 != operation.PriorRelease.ArtifactSHA256 || evidence.RegistrationDigest != operation.PriorRelease.RegistrationDigest {
			if err == nil {
				err = errors.New("invalid drain evidence")
			}
			return operation, s.failUpdate(&operation, "drain", err, now)
		}
		err = s.persistUpdateEvidence(&operation, "drained", evidence, now)
	case "drained", "stopping":
		if operation.State == "drained" {
			if err := s.persistUpdateIntent(&operation, "stopping", "Fence and stop the exact selected worker.", now); err != nil {
				return operation, err
			}
		}
		evidence, err = driver.Stop(ctx, operation)
		if err != nil || validateUpdateEvidence(evidence, "stop") != nil || evidence.ArtifactSHA256 != operation.PriorRelease.ArtifactSHA256 || evidence.RegistrationDigest != operation.PriorRelease.RegistrationDigest {
			if err == nil {
				err = errors.New("invalid stop evidence")
			}
			return operation, s.failUpdate(&operation, "stop", err, now)
		}
		err = s.persistUpdateEvidence(&operation, "stopped", evidence, now)
	case "stopped", "installing":
		if operation.State == "stopped" {
			if err := s.persistUpdateIntent(&operation, "installing", "Install only the exact locally staged candidate.", now); err != nil {
				return operation, err
			}
		}
		trust, trustErr := s.ReleaseTrust()
		verified, verifyErr := VerifyRelease(staged.Release, trust, now)
		if trustErr != nil || verifyErr != nil {
			return operation, s.failUpdate(&operation, "install-authorization", errors.New("current publisher policy no longer verifies the staged release"), now)
		}
		if _, approvalErr := activeReleaseApproval(s.ReleaseApprovals(), verified, s.InstanceID(), now); approvalErr != nil {
			return operation, s.failUpdate(&operation, "install-authorization", errors.New("current local release approval is absent, revoked or expired"), now)
		}
		evidence, err = driver.Install(ctx, operation, staged)
		if err != nil || validateUpdateEvidence(evidence, "install") != nil || evidence.ArtifactSHA256 != staged.Artifact.SHA256 {
			if err == nil {
				err = errors.New("invalid install evidence")
			}
			return operation, s.failUpdate(&operation, "install", err, now)
		}
		err = s.persistUpdateEvidence(&operation, "installed", evidence, now)
	case "installed", "forward-recovered", "verifying":
		if operation.State == "installed" || operation.State == "forward-recovered" {
			if err := s.persistUpdateIntent(&operation, "verifying", "Verify artifact, registration, identities, networks, checkpoints and fencing after installation.", now); err != nil {
				return operation, err
			}
		}
		evidence, err = driver.Verify(ctx, operation)
		if err != nil || validateUpdateEvidence(evidence, "verify") != nil || evidence.ArtifactSHA256 != operation.CandidateArtifactSHA256() || evidence.RegistrationDigest == "" {
			if err == nil {
				err = errors.New("invalid post-install verification evidence")
			}
			return operation, s.failUpdate(&operation, "verify", err, now)
		}
		err = s.persistUpdateEvidence(&operation, "verified", evidence, now)
	case "verified", "complete", "failed", "halted", "rolled-back":
		return operation, nil
	default:
		return operation, errors.New("update operation requires its explicit recovery command")
	}
	if err != nil {
		return operation, err
	}
	return operation, nil
}

func (s *Store) RollbackUpdate(ctx context.Context, id string, driver UpdateDriver, now time.Time) (UpdateOperation, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	operation, err := s.readUpdateOperation()
	if err != nil || operation.ID != id || driver == nil || (operation.State != "failed" && operation.State != "rolling-back") || operation.Recovery != "rollback" {
		return operation, errors.New("update is not eligible for compatible rollback")
	}
	if operation.State == "failed" {
		if err := s.persistUpdateIntent(&operation, "rolling-back", "Restore the exact prior artifact while preserving and rechecking durable state.", now); err != nil {
			return operation, err
		}
	}
	evidence, err := driver.Rollback(ctx, operation)
	if err != nil || validateUpdateEvidence(evidence, "rollback") != nil || evidence.ArtifactSHA256 != operation.PriorRelease.ArtifactSHA256 {
		if err == nil {
			err = errors.New("invalid rollback evidence")
		}
		return operation, s.failUpdate(&operation, "rollback", err, now)
	}
	operation.Recovery = ""
	operation.Failure = ""
	if err := s.persistUpdateEvidence(&operation, "rolled-back", evidence, now); err != nil {
		return operation, err
	}
	return operation, nil
}

func (s *Store) ForwardRecoverUpdate(ctx context.Context, id string, req ForwardRecoveryRequest, driver UpdateDriver, now time.Time) (UpdateOperation, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	operation, err := s.readUpdateOperation()
	if err != nil || operation.ID != id || driver == nil || (operation.State != "failed" && operation.State != "forward-recovering") || operation.Recovery != "forward" {
		return operation, errors.New("update is not eligible for forward recovery")
	}
	staged, err := s.loadStaged(req.ReleaseDigest, req.Platform, now)
	if err != nil || req.Platform != operation.Platform {
		return operation, errors.New("exact staged forward-recovery artifact required")
	}
	manifest := staged.Release.Manifest
	predecessor := false
	for _, version := range manifest.CompatibleFrom {
		predecessor = predecessor || version == operation.Candidate.Version
	}
	if manifest.Component != "validator" || manifest.Sequence <= operation.Candidate.Sequence || !predecessor || manifest.ConfigSchema != operation.Candidate.ConfigSchema || manifest.DatabaseSchema != operation.Candidate.DatabaseSchema || manifest.SigningCodec != operation.Candidate.SigningCodec {
		return operation, errors.New("forward recovery must continue the failed migrated schema and codec at a newer sequence")
	}
	trust, trustErr := s.ReleaseTrust()
	verified, verifyErr := VerifyRelease(staged.Release, trust, now)
	if trustErr != nil || verifyErr != nil {
		return operation, errors.New("forward-recovery release verification failed")
	}
	if _, approvalErr := activeReleaseApproval(s.ReleaseApprovals(), verified, s.InstanceID(), now); approvalErr != nil {
		return operation, errors.New("forward-recovery release lacks current local approval")
	}
	if candidate := s.candidateResult(staged.Digest, staged.Platform, staged.Artifact.SHA256); candidate == nil || candidate.Report.State != "checks-passed" {
		return operation, errors.New("forward-recovery artifact lacks the isolated candidate report")
	}
	if operation.State == "failed" {
		if operation.RecoveryRelease == nil {
			operation.RecoveryRelease = &manifest
			operation.RecoveryDigest = staged.Digest
		} else if operation.RecoveryDigest != staged.Digest || operation.RecoveryRelease.Version != manifest.Version {
			return operation, errors.New("forward recovery retry must use the exact journaled release")
		}
		if err := s.persistUpdateIntent(&operation, "forward-recovering", "Install a newer tested release that supports the already migrated schema; rollback remains fenced.", now); err != nil {
			return operation, err
		}
	} else if operation.RecoveryRelease == nil || operation.RecoveryDigest != staged.Digest || operation.RecoveryRelease.Version != manifest.Version {
		return operation, errors.New("forward recovery retry must use the exact journaled release")
	}
	evidence, err := driver.ForwardRecover(ctx, operation, staged)
	if err != nil || validateUpdateEvidence(evidence, "forward-recover") != nil || evidence.ArtifactSHA256 != staged.Artifact.SHA256 {
		if err == nil {
			err = errors.New("invalid forward-recovery evidence")
		}
		return operation, s.failUpdate(&operation, "forward-recovery", err, now)
	}
	operation.Recovery = ""
	operation.Failure = ""
	operation.ReleaseDigest = staged.Digest
	operation.Candidate = manifest
	if err := s.persistUpdateEvidence(&operation, "forward-recovered", evidence, now); err != nil {
		return operation, err
	}
	return operation, nil
}

func (s *Store) ConfirmUpdateProgress(id, progressID string, now time.Time) (UpdateOperation, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	operation, err := s.readUpdateOperation()
	if err != nil || operation.ID != id || operation.State != "verified" || !slug.MatchString(progressID) {
		return operation, errors.New("verified update and valid progress receipt ID required")
	}
	progress, err := s.readProgressReceipt(progressID)
	if err != nil || progress.Final == nil || progress.Evaluation.State != "recorded-progress" || !progress.Evaluation.BothDirectionsRecorded || !progress.Evaluation.BothLocalSignaturesChanged || progress.Final.SampledAt.Before(operation.UpdatedAt) {
		return operation, errors.New("fresh two-direction post-update signing progress is required")
	}
	current, err := s.CurrentRelease()
	if err != nil || current.Digest != operation.ReleaseDigest || current.ArtifactSHA256 != operation.CandidateArtifactSHA256() {
		return operation, errors.New("installed release changed before update completion")
	}
	operation.ProgressID = progressID
	operation.State = "complete"
	operation.UpdatedAt = now.UTC()
	operation.Steps = append(operation.Steps, UpdateStep{At: now.UTC(), State: "complete", Message: "Fresh two-direction signing progress completed the local update wave."})
	if err := s.writeUpdateOperation(operation); err != nil {
		return operation, err
	}
	return operation, nil
}

func (o UpdateOperation) CandidateArtifactSHA256() string {
	for i := len(o.Steps) - 1; i >= 0; i-- {
		step := o.Steps[i]
		if step.Evidence != nil && (step.Evidence.Action == "install" || step.Evidence.Action == "forward-recover") {
			return step.Evidence.ArtifactSHA256
		}
	}
	return ""
}
