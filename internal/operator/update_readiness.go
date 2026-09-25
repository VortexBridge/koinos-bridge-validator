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

const maxUpdateReadinessReceipts = 64

var requiredUpdateReadinessChecks = []string{"current-release", "staged-artifact", "compatibility", "candidate-test", "local-approval", "worker-observation", "encrypted-backup", "maintenance-reservation", "authenticated-participation", "signing-quorum", "prior-wave", "installer"}

type UpdateReadinessRequest struct {
	ID                     string                           `json:"id"`
	ExpectedRevision       uint64                           `json:"expectedRevision"`
	ReleaseDigest          string                           `json:"releaseDigest"`
	Platform               string                           `json:"platform"`
	BackupID               string                           `json:"backupId"`
	ParticipationResponses []SignedParticipationObservation `json:"participationResponses"`
	PriorWaveResult        *SignedWaveResult                `json:"priorWaveResult,omitempty"`
}

type UpdateReadinessCheck struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Message string `json:"message"`
}

type UpdateReadinessReceipt struct {
	SchemaVersion    int                    `json:"schemaVersion"`
	ID               string                 `json:"id"`
	InstanceID       string                 `json:"instanceId"`
	RequestDigest    string                 `json:"requestDigest"`
	Revision         uint64                 `json:"revision"`
	ReleaseDigest    string                 `json:"releaseDigest"`
	Platform         string                 `json:"platform"`
	CurrentVersion   string                 `json:"currentVersion,omitempty"`
	CandidateVersion string                 `json:"candidateVersion,omitempty"`
	BackupID         string                 `json:"backupId,omitempty"`
	CheckedAt        time.Time              `json:"checkedAt"`
	ExpiresAt        time.Time              `json:"expiresAt"`
	State            string                 `json:"state"`
	ActivationReady  bool                   `json:"activationReady"`
	Checks           []UpdateReadinessCheck `json:"checks"`
	Notice           string                 `json:"notice"`
}

type UpdateReadinessInventory struct {
	Receipts []UpdateReadinessReceipt `json:"receipts"`
	Problem  string                   `json:"problem,omitempty"`
	Notice   string                   `json:"notice"`
}

func updateCheck(id, state, message string) UpdateReadinessCheck {
	return UpdateReadinessCheck{ID: id, State: state, Message: message}
}

func updateReceiptPath(s *Store, id string) string {
	return filepath.Join(s.dir, "update-readiness", id+".json")
}

func validateUpdateReadinessReceipt(receipt UpdateReadinessReceipt) error {
	if receipt.SchemaVersion != 1 || !slug.MatchString(receipt.ID) || !slug.MatchString(receipt.InstanceID) || !hexHash.MatchString(receipt.RequestDigest) || !hexHash.MatchString(receipt.ReleaseDigest) || receipt.CheckedAt.IsZero() || !receipt.ExpiresAt.After(receipt.CheckedAt) || (receipt.State != "blocked" && receipt.State != "ready") || receipt.ActivationReady != (receipt.State == "ready") || len(receipt.Checks) == 0 || len(receipt.Checks) > 32 || len(receipt.Notice) == 0 || len(receipt.Notice) > 2048 {
		return errors.New("invalid update readiness receipt")
	}
	if receipt.Platform != "linux-amd64" && receipt.Platform != "linux-arm64" && receipt.Platform != "darwin-arm64" {
		return errors.New("invalid update readiness platform")
	}
	seen := map[string]bool{}
	allPassed := true
	for _, check := range receipt.Checks {
		if !slug.MatchString(check.ID) || seen[check.ID] || (check.State != "passed" && check.State != "blocked" && check.State != "unknown") || len(check.Message) == 0 || len(check.Message) > 2048 {
			return errors.New("invalid update readiness check")
		}
		seen[check.ID] = true
		allPassed = allPassed && check.State == "passed"
	}
	if len(seen) != len(requiredUpdateReadinessChecks) {
		return errors.New("update readiness receipt has an incomplete check set")
	}
	for _, id := range requiredUpdateReadinessChecks {
		if !seen[id] {
			return errors.New("update readiness receipt is missing a required check")
		}
	}
	if receipt.ActivationReady != allPassed {
		return errors.New("update readiness state contradicts its checks")
	}
	return nil
}

func (s *Store) readUpdateReadiness(id string) (UpdateReadinessReceipt, error) {
	if !slug.MatchString(id) {
		return UpdateReadinessReceipt{}, errors.New("invalid update readiness ID")
	}
	raw, err := worker.ReadPrivateFile(updateReceiptPath(s, id), 128<<10)
	if err != nil {
		return UpdateReadinessReceipt{}, errors.New("update readiness receipt unavailable")
	}
	var receipt UpdateReadinessReceipt
	if strictJSON(raw, &receipt) != nil || validateUpdateReadinessReceipt(receipt) != nil || receipt.ID != id || receipt.InstanceID != s.InstanceID() {
		return receipt, errors.New("update readiness receipt is invalid")
	}
	return receipt, nil
}

func (s *Store) UpdateReadinessInventory() UpdateReadinessInventory {
	s.readinessMu.Lock()
	defer s.readinessMu.Unlock()
	result := UpdateReadinessInventory{Receipts: []UpdateReadinessReceipt{}, Notice: "Historical point-in-time checks only. Expired receipts and passed individual checks never authorize installation."}
	root := filepath.Join(s.dir, "update-readiness")
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return result
	}
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		result.Problem = "update readiness history is unavailable, nonprivate or a symlink"
		return result
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > maxUpdateReadinessReceipts {
		result.Problem = "update readiness history is unavailable or exceeds 64 receipts"
		return result
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".json" {
			result.Problem = "update readiness history contains an unexpected entry"
			continue
		}
		receipt, err := s.readUpdateReadiness(name[:len(name)-len(".json")])
		if err == nil {
			result.Receipts = append(result.Receipts, receipt)
		} else {
			result.Problem = "one or more update readiness receipts require local recovery"
		}
	}
	sort.Slice(result.Receipts, func(i, j int) bool { return result.Receipts[i].CheckedAt.After(result.Receipts[j].CheckedAt) })
	return result
}

func (s *Store) UpdateReadinessReceipts() []UpdateReadinessReceipt {
	return s.UpdateReadinessInventory().Receipts
}

func activeReleaseApproval(approvals []ReleaseApproval, verified ReleaseVerification, instanceID string, now time.Time) (ReleaseApproval, error) {
	for i := len(approvals) - 1; i >= 0; i-- {
		approval := approvals[i]
		if approval.Digest == verified.Digest && approval.Component == verified.Manifest.Component && approval.Sequence == verified.Manifest.Sequence {
			if err := CheckActivation(approval, verified, instanceID, now); err != nil {
				return approval, err
			}
			return approval, nil
		}
	}
	return ReleaseApproval{}, errors.New("no matching active local approval")
}

func findManagedBackup(inventory BackupInventory, id string) (*ManagedBackup, error) {
	if id == "" {
		return nil, errors.New("select a completed encrypted backup")
	}
	for i := range inventory.Jobs {
		if inventory.Jobs[i].Request.ID == id {
			return &inventory.Jobs[i], nil
		}
	}
	return nil, errors.New("selected backup is absent from this operator")
}

func (s *Store) CheckUpdateReadiness(ctx context.Context, req UpdateReadinessRequest, now time.Time) (UpdateReadinessReceipt, error) {
	s.readinessMu.Lock()
	defer s.readinessMu.Unlock()
	if !slug.MatchString(req.ID) || !hexHash.MatchString(req.ReleaseDigest) || (req.Platform != "linux-amd64" && req.Platform != "linux-arm64" && req.Platform != "darwin-arm64") || (req.BackupID != "" && !slug.MatchString(req.BackupID)) || len(req.ParticipationResponses) > 32 {
		return UpdateReadinessReceipt{}, errors.New("readiness requires a lowercase ID, exact release digest, supported validator platform and optional valid backup ID")
	}
	requestDigest := maintenanceDigest(req)
	if _, err := os.Lstat(updateReceiptPath(s, req.ID)); !os.IsNotExist(err) {
		old, readErr := s.readUpdateReadiness(req.ID)
		if readErr != nil {
			return UpdateReadinessReceipt{}, readErr
		}
		if old.RequestDigest != requestDigest {
			return UpdateReadinessReceipt{}, errors.New("readiness ID already binds different evidence")
		}
		return old, nil
	}
	revision, _, _ := s.Summary()
	if req.ExpectedRevision != revision {
		return UpdateReadinessReceipt{}, errors.New("operator revision changed; refresh before checking update readiness")
	}
	receipt := UpdateReadinessReceipt{
		SchemaVersion: 1, ID: req.ID, InstanceID: s.InstanceID(), RequestDigest: requestDigest,
		Revision: revision, ReleaseDigest: req.ReleaseDigest, Platform: req.Platform, BackupID: req.BackupID,
		CheckedAt: now, ExpiresAt: now.Add(30 * time.Second), State: "blocked", ActivationReady: false,
		Checks: []UpdateReadinessCheck{},
		Notice: "Point-in-time local evidence only. Installation still requires the exact retained receipt and a separate explicit local execution request before it expires.",
	}

	current, currentErr := s.CurrentRelease()
	if currentErr != nil {
		receipt.Checks = append(receipt.Checks, updateCheck("current-release", "blocked", currentErr.Error()))
	} else {
		receipt.CurrentVersion = current.Version
		receipt.Checks = append(receipt.Checks, updateCheck("current-release", "passed", "The current release still matches the pinned worker, registration and configuration."))
	}

	staged, stagedErr := s.loadStaged(req.ReleaseDigest, req.Platform, now)
	var verified ReleaseVerification
	if stagedErr != nil {
		receipt.Checks = append(receipt.Checks, updateCheck("staged-artifact", "blocked", stagedErr.Error()))
	} else {
		trust, trustErr := s.ReleaseTrust()
		if trustErr == nil {
			verified, trustErr = VerifyRelease(staged.Release, trust, now)
		}
		if trustErr != nil || verified.Digest != req.ReleaseDigest {
			receipt.Checks = append(receipt.Checks, updateCheck("staged-artifact", "blocked", "The staged release failed current publisher, freshness or digest verification."))
			stagedErr = errors.New("staged release verification failed")
		} else {
			receipt.CandidateVersion = staged.Release.Manifest.Version
			receipt.Checks = append(receipt.Checks, updateCheck("staged-artifact", "passed", "Signed metadata and the exact staged artifact bytes were reverified."))
		}
	}

	if current == nil || stagedErr != nil {
		receipt.Checks = append(receipt.Checks, updateCheck("compatibility", "blocked", "Current and candidate release identities are both required."))
	} else {
		compatibility := EvaluateReleaseCompatibility(current, req.ReleaseDigest, staged.Release.Manifest)
		if compatibility.RollingUpdate {
			receipt.Checks = append(receipt.Checks, updateCheck("compatibility", "passed", compatibility.Reasons[0]))
		} else if forwardMigrationEligible(*current, staged.Release.Manifest) {
			receipt.Checks = append(receipt.Checks, updateCheck("compatibility", "passed", "The candidate is a declared forward-only validator migration from the exact current version. Starting it still requires explicit migration mode and forward-only confirmation."))
		} else {
			receipt.Checks = append(receipt.Checks, updateCheck("compatibility", "blocked", compatibility.Reasons[0]))
		}
	}

	if stagedErr != nil {
		receipt.Checks = append(receipt.Checks, updateCheck("candidate-test", "blocked", "A verified staged candidate is required."))
	} else if candidate := s.candidateResult(req.ReleaseDigest, req.Platform, staged.Artifact.SHA256); candidate == nil || candidate.StartedAt.IsZero() || candidate.FinishedAt.IsZero() || candidate.FinishedAt.After(now) || candidate.Report.SchemaVersion != 2 || candidate.Report.Scope != "isolated-observation-transfer-v2" || candidate.Report.State != "checks-passed" {
		receipt.Checks = append(receipt.Checks, updateCheck("candidate-test", "blocked", "Run the current isolated observation-transfer candidate suite for this exact artifact."))
	} else {
		receipt.Checks = append(receipt.Checks, updateCheck("candidate-test", "passed", "The exact artifact has a current eight-check isolated observation-transfer report."))
	}

	var approval ReleaseApproval
	if stagedErr != nil {
		receipt.Checks = append(receipt.Checks, updateCheck("local-approval", "blocked", "A verified release is required before local approval can be checked."))
	} else {
		var approvalErr error
		approval, approvalErr = activeReleaseApproval(s.ReleaseApprovals(), verified, s.InstanceID(), now)
		if approvalErr != nil {
			receipt.Checks = append(receipt.Checks, updateCheck("local-approval", "blocked", approvalErr.Error()))
		} else {
			receipt.Checks = append(receipt.Checks, updateCheck("local-approval", "passed", "The exact release is locally approved inside its current activation window."))
			if approval.WindowEnd.Before(receipt.ExpiresAt) {
				receipt.ExpiresAt = approval.WindowEnd
			}
		}
	}

	s.workerMu.Lock()
	snapshot, workerErr := s.captureProgress(ctx)
	s.workerMu.Unlock()
	if workerErr != nil {
		receipt.Checks = append(receipt.Checks, updateCheck("worker-observation", "blocked", workerErr.Error()))
	} else if current == nil || snapshot.Worker.RegistrationDigest != current.RegistrationDigest {
		receipt.Checks = append(receipt.Checks, updateCheck("worker-observation", "blocked", "Fresh worker evidence does not match the recorded current release."))
	} else {
		receipt.Checks = append(receipt.Checks, updateCheck("worker-observation", "passed", "The current worker has fresh bound observations on both chains."))
	}

	inventory := s.ManagedBackups()
	backup, backupErr := findManagedBackup(inventory, req.BackupID)
	if backupErr == nil && inventory.Problem != "" {
		backupErr = errors.New("backup inventory has unresolved local errors")
	}
	if backupErr == nil && current != nil && backup.Request.RegistrationDigest != current.RegistrationDigest {
		backupErr = errors.New("selected backup belongs to another worker registration")
	}
	if backupErr == nil && backup.State != "complete" {
		backupErr = errors.New("selected backup has no completed receipt")
	}
	if backupErr == nil && backup.RecoveryRecipient == "" {
		backupErr = errors.New("selected backup predates recovery-recipient provenance")
	}
	if backupErr == nil && approval.ApprovedAt.IsZero() {
		backupErr = errors.New("matching local approval is required before backup timing can be accepted")
	}
	if backupErr == nil && backup.FinishedAt.Before(approval.ApprovedAt) {
		backupErr = errors.New("selected backup predates local approval of this release")
	}
	if backupErr == nil {
		verification, verifyErr := s.VerifyManagedBackup(req.BackupID)
		if verifyErr != nil || verification.State != "intact" {
			backupErr = errors.New("selected encrypted backup is damaged, missing or unverifiable")
		}
	}
	if backupErr != nil {
		receipt.Checks = append(receipt.Checks, updateCheck("encrypted-backup", "blocked", backupErr.Error()))
	} else {
		receipt.Checks = append(receipt.Checks, updateCheck("encrypted-backup", "passed", "The selected post-approval backup receipt matches intact ciphertext; restore and reconciliation remain separate evidence."))
	}

	participation, participationErr := s.CheckParticipation(ctx, req.ParticipationResponses, now)
	if participationErr != nil {
		receipt.Checks = append(receipt.Checks, updateCheck("maintenance-reservation", "blocked", participationErr.Error()))
		receipt.Checks = append(receipt.Checks, updateCheck("authenticated-participation", "blocked", "Fresh authenticated responses from the reserved maintenance plan are required."))
		receipt.Checks = append(receipt.Checks, updateCheck("signing-quorum", "blocked", "Signing participation and every route-stage threshold remain unverified."))
		receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "unknown", "The local maintenance wave and any preceding result cannot be evaluated."))
	} else {
		receipt.Checks = append(receipt.Checks, updateCheck("maintenance-reservation", "passed", "The participation request is bound to a fully endorsed, locally retained maintenance reservation."))
		if participation.ExpiresAt.Before(receipt.ExpiresAt) {
			receipt.ExpiresAt = participation.ExpiresAt
		}
		if participation.AllResponded {
			receipt.Checks = append(receipt.Checks, updateCheck("authenticated-participation", "passed", "Every configured maintenance member returned a fresh authenticated worker observation."))
		} else {
			receipt.Checks = append(receipt.Checks, updateCheck("authenticated-participation", "blocked", "One or more configured maintenance members did not return a fresh response."))
		}
		if participation.ActivationReady {
			receipt.Checks = append(receipt.Checks, updateCheck("signing-quorum", "passed", "Fresh verified signing participation satisfies every applicable route stage."))
		} else if participation.ContractMembershipThresholdsMet {
			receipt.Checks = append(receipt.Checks, updateCheck("signing-quorum", "blocked", "Non-updating operators proved enough locally mapped bridge keys and finalized contract membership for both contract stages, but productive signing and peer/API/frontend thresholds remain unverified."))
		} else if participation.ContractKeyThresholdsMet {
			receipt.Checks = append(receipt.Checks, updateCheck("signing-quorum", "blocked", "Non-updating operators proved enough locally mapped bridge keys, but current contract membership, finality or deployed-code provenance remains unknown, mismatched or below a required threshold on at least one route."))
		} else {
			receipt.Checks = append(receipt.Checks, updateCheck("signing-quorum", "blocked", "Authenticated responses do not prove enough locally mapped bridge keys for both contract stages; all external route stages also remain unverified."))
		}
		request, readErr := s.readLocalParticipation()
		policy, policyErr := s.MaintenancePolicy(now)
		wave := -1
		if readErr == nil && policyErr == nil {
			for i, window := range request.Envelope.Plan.Windows {
				if window.InstanceID == s.InstanceID() {
					wave = i
				}
			}
		}
		if readErr != nil || policyErr != nil {
			receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "blocked", "The local maintenance plan or policy is unavailable for prior-wave verification."))
		} else if wave == 0 && req.PriorWaveResult == nil {
			receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "passed", "This operator is the first scheduled wave; no preceding update receipt is required."))
		} else if wave == 0 {
			receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "blocked", "The first scheduled wave must not rely on an unrelated prior-wave result."))
		} else if wave > 0 {
			if req.PriorWaveResult == nil {
				receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "blocked", "Import the signed result from the immediately preceding maintenance wave."))
			} else if verifiedWave, err := VerifyWaveResult(*req.PriorWaveResult, request.Envelope, policy, now); err != nil {
				receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "blocked", err.Error()))
			} else if verifiedWave.Wave != wave-1 || verifiedWave.InstanceID != request.Envelope.Plan.Windows[wave-1].InstanceID {
				receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "blocked", "The signed result is not from the immediately preceding maintenance wave."))
			} else {
				receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "passed", "The immediately preceding operator signed installed-release and two-direction signing-progress evidence for this plan."))
			}
		} else {
			receipt.Checks = append(receipt.Checks, updateCheck("prior-wave", "blocked", "This operator has no matching maintenance window."))
		}
	}
	receipt.Checks = append(receipt.Checks, updateCheck("installer", "passed", "The durable local install, verification and recovery state machine is available; this check does not start it."))

	allPassed := true
	for _, check := range receipt.Checks {
		allPassed = allPassed && check.State == "passed"
	}
	if allPassed {
		receipt.State = "ready"
		receipt.ActivationReady = true
		receipt.Notice = "Every configured point-in-time gate passed. Starting installation still requires a separate explicit local request bound to this exact unexpired receipt; publisher or coordinator evidence alone cannot start it."
	}

	if !receipt.ExpiresAt.After(receipt.CheckedAt) {
		return UpdateReadinessReceipt{}, errors.New("readiness evidence expired before the receipt could be recorded")
	}
	latestRevision, _, _ := s.Summary()
	if latestRevision != revision {
		return UpdateReadinessReceipt{}, errors.New("operator revision changed during readiness checks; collect fresh evidence")
	}
	if err := validateUpdateReadinessReceipt(receipt); err != nil {
		return UpdateReadinessReceipt{}, err
	}
	root := filepath.Join(s.dir, "update-readiness")
	if err := worker.PrivateDir(root); err != nil {
		return UpdateReadinessReceipt{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) >= maxUpdateReadinessReceipts {
		return UpdateReadinessReceipt{}, errors.New("update readiness history is full; reviewed retention is required")
	}
	raw, _ := json.Marshal(receipt)
	if err := atomicFile(root, req.ID+".json", raw); err != nil {
		return UpdateReadinessReceipt{}, errors.New("cannot persist update readiness receipt")
	}
	return receipt, nil
}
