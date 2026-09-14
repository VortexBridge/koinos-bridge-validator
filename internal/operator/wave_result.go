package operator

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

const maxWaveResults = 64

// Wave results use maintenance identities. They authenticate an operator's
// retained local evidence; they are not remote attestation or bridge signatures.
type WaveResultClaim struct {
	SchemaVersion int              `json:"schemaVersion"`
	ID            string           `json:"id"`
	RequestDigest string           `json:"requestDigest"`
	InstanceID    string           `json:"instanceId"`
	PlanDigest    string           `json:"planDigest"`
	PolicyDigest  string           `json:"policyDigest"`
	Wave          int              `json:"wave"`
	Release       InstalledRelease `json:"release"`
	Progress      ProgressWindow   `json:"progress"`
	RecordedAt    time.Time        `json:"recordedAt"`
	State         string           `json:"state"`
	Notice        string           `json:"notice"`
}

type SignedWaveResult struct {
	Claim     WaveResultClaim `json:"claim"`
	Signature string          `json:"signature"`
}

type RecordWaveResultRequest struct {
	ID               string              `json:"id"`
	ExpectedRevision uint64              `json:"expectedRevision"`
	Envelope         MaintenanceEnvelope `json:"envelope"`
	ProgressID       string              `json:"progressId"`
}

type WaveResultVerification struct {
	Digest        string `json:"digest"`
	InstanceID    string `json:"instanceId"`
	Wave          int    `json:"wave"`
	ReleaseDigest string `json:"releaseDigest"`
	ProgressID    string `json:"progressId"`
	State         string `json:"state"`
	Notice        string `json:"notice"`
}

type WaveResultInventory struct {
	Results []SignedWaveResult `json:"results"`
	Problem string             `json:"problem,omitempty"`
	Notice  string             `json:"notice"`
}

func ReadSignedWaveResult(path string) (SignedWaveResult, error) {
	var result SignedWaveResult
	raw, err := worker.ReadPrivateFile(path, 64<<10)
	if err != nil || strictJSON(raw, &result) != nil || validateWaveResultClaim(result.Claim) != nil {
		return result, errors.New("wave result must be a private bounded JSON file with valid evidence fields")
	}
	signature, err := hex.DecodeString(result.Signature)
	if err != nil || result.Signature != hex.EncodeToString(signature) || len(signature) != ed25519.SignatureSize {
		return result, errors.New("wave result file has an invalid signature encoding")
	}
	return result, nil
}

type waveResultRequestIdentity struct {
	ID         string `json:"id"`
	PlanDigest string `json:"planDigest"`
	ProgressID string `json:"progressId"`
}

func CanonicalWaveResult(claim WaveResultClaim) []byte {
	raw, _ := json.Marshal(claim)
	return append([]byte("VORTEX-MAINTENANCE-WAVE-RESULT-V1\n"), raw...)
}

func waveResultRequestDigest(req RecordWaveResultRequest) string {
	return maintenanceDigest(waveResultRequestIdentity{req.ID, maintenanceDigest(req.Envelope.Plan), req.ProgressID})
}

func validateWaveResultClaim(claim WaveResultClaim) error {
	if claim.SchemaVersion != 1 || !slug.MatchString(claim.ID) || !hexHash.MatchString(claim.RequestDigest) || !slug.MatchString(claim.InstanceID) || !hexHash.MatchString(claim.PlanDigest) || !hexHash.MatchString(claim.PolicyDigest) || claim.Wave < 0 || claim.Wave > 31 || claim.RecordedAt.IsZero() || claim.State != "reported-progress" || len(claim.Notice) == 0 || len(claim.Notice) > 2048 {
		return errors.New("invalid maintenance wave result claim")
	}
	if validateInstalledRelease(claim.Release) != nil || claim.Release.State != "installed" || claim.Release.InstanceID != claim.InstanceID || claim.Progress.InstanceID != claim.InstanceID || !validProgressReceipt(claim.Progress) || claim.Progress.Final == nil || claim.Progress.Evaluation.State != "recorded-progress" || !claim.Progress.Evaluation.BothDirectionsRecorded || !claim.Progress.Evaluation.BothLocalSignaturesChanged {
		return errors.New("wave result lacks an installed release and completed signing progress")
	}
	progress := claim.Progress
	if progress.SchemaVersion != 1 || !slug.MatchString(progress.ID) || progress.MinimumSeconds < 30 || progress.MinimumSeconds > 86400 || !progress.EarliestFinish.Equal(progress.Baseline.SampledAt.Add(time.Duration(progress.MinimumSeconds)*time.Second)) || !progress.ExpiresAt.Equal(progress.EarliestFinish.Add(5*time.Minute)) {
		return errors.New("wave result progress receipt metadata is invalid")
	}
	expectedRequest := maintenanceDigest(waveResultRequestIdentity{claim.ID, claim.PlanDigest, progress.ID})
	if claim.RequestDigest != expectedRequest {
		return errors.New("wave result request binding is invalid")
	}
	return nil
}

func maintenanceWave(envelope MaintenanceEnvelope, instanceID string) (int, MaintenanceWindow, error) {
	for i, window := range envelope.Plan.Windows {
		if window.InstanceID == instanceID {
			return i, window, nil
		}
	}
	return -1, MaintenanceWindow{}, errors.New("operator has no maintenance wave")
}

func waveResultRouteMatches(claim WaveResultClaim, policy MaintenancePolicy) bool {
	binding := claim.Progress.Baseline.Worker.Health.NetworkBinding
	matched := false
	for _, route := range policy.Routes {
		participates := false
		for _, stage := range route.Stages {
			for _, id := range stage.Participants {
				if id == claim.InstanceID {
					participates = true
				}
			}
		}
		if !participates {
			continue
		}
		if binding.EVMNetworkID != route.EVM.NetworkID || binding.KoinosNetworkID != route.Koinos.NetworkID || !strings.EqualFold(binding.EVMContract, route.EVM.Contract) || binding.KoinosContract != route.Koinos.Contract {
			return false
		}
		matched = true
	}
	return matched
}

func VerifyWaveResult(signed SignedWaveResult, envelope MaintenanceEnvelope, policy MaintenancePolicy, now time.Time) (WaveResultVerification, error) {
	verifiedPlan, err := VerifyMaintenance(envelope, policy, now)
	if err != nil || verifiedPlan.State != "reserved" {
		return WaveResultVerification{}, errors.New("wave result requires the same valid fully endorsed maintenance plan")
	}
	claim := signed.Claim
	if err := validateWaveResultClaim(claim); err != nil {
		return WaveResultVerification{}, err
	}
	wave, window, err := maintenanceWave(envelope, claim.InstanceID)
	if err != nil || claim.Wave != wave || claim.PlanDigest != verifiedPlan.Digest || claim.PolicyDigest != MaintenancePolicyDigest(policy) || claim.Release.Digest != window.ReleaseDigest {
		return WaveResultVerification{}, errors.New("wave result belongs to another plan, policy, wave or release")
	}
	progress := claim.Progress
	if progress.Baseline.Worker.Health.Mode != "signing" || progress.Final.Worker.Health.Mode != "signing" || progress.Baseline.Worker.RegistrationDigest != claim.Release.RegistrationDigest || progress.Baseline.Worker.BinarySHA256 != claim.Release.ArtifactSHA256 || progress.Baseline.Worker.ConfigSHA256 != claim.Release.RegisteredConfigSHA256 {
		return WaveResultVerification{}, errors.New("wave result does not bind a signing worker to the installed release")
	}
	if claim.Release.RecordedAt.Before(window.Start) || claim.Release.RecordedAt.After(progress.Baseline.SampledAt) || progress.Baseline.SampledAt.Before(window.Start) || progress.Final.SampledAt.After(window.End) || claim.RecordedAt.Before(progress.Final.SampledAt) || claim.RecordedAt.After(window.End) || claim.RecordedAt.After(now) {
		return WaveResultVerification{}, errors.New("wave result timestamps fall outside the endorsed maintenance window")
	}
	if !waveResultRouteMatches(claim, policy) {
		return WaveResultVerification{}, errors.New("wave result worker route differs from the operator's declared maintenance routes")
	}
	key, keyErr := participationPublicKey(policy, claim.InstanceID)
	signature, signatureErr := hex.DecodeString(signed.Signature)
	if keyErr != nil || signatureErr != nil || signed.Signature != hex.EncodeToString(signature) || !ed25519.Verify(key, CanonicalWaveResult(claim), signature) {
		return WaveResultVerification{}, errors.New("wave result signature is invalid")
	}
	return WaveResultVerification{
		Digest: maintenanceDigest(claim), InstanceID: claim.InstanceID, Wave: claim.Wave,
		ReleaseDigest: claim.Release.Digest, ProgressID: claim.Progress.ID, State: "verified-progress",
		Notice: "Authenticated operator evidence only. Recheck current participation and every route-stage threshold; this is not remote attestation or installation authority.",
	}, nil
}

func waveResultPath(s *Store, id string) string {
	return filepath.Join(s.dir, "maintenance", "wave-results", id+".json")
}

func (s *Store) readLocalWaveResult(id string) (SignedWaveResult, error) {
	if !slug.MatchString(id) {
		return SignedWaveResult{}, errors.New("invalid wave result ID")
	}
	raw, err := worker.ReadPrivateFile(waveResultPath(s, id), 64<<10)
	if err != nil {
		return SignedWaveResult{}, errors.New("wave result is unavailable")
	}
	var result SignedWaveResult
	if strictJSON(raw, &result) != nil || validateWaveResultClaim(result.Claim) != nil || result.Claim.ID != id || result.Claim.InstanceID != s.InstanceID() {
		return SignedWaveResult{}, errors.New("wave result is invalid")
	}
	_, key, err := s.maintenanceIdentity()
	signature, decodeErr := hex.DecodeString(result.Signature)
	if err != nil || decodeErr != nil || result.Signature != hex.EncodeToString(signature) || !ed25519.Verify(key.Public().(ed25519.PublicKey), CanonicalWaveResult(result.Claim), signature) {
		return SignedWaveResult{}, errors.New("local wave result signature is invalid")
	}
	return result, nil
}

func (s *Store) waveResultInventoryLocked() WaveResultInventory {
	result := WaveResultInventory{Results: []SignedWaveResult{}, Notice: "Authenticated historical operator reports only; each later wave must reverify the exact report against its active plan and local policy."}
	root := filepath.Join(s.dir, "maintenance", "wave-results")
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return result
	}
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		result.Problem = "wave result history is unavailable, nonprivate or a symlink"
		return result
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > maxWaveResults {
		result.Problem = "wave result history is unavailable or exceeds 64 results"
		return result
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".json" {
			result.Problem = "wave result history contains an unexpected entry"
			continue
		}
		resultEntry, err := s.readLocalWaveResult(strings.TrimSuffix(name, ".json"))
		if err != nil {
			result.Problem = "one or more wave results require local recovery"
			continue
		}
		result.Results = append(result.Results, resultEntry)
	}
	sort.Slice(result.Results, func(i, j int) bool {
		return result.Results[i].Claim.RecordedAt.After(result.Results[j].Claim.RecordedAt)
	})
	return result
}

func (s *Store) WaveResultInventory() WaveResultInventory {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	return s.waveResultInventoryLocked()
}

func (s *Store) RecordWaveResult(req RecordWaveResultRequest, now time.Time) (SignedWaveResult, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if !slug.MatchString(req.ID) || !slug.MatchString(req.ProgressID) {
		return SignedWaveResult{}, errors.New("wave result requires lowercase result and progress IDs")
	}
	requestDigest := waveResultRequestDigest(req)
	if _, err := os.Lstat(waveResultPath(s, req.ID)); !os.IsNotExist(err) {
		old, readErr := s.readLocalWaveResult(req.ID)
		if readErr != nil {
			return SignedWaveResult{}, readErr
		}
		if old.Claim.RequestDigest != requestDigest {
			return SignedWaveResult{}, errors.New("wave result ID already binds different evidence")
		}
		return old, nil
	}
	policy, err := s.MaintenancePolicy(now)
	if err != nil {
		return SignedWaveResult{}, err
	}
	verifiedPlan, err := VerifyMaintenance(req.Envelope, policy, now)
	if err != nil || verifiedPlan.State != "reserved" {
		return SignedWaveResult{}, errors.New("recording a wave result requires the fully endorsed active plan")
	}
	member, key, err := s.maintenanceIdentity()
	if err != nil {
		return SignedWaveResult{}, err
	}
	if _, err := s.localParticipationReservation(req.Envelope, policy); err != nil {
		return SignedWaveResult{}, err
	}
	wave, window, err := maintenanceWave(req.Envelope, s.InstanceID())
	if err != nil || now.Before(window.Start) || !now.Before(window.End) {
		return SignedWaveResult{}, errors.New("wave result must be recorded inside this operator's endorsed window")
	}
	current, err := s.CurrentRelease()
	if err != nil || current.State != "installed" || current.Digest != window.ReleaseDigest {
		return SignedWaveResult{}, errors.New("the planned release is not recorded as installed by the update state machine")
	}
	progress, err := s.readProgressReceipt(req.ProgressID)
	if err != nil {
		return SignedWaveResult{}, err
	}
	claim := WaveResultClaim{
		SchemaVersion: 1, ID: req.ID, RequestDigest: requestDigest, InstanceID: s.InstanceID(),
		PlanDigest: verifiedPlan.Digest, PolicyDigest: MaintenancePolicyDigest(policy), Wave: wave,
		Release: *current, Progress: progress, RecordedAt: now, State: "reported-progress",
		Notice: "This scheduling-key signature authenticates retained local installed-release and progress evidence. It is not remote attestation, chain finality or permission for another operator to update.",
	}
	signed := SignedWaveResult{Claim: claim, Signature: hex.EncodeToString(ed25519.Sign(key, CanonicalWaveResult(claim)))}
	if member.InstanceID != claim.InstanceID {
		return SignedWaveResult{}, errors.New("local maintenance identity changed")
	}
	if _, err := VerifyWaveResult(signed, req.Envelope, policy, now); err != nil {
		return SignedWaveResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.ExpectedRevision != s.data.Revision {
		return SignedWaveResult{}, errors.New("operator revision changed; review the wave result again")
	}
	root := filepath.Join(s.dir, "maintenance", "wave-results")
	if err := worker.PrivateDir(root); err != nil {
		return SignedWaveResult{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) >= maxWaveResults {
		return SignedWaveResult{}, errors.New("wave result history is full; reviewed retention is required")
	}
	raw, _ := json.Marshal(signed)
	if len(raw) > 64<<10 {
		return SignedWaveResult{}, errors.New("wave result exceeds the portable size limit")
	}
	if err := atomicFile(root, req.ID+".json", raw); err != nil {
		return SignedWaveResult{}, errors.New("cannot persist wave result")
	}
	if err := s.recordLifecycleLocked("maintenance wave result recorded: "+req.ID, ""); err != nil {
		return SignedWaveResult{}, err
	}
	return signed, nil
}
