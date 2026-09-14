package operator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// These messages authenticate fresh local observations. Scheduling keys never
// acquire bridge signing authority or permission to install executable code.
type ParticipationChallenge struct {
	SchemaVersion int       `json:"schemaVersion"`
	ID            string    `json:"id"`
	Requester     string    `json:"requester"`
	PlanDigest    string    `json:"planDigest"`
	PolicyDigest  string    `json:"policyDigest"`
	ReleaseDigest string    `json:"releaseDigest"`
	Nonce         string    `json:"nonce"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
}
type SignedParticipationChallenge struct {
	Challenge ParticipationChallenge `json:"challenge"`
	Signature string                 `json:"signature"`
}
type ParticipationRequest struct {
	Envelope MaintenanceEnvelope          `json:"envelope"`
	Probe    SignedParticipationChallenge `json:"probe"`
}
type BeginParticipationRequest struct {
	ID               string              `json:"id"`
	ExpectedRevision uint64              `json:"expectedRevision"`
	Envelope         MaintenanceEnvelope `json:"envelope"`
}
type ParticipationObservation struct {
	SchemaVersion int                  `json:"schemaVersion"`
	InstanceID    string               `json:"instanceId"`
	ProbeDigest   string               `json:"probeDigest"`
	ObservedAt    time.Time            `json:"observedAt"`
	Snapshot      *ProgressSnapshot    `json:"snapshot,omitempty"`
	SigningProof  *worker.SigningProof `json:"signingProof,omitempty"`
	Problem       string               `json:"problem,omitempty"`
}
type SignedParticipationObservation struct {
	Observation ParticipationObservation `json:"observation"`
	Signature   string                   `json:"signature"`
}
type ParticipationMemberResult struct {
	InstanceID string `json:"instanceId"`
	State      string `json:"state"`
	Notice     string `json:"notice"`
}
type ParticipationStageResult struct {
	RouteID    string   `json:"routeId"`
	Stage      string   `json:"stage"`
	Required   int      `json:"required"`
	Eligible   []string `json:"eligible"`
	Unverified []string `json:"unverified"`
	State      string   `json:"state"`
	Notice     string   `json:"notice"`
}
type ParticipationVerification struct {
	ProbeDigest              string                      `json:"probeDigest"`
	CheckedAt                time.Time                   `json:"checkedAt"`
	ExpiresAt                time.Time                   `json:"expiresAt"`
	Members                  []ParticipationMemberResult `json:"members"`
	Missing                  []string                    `json:"missing"`
	Stages                   []ParticipationStageResult  `json:"stages"`
	AllResponded             bool                        `json:"allResponded"`
	ContractKeyThresholdsMet bool                        `json:"contractKeyThresholdsMet"`
	ActivationReady          bool                        `json:"activationReady"`
	Notice                   string                      `json:"notice"`
}

func participationBytes(domain string, value interface{}) []byte {
	raw, _ := json.Marshal(value)
	return append([]byte(domain+"\n"), raw...)
}
func participationPublicKey(policy MaintenancePolicy, id string) (ed25519.PublicKey, error) {
	for _, m := range policy.Members {
		if m.InstanceID == id {
			return maintenanceKey(m)
		}
	}
	return nil, errors.New("participation signer is absent from local maintenance policy")
}
func verifyParticipationRequest(req ParticipationRequest, policy MaintenancePolicy, now time.Time) error {
	verified, err := VerifyMaintenance(req.Envelope, policy, now)
	if err != nil || verified.State != "reserved" {
		return errors.New("participation requires a valid fully endorsed maintenance plan")
	}
	p := req.Probe.Challenge
	if p.SchemaVersion != 1 || !slug.MatchString(p.ID) || !hexHash.MatchString(p.Nonce) || p.PlanDigest != verified.Digest || p.PolicyDigest != MaintenancePolicyDigest(policy) || p.IssuedAt.IsZero() || p.IssuedAt.After(now) || !p.ExpiresAt.After(now) || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 2*time.Minute {
		return errors.New("participation challenge is expired, future-dated or bound to another plan")
	}
	found := false
	for _, w := range req.Envelope.Plan.Windows {
		if w.InstanceID == p.Requester && w.ReleaseDigest == p.ReleaseDigest && !p.ExpiresAt.After(w.End) {
			found = true
		}
	}
	if !found {
		return errors.New("challenge requester or release has no matching maintenance window")
	}
	key, err := participationPublicKey(policy, p.Requester)
	signature, decodeErr := hex.DecodeString(req.Probe.Signature)
	if err != nil || decodeErr != nil || !ed25519.Verify(key, participationBytes("VORTEX-MAINTENANCE-PROBE-V1", p), signature) {
		return errors.New("invalid participation challenge signature")
	}
	return nil
}

// A valid imported plan cannot replace a missing local reservation journal.
func (s *Store) localParticipationReservation(req MaintenanceEnvelope, policy MaintenancePolicy) (ed25519.PrivateKey, error) {
	member, key, err := s.maintenanceIdentity()
	if err != nil {
		return nil, err
	}
	public, err := participationPublicKey(policy, s.InstanceID())
	if err != nil || hex.EncodeToString(public) != member.PublicKey {
		return nil, errors.New("local scheduling identity differs from maintenance policy")
	}
	journal, err := s.maintenanceJournal(key)
	if err != nil {
		return nil, err
	}
	for _, e := range journal.Reservations {
		if maintenanceDigest(e.Plan) == maintenanceDigest(req.Plan) {
			return key, nil
		}
	}
	return nil, errors.New("plan has no durable local reservation")
}
func (s *Store) BeginParticipation(req BeginParticipationRequest, now time.Time) (ParticipationRequest, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	var empty ParticipationRequest
	if !slug.MatchString(req.ID) {
		return empty, errors.New("choose a lowercase participation request ID")
	}
	policy, err := s.MaintenancePolicy(now)
	if err != nil {
		return empty, err
	}
	verified, err := VerifyMaintenance(req.Envelope, policy, now)
	if err != nil || verified.State != "reserved" {
		return empty, errors.New("collect every maintenance endorsement before requesting participation")
	}
	key, err := s.localParticipationReservation(req.Envelope, policy)
	if err != nil {
		return empty, err
	}
	var window *MaintenanceWindow
	for _, w := range req.Envelope.Plan.Windows {
		if w.InstanceID == s.InstanceID() {
			copy := w
			window = &copy
		}
	}
	if window == nil || !window.End.After(now) {
		return empty, errors.New("this operator has no current or future window in the plan")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !currentParticipationApproval(req.Envelope, s.data.Approvals, s.InstanceID()) {
		return empty, errors.New("matching current local release approval is required")
	}
	file := filepath.Join(s.dir, "maintenance", "participation.json")
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		old, err := s.readLocalParticipation()
		if err != nil {
			return empty, errors.New("participation record is unreadable; inspect it locally")
		}
		if old.Probe.Challenge.ID == req.ID {
			if old.Probe.Challenge.PlanDigest != verified.Digest {
				return empty, errors.New("participation ID already binds another plan")
			}
			if err := verifyParticipationRequest(old, policy, now); err != nil {
				return empty, err
			}
			return old, nil
		}
		if old.Probe.Challenge.ExpiresAt.After(now) {
			return empty, errors.New("an existing participation challenge is still active")
		}
	}
	if req.ExpectedRevision != s.data.Revision {
		return empty, errors.New("operator revision changed; review the plan again")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return empty, errors.New("cannot create participation nonce")
	}
	expires := now.Add(2 * time.Minute)
	if window.End.Before(expires) {
		expires = window.End
	}
	challenge := ParticipationChallenge{1, req.ID, s.InstanceID(), verified.Digest, MaintenancePolicyDigest(policy), window.ReleaseDigest, hex.EncodeToString(nonce), now, expires}
	result := ParticipationRequest{req.Envelope, SignedParticipationChallenge{challenge, hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-PROBE-V1", challenge)))}}
	raw, _ := json.Marshal(result)
	if len(raw) > 256<<10 {
		return empty, errors.New("participation request exceeds local size limit")
	}
	if err := s.recordLifecycleLocked("participation challenge created: "+req.ID, ""); err != nil {
		return empty, err
	}
	if err := atomicFile(filepath.Join(s.dir, "maintenance"), "participation.json", raw); err != nil {
		return empty, err
	}
	return result, nil
}
func (s *Store) ObserveParticipation(ctx context.Context, req ParticipationRequest) (SignedParticipationObservation, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	now := time.Now().UTC()
	policy, err := s.MaintenancePolicy(now)
	if err != nil {
		return SignedParticipationObservation{}, err
	}
	if err := verifyParticipationRequest(req, policy, now); err != nil {
		return SignedParticipationObservation{}, err
	}
	key, err := s.localParticipationReservation(req.Envelope, policy)
	if err != nil {
		return SignedParticipationObservation{}, err
	}
	s.workerMu.Lock()
	snapshot, captureErr := s.captureProgress(ctx)
	var proof *worker.SigningProof
	if captureErr == nil && snapshot.Worker.Health.Mode == "signing" {
		registration, registrationErr := s.registration()
		if registrationErr == nil {
			signed, proofErr := worker.CallSigningProof(ctx, filepath.Join(registration.BaseDir, "bridge", ".operator"), maintenanceDigest(req.Probe.Challenge), *snapshot.Worker.Health)
			if proofErr == nil {
				proof = &signed
			} else {
				captureErr = errors.New("worker signing-key proof is unavailable")
			}
		} else {
			captureErr = errors.New("worker registration changed before signing-key proof")
		}
	}
	s.workerMu.Unlock()
	now = time.Now().UTC()
	currentPolicy, policyErr := s.MaintenancePolicy(now)
	if policyErr != nil || MaintenancePolicyDigest(currentPolicy) != MaintenancePolicyDigest(policy) {
		return SignedParticipationObservation{}, errors.New("local maintenance policy changed during participation capture")
	}
	if err := verifyParticipationRequest(req, currentPolicy, now); err != nil {
		return SignedParticipationObservation{}, err
	}
	observation := ParticipationObservation{SchemaVersion: 1, InstanceID: s.InstanceID(), ProbeDigest: maintenanceDigest(req.Probe.Challenge), ObservedAt: now}
	if captureErr != nil {
		observation.Problem = captureErr.Error()
	} else {
		observation.Snapshot = &snapshot
		observation.SigningProof = proof
	}
	// No caller-provided worker data or stage-ready assertions are signed.
	return SignedParticipationObservation{observation, hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", observation)))}, nil
}

func verifyParticipationSigningProof(proof worker.SigningProof, probeDigest string, snapshot ProgressSnapshot, member MaintenanceMember) (string, error) {
	health := snapshot.Worker.Health
	challenge := proof.Challenge
	if challenge.SchemaVersion != 1 || challenge.ProbeDigest != probeDigest || health == nil || challenge.InstanceID != health.InstanceID || challenge.PID != health.PID || !challenge.StartedAt.Equal(health.StartedAt) || !strings.EqualFold(challenge.EVMAddress, health.EVMAddress) || challenge.KoinosAddress != health.KoinosAddress {
		return "", errors.New("worker signing proof contradicts the authenticated snapshot")
	}
	digest, err := worker.SigningProofDigest(challenge)
	if err != nil {
		return "", err
	}
	evm, evmErr := util.RecoverEthereumAddressFromSignature(proof.EVMSignature, digest)
	koinos, koinosErr := util.RecoverKoinosAddressFromSignature(proof.KoinosSignature, digest)
	if evmErr != nil || koinosErr != nil || !strings.EqualFold(evm, challenge.EVMAddress) || koinos != challenge.KoinosAddress {
		return "", errors.New("worker signing proof does not verify against both reported bridge identities")
	}
	if member.EVMAddress == "" || member.KoinosAddress == "" {
		return "signing-identity-unmapped", nil
	}
	if !strings.EqualFold(member.EVMAddress, evm) || member.KoinosAddress != koinos {
		return "signing-identity-mismatch", nil
	}
	return "signing-key-proved", nil
}

func participationStages(policy MaintenancePolicy, requester string, states map[string]string) ([]ParticipationStageResult, bool) {
	results := []ParticipationStageResult{}
	allContractKeys := true
	for _, route := range policy.Routes {
		for _, stage := range route.Stages {
			result := ParticipationStageResult{RouteID: route.ID, Stage: stage.Name, Required: stage.Required, Eligible: []string{}, Unverified: []string{}, State: "unknown"}
			if stage.Name == "evm-contract" || stage.Name == "koinos-contract" {
				for _, id := range stage.Participants {
					if id != requester && states[id] == "signing-key-proved" {
						result.Eligible = append(result.Eligible, id)
					} else {
						result.Unverified = append(result.Unverified, id)
					}
				}
				if len(result.Eligible) >= result.Required {
					result.State = "key-threshold-passed"
					result.Notice = "Enough non-updating participants proved possession of their locally mapped bridge keys. Fresh on-chain membership and valid bridge signatures remain separate checks."
				} else {
					result.State = "blocked"
					result.Notice = "Too few non-updating participants proved possession of their locally mapped bridge keys."
					allContractKeys = false
				}
			} else {
				result.Unverified = append(result.Unverified, stage.Participants...)
				result.Notice = "Authenticated worker key possession does not verify this external peer, API or frontend stage."
			}
			results = append(results, result)
		}
	}
	return results, allContractKeys
}

func VerifyParticipation(req ParticipationRequest, reports []SignedParticipationObservation, policy MaintenancePolicy, now time.Time) (ParticipationVerification, error) {
	if err := verifyParticipationRequest(req, policy, now); err != nil {
		return ParticipationVerification{}, err
	}
	if len(reports) > len(policy.Members) {
		return ParticipationVerification{}, errors.New("too many participation responses")
	}
	result := ParticipationVerification{ProbeDigest: maintenanceDigest(req.Probe.Challenge), CheckedAt: now, ExpiresAt: req.Probe.Challenge.ExpiresAt, Members: []ParticipationMemberResult{}, Missing: []string{}, Stages: []ParticipationStageResult{}, Notice: "Authenticated operator and worker key-possession evidence only. Fresh contract membership, valid bridge signatures and each peer/API/frontend threshold remain required; observations cannot authorize installation."}
	seen := map[string]bool{}
	memberStates := map[string]string{}
	memberPolicy := map[string]MaintenanceMember{}
	for _, member := range policy.Members {
		memberPolicy[member.InstanceID] = member
	}
	for _, signed := range reports {
		o := signed.Observation
		key, err := participationPublicKey(policy, o.InstanceID)
		signature, decodeErr := hex.DecodeString(signed.Signature)
		if err != nil || decodeErr != nil || seen[o.InstanceID] || o.SchemaVersion != 1 || o.ProbeDigest != result.ProbeDigest || !ed25519.Verify(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", o), signature) {
			return ParticipationVerification{}, errors.New("unknown, duplicate, changed or wrong-challenge participation response")
		}
		if o.ObservedAt.Before(req.Probe.Challenge.IssuedAt) || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) >= 30*time.Second {
			return ParticipationVerification{}, errors.New("participation response is stale or has inconsistent time")
		}
		if (o.Snapshot == nil) == (o.Problem == "") || len(o.Problem) > 1024 || (o.SigningProof != nil && o.Snapshot == nil) {
			return ParticipationVerification{}, errors.New("participation response has contradictory evidence")
		}
		member := ParticipationMemberResult{o.InstanceID, "unavailable", o.Problem}
		if o.Snapshot != nil {
			snapshot := *o.Snapshot
			if !validProgressSnapshot(snapshot) || snapshot.SampledAt.Before(req.Probe.Challenge.IssuedAt) || snapshot.SampledAt.After(o.ObservedAt) || o.ObservedAt.Sub(snapshot.SampledAt) > 5*time.Second {
				return ParticipationVerification{}, errors.New("participation worker snapshot is invalid or stale")
			}
			matched := false
			for _, route := range policy.Routes {
				participant := false
				for _, stage := range route.Stages {
					for _, id := range stage.Participants {
						if id == o.InstanceID {
							participant = true
						}
					}
				}
				b := snapshot.Worker.Health.NetworkBinding
				if participant && b.EVMNetworkID == route.EVM.NetworkID && b.KoinosNetworkID == route.Koinos.NetworkID && strings.EqualFold(b.EVMContract, route.EVM.Contract) && b.KoinosContract == route.Koinos.Contract {
					matched = true
				}
			}
			if !matched {
				return ParticipationVerification{}, errors.New("participation worker route differs from declared deployment")
			}
			member.State = "worker-observed"
			if snapshot.Worker.Health.Mode == "observation-only" {
				if o.SigningProof != nil {
					return ParticipationVerification{}, errors.New("observation-only worker supplied a signing proof")
				}
				member.State = "observation-only"
			} else if o.SigningProof == nil {
				member.State = "signing-proof-missing"
			} else {
				state, err := verifyParticipationSigningProof(*o.SigningProof, result.ProbeDigest, snapshot, memberPolicy[o.InstanceID])
				if err != nil {
					return ParticipationVerification{}, err
				}
				member.State = state
			}
			switch member.State {
			case "signing-key-proved":
				member.Notice = "Fresh worker proof matches both bridge identities in this operator's local policy. Membership, productive signing and external stages remain unverified."
			case "signing-identity-unmapped":
				member.Notice = "The worker proved both bridge keys, but this local policy does not map them to the operator."
			case "signing-identity-mismatch":
				member.Notice = "The worker proved both reported bridge keys, but they differ from this local policy."
			default:
				member.Notice = "Fresh signed local telemetry; bridge-key possession and stage quorum remain unverified."
			}
		}
		if end := o.ObservedAt.Add(30 * time.Second); end.Before(result.ExpiresAt) {
			result.ExpiresAt = end
		}
		seen[o.InstanceID] = true
		memberStates[o.InstanceID] = member.State
		result.Members = append(result.Members, member)
	}
	for _, m := range policy.Members {
		if !seen[m.InstanceID] {
			result.Missing = append(result.Missing, m.InstanceID)
		}
	}
	sort.Slice(result.Members, func(i, j int) bool { return result.Members[i].InstanceID < result.Members[j].InstanceID })
	sort.Strings(result.Missing)
	result.AllResponded = len(result.Missing) == 0
	result.Stages, result.ContractKeyThresholdsMet = participationStages(policy, req.Probe.Challenge.Requester, memberStates)
	return result, nil
}
func (s *Store) CheckParticipation(reports []SignedParticipationObservation, now time.Time) (ParticipationVerification, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	req, err := s.readLocalParticipation()
	if err != nil {
		return ParticipationVerification{}, errors.New("no local participation challenge is available")
	}
	policy, err := s.MaintenancePolicy(now)
	if err != nil {
		return ParticipationVerification{}, err
	}
	if _, err := s.localParticipationReservation(req.Envelope, policy); err != nil {
		return ParticipationVerification{}, err
	}
	if !currentParticipationApproval(req.Envelope, s.ReleaseApprovals(), s.InstanceID()) {
		return ParticipationVerification{}, errors.New("local release approval was revoked or superseded")
	}
	return VerifyParticipation(req, reports, policy, now)
}

func currentParticipationApproval(envelope MaintenanceEnvelope, approvals []ReleaseApproval, id string) bool {
	var latest *ReleaseApproval
	for _, a := range approvals {
		if a.InstanceID == id && a.Component == "validator" && (latest == nil || a.Sequence > latest.Sequence) {
			copy := a
			latest = &copy
		}
	}
	if latest == nil || latest.Revoked {
		return false
	}
	for _, w := range envelope.Plan.Windows {
		if w.InstanceID == id && w.ReleaseDigest == latest.Digest && !w.Start.Before(latest.WindowStart) && !w.End.After(latest.WindowEnd) {
			return true
		}
	}
	return false
}
func ReadParticipationInput(path string, value interface{}) error {
	raw, err := worker.ReadPrivateFile(path, 1<<20)
	if err != nil || strictJSON(raw, value) != nil {
		return errors.New("participation input must be a private bounded JSON file")
	}
	return nil
}
func (s *Store) ParticipationState(now time.Time) map[string]interface{} {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	revision, _, _ := s.Summary()
	result := map[string]interface{}{"revision": revision}
	path := filepath.Join(s.dir, "maintenance", "participation.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return result
	}
	req, err := s.readLocalParticipation()
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	policy, err := s.MaintenancePolicy(now)
	if err == nil {
		err = verifyParticipationRequest(req, policy, now)
	}
	result["request"] = req
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}

func (s *Store) readLocalParticipation() (ParticipationRequest, error) {
	var req ParticipationRequest
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, "maintenance", "participation.json"), 256<<10)
	if err != nil || strictJSON(raw, &req) != nil {
		return req, errors.New("local participation record is unreadable")
	}
	member, _, err := s.maintenanceIdentity()
	public, keyErr := maintenanceKey(member)
	signature, sigErr := hex.DecodeString(req.Probe.Signature)
	c := req.Probe.Challenge
	if err != nil || keyErr != nil || sigErr != nil || c.Requester != s.InstanceID() || c.PlanDigest != maintenanceDigest(req.Envelope.Plan) || c.PolicyDigest != req.Envelope.Plan.PolicyDigest || !ed25519.Verify(public, participationBytes("VORTEX-MAINTENANCE-PROBE-V1", c), signature) {
		return req, errors.New("local participation record failed signature verification")
	}
	return req, nil
}
