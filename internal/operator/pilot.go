package operator

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

var pilotDuties = []string{
	"hosting",
	"monitoring",
	"maintenance",
	"incident-response",
	"key-recovery",
	"backup-custody",
	"funding",
	"release-review",
}

var pilotControlDomains = []string{
	"host-admin",
	"cloud-recovery",
	"key-recovery",
	"backup-custody",
	"release-approval",
}

type PilotControlEvidence struct {
	Domain    string `json:"domain"`
	Reference string `json:"reference"`
}

// PilotAcceptanceRequest contains only the reviewed, non-secret values an
// operator supplies. The local instance and maintenance public key are always
// derived from this store rather than trusted from the input file.
type PilotAcceptanceRequest struct {
	SchemaVersion   int                    `json:"schemaVersion"`
	ID              string                 `json:"id"`
	OperatorAlias   string                 `json:"operatorAlias"`
	PolicyDigest    string                 `json:"policyDigest"`
	HostProfile     string                 `json:"hostProfile"`
	AcceptedDuties  []string               `json:"acceptedDuties"`
	ControlEvidence []PilotControlEvidence `json:"controlEvidence"`
	ExpiresAt       time.Time              `json:"expiresAt"`
}

type PilotAcceptanceClaim struct {
	SchemaVersion        int                    `json:"schemaVersion"`
	ID                   string                 `json:"id"`
	OperatorAlias        string                 `json:"operatorAlias"`
	InstanceID           string                 `json:"instanceId"`
	MaintenancePublicKey string                 `json:"maintenancePublicKey"`
	PolicyDigest         string                 `json:"policyDigest"`
	HostProfile          string                 `json:"hostProfile"`
	AcceptedDuties       []string               `json:"acceptedDuties"`
	ControlEvidence      []PilotControlEvidence `json:"controlEvidence"`
	AcceptedAt           time.Time              `json:"acceptedAt"`
	ExpiresAt            time.Time              `json:"expiresAt"`
}

type SignedPilotAcceptance struct {
	Claim     PilotAcceptanceClaim `json:"claim"`
	Signature string               `json:"signature"`
}

type PilotAcceptanceVerification struct {
	State           string   `json:"state"`
	PolicyDigest    string   `json:"policyDigest"`
	Operators       []string `json:"operators"`
	Instances       []string `json:"instances"`
	ActivationReady bool     `json:"activationReady"`
	Notice          string   `json:"notice"`
}

func CanonicalPilotAcceptance(claim PilotAcceptanceClaim) []byte {
	raw, _ := json.Marshal(claim)
	return append([]byte("VORTEX-PILOT-ACCEPTANCE-V1\n"), raw...)
}

func exactStringSet(values, expected []string) bool {
	if len(values) != len(expected) {
		return false
	}
	want := make(map[string]bool, len(expected))
	for _, value := range expected {
		want[value] = true
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !want[value] || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validatePilotClaim(claim PilotAcceptanceClaim, now time.Time) error {
	if claim.SchemaVersion != 1 || !slug.MatchString(claim.ID) || !slug.MatchString(claim.OperatorAlias) || !slug.MatchString(claim.InstanceID) {
		return errors.New("invalid pilot acceptance identity")
	}
	key, keyErr := hex.DecodeString(claim.MaintenancePublicKey)
	if keyErr != nil || len(key) != ed25519.PublicKeySize || claim.MaintenancePublicKey != hex.EncodeToString(key) || !hexHash.MatchString(claim.PolicyDigest) {
		return errors.New("invalid pilot acceptance key or policy digest")
	}
	if claim.HostProfile != "standard" && claim.HostProfile != "restricted" {
		return errors.New("pilot host profile must be standard or restricted")
	}
	if !exactStringSet(claim.AcceptedDuties, pilotDuties) {
		return errors.New("pilot acceptance must include every required duty exactly once")
	}
	if claim.AcceptedAt.IsZero() || claim.AcceptedAt.After(now.Add(5*time.Minute)) || claim.AcceptedAt.Before(now.Add(-90*24*time.Hour)) || !claim.ExpiresAt.After(now) || !claim.ExpiresAt.After(claim.AcceptedAt) || claim.ExpiresAt.Sub(claim.AcceptedAt) > 90*24*time.Hour {
		return errors.New("pilot acceptance is expired or outside the allowed 90-day window")
	}
	domains := make([]string, 0, len(claim.ControlEvidence))
	for _, evidence := range claim.ControlEvidence {
		if !hexHash.MatchString(evidence.Reference) {
			return errors.New("pilot control evidence references must be sanitized SHA-256 digests")
		}
		domains = append(domains, evidence.Domain)
	}
	if !exactStringSet(domains, pilotControlDomains) {
		return errors.New("pilot acceptance must cover every required control domain exactly once")
	}
	return nil
}

func verifySignedPilotAcceptance(acceptance SignedPilotAcceptance, now time.Time) error {
	if err := validatePilotClaim(acceptance.Claim, now); err != nil {
		return err
	}
	key, _ := hex.DecodeString(acceptance.Claim.MaintenancePublicKey)
	signature, err := hex.DecodeString(acceptance.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), CanonicalPilotAcceptance(acceptance.Claim), signature) {
		return errors.New("invalid pilot acceptance signature")
	}
	return nil
}

func VerifyPilotAcceptances(acceptances []SignedPilotAcceptance, policyDigest string, now time.Time) (PilotAcceptanceVerification, error) {
	result := PilotAcceptanceVerification{
		State:           "invalid",
		PolicyDigest:    policyDigest,
		Operators:       []string{},
		Instances:       []string{},
		ActivationReady: false,
		Notice:          "Three valid signed declarations are necessary but do not prove real-world identity, separate host administration, separate cloud recovery, separate key custody or independent release approval. Human review of sanitized control-domain evidence is still required before pilot activation.",
	}
	if !hexHash.MatchString(policyDigest) || len(acceptances) != 3 {
		return result, errors.New("pilot verification requires exactly three acceptances for one reviewed policy digest")
	}
	aliases, instances, keys, IDs := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, acceptance := range acceptances {
		if err := verifySignedPilotAcceptance(acceptance, now); err != nil {
			return result, err
		}
		claim := acceptance.Claim
		if claim.PolicyDigest != policyDigest || aliases[claim.OperatorAlias] || instances[claim.InstanceID] || keys[claim.MaintenancePublicKey] || IDs[claim.ID] {
			return result, errors.New("pilot acceptances must use one policy and distinct operators, instances, keys and record IDs")
		}
		aliases[claim.OperatorAlias], instances[claim.InstanceID], keys[claim.MaintenancePublicKey], IDs[claim.ID] = true, true, true, true
		result.Operators = append(result.Operators, claim.OperatorAlias)
		result.Instances = append(result.Instances, claim.InstanceID)
	}
	sort.Strings(result.Operators)
	sort.Strings(result.Instances)
	result.State = "signed-declarations-valid"
	return result, nil
}

func (s *Store) RecordPilotAcceptance(request PilotAcceptanceRequest, now time.Time) (SignedPilotAcceptance, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	var empty SignedPilotAcceptance
	member, key, err := s.maintenanceIdentity()
	if err != nil {
		return empty, err
	}
	claim := PilotAcceptanceClaim{
		SchemaVersion:        request.SchemaVersion,
		ID:                   request.ID,
		OperatorAlias:        request.OperatorAlias,
		InstanceID:           member.InstanceID,
		MaintenancePublicKey: member.PublicKey,
		PolicyDigest:         request.PolicyDigest,
		HostProfile:          request.HostProfile,
		AcceptedDuties:       append([]string(nil), request.AcceptedDuties...),
		ControlEvidence:      append([]PilotControlEvidence(nil), request.ControlEvidence...),
		AcceptedAt:           now,
		ExpiresAt:            request.ExpiresAt,
	}
	if err := validatePilotClaim(claim, now); err != nil {
		return empty, err
	}
	acceptance := SignedPilotAcceptance{Claim: claim, Signature: hex.EncodeToString(ed25519.Sign(key, CanonicalPilotAcceptance(claim)))}
	if err := verifySignedPilotAcceptance(acceptance, now); err != nil {
		return empty, err
	}
	raw, _ := json.Marshal(acceptance)
	if err := atomicFile(filepath.Join(s.dir, "maintenance"), "pilot-acceptance.json", raw); err != nil {
		return empty, errors.New("cannot persist pilot acceptance; no signature returned")
	}
	return acceptance, nil
}

func (s *Store) PilotState(now time.Time) map[string]interface{} {
	result := map[string]interface{}{
		"state":                  "not-accepted",
		"activationReady":        false,
		"requiredOperators":      3,
		"requiredDuties":         append([]string(nil), pilotDuties...),
		"requiredControlDomains": append([]string(nil), pilotControlDomains...),
		"notice":                 "This local record is one signed declaration. Prompt 06 requires three independent people on separate control domains and human review of sanitized evidence.",
	}
	member, _, err := s.maintenanceIdentity()
	if err != nil {
		result["problem"] = err.Error()
		return result
	}
	result["instanceId"] = member.InstanceID
	result["maintenancePublicKey"] = member.PublicKey
	path := filepath.Join(s.dir, "maintenance", "pilot-acceptance.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return result
	}
	raw, err := worker.ReadPrivateFile(path, 64<<10)
	var acceptance SignedPilotAcceptance
	if err != nil || strictJSON(raw, &acceptance) != nil || acceptance.Claim.InstanceID != member.InstanceID || acceptance.Claim.MaintenancePublicKey != member.PublicKey || verifySignedPilotAcceptance(acceptance, now) != nil {
		result["state"] = "invalid-local-record"
		result["problem"] = "local pilot acceptance is missing, expired, corrupt or signed by another identity"
		return result
	}
	result["state"] = "locally-accepted"
	result["acceptance"] = acceptance
	return result
}

func ReadPilotAcceptanceRequest(path string) (PilotAcceptanceRequest, error) {
	var request PilotAcceptanceRequest
	raw, err := worker.ReadPrivateFile(path, 64<<10)
	if err != nil || strictJSON(raw, &request) != nil {
		return request, errors.New("pilot acceptance request must be a private bounded JSON file")
	}
	return request, nil
}

func ReadPilotAcceptances(path string) ([]SignedPilotAcceptance, error) {
	var acceptances []SignedPilotAcceptance
	raw, err := worker.ReadPrivateFile(path, 256<<10)
	if err != nil || strictJSON(raw, &acceptances) != nil {
		return nil, errors.New("pilot acceptances must be one private bounded JSON array")
	}
	return acceptances, nil
}
