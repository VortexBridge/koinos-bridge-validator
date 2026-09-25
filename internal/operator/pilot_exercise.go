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

var pilotExercisePhases = []string{
	"onboarding",
	"membership",
	"evm-to-koinos-normal",
	"koinos-to-evm-normal",
	"unexpected-validator-outage",
	"planned-maintenance",
	"rpc-disagreement",
	"peer-outage",
	"persistence-failure",
	"coordinator-outage",
	"restart-reconciliation",
	"observation-restore",
	"fenced-replacement",
}

type PilotExerciseRequest struct {
	SchemaVersion    int       `json:"schemaVersion"`
	ID               string    `json:"id"`
	SessionID        string    `json:"sessionId"`
	AcceptanceDigest string    `json:"acceptanceDigest"`
	Phase            string    `json:"phase"`
	Result           string    `json:"result"`
	ObservedAt       time.Time `json:"observedAt"`
	DurationMillis   uint64    `json:"durationMillis"`
	EvidenceDigests  []string  `json:"evidenceDigests"`
	ProblemCode      string    `json:"problemCode,omitempty"`
}

type PilotExerciseClaim struct {
	SchemaVersion        int       `json:"schemaVersion"`
	ID                   string    `json:"id"`
	SessionID            string    `json:"sessionId"`
	OperatorAlias        string    `json:"operatorAlias"`
	InstanceID           string    `json:"instanceId"`
	MaintenancePublicKey string    `json:"maintenancePublicKey"`
	PolicyDigest         string    `json:"policyDigest"`
	AcceptanceDigest     string    `json:"acceptanceDigest"`
	Phase                string    `json:"phase"`
	Result               string    `json:"result"`
	ObservedAt           time.Time `json:"observedAt"`
	DurationMillis       uint64    `json:"durationMillis"`
	EvidenceDigests      []string  `json:"evidenceDigests"`
	ProblemCode          string    `json:"problemCode,omitempty"`
}

type SignedPilotExercise struct {
	Claim     PilotExerciseClaim `json:"claim"`
	Signature string             `json:"signature"`
}

type PilotExerciseVerification struct {
	State           string         `json:"state"`
	SessionID       string         `json:"sessionId"`
	PolicyDigest    string         `json:"policyDigest"`
	Operators       []string       `json:"operators"`
	PhaseReceipts   map[string]int `json:"phaseReceipts"`
	ReceiptCount    int            `json:"receiptCount"`
	ActivationReady bool           `json:"activationReady"`
	Notice          string         `json:"notice"`
}

func PilotAcceptanceDigest(acceptance SignedPilotAcceptance) string {
	return maintenanceDigest(acceptance)
}

func CanonicalPilotExercise(claim PilotExerciseClaim) []byte {
	raw, _ := json.Marshal(claim)
	return append([]byte("VORTEX-PILOT-EXERCISE-V1\n"), raw...)
}

func validPilotPhase(phase string) bool {
	for _, expected := range pilotExercisePhases {
		if phase == expected {
			return true
		}
	}
	return false
}

func validatePilotExerciseClaim(claim PilotExerciseClaim, now time.Time) error {
	if claim.SchemaVersion != 1 || !slug.MatchString(claim.ID) || !slug.MatchString(claim.SessionID) || !slug.MatchString(claim.OperatorAlias) || !slug.MatchString(claim.InstanceID) {
		return errors.New("invalid pilot exercise identity")
	}
	key, keyErr := hex.DecodeString(claim.MaintenancePublicKey)
	if keyErr != nil || len(key) != ed25519.PublicKeySize || claim.MaintenancePublicKey != hex.EncodeToString(key) || !hexHash.MatchString(claim.PolicyDigest) || !hexHash.MatchString(claim.AcceptanceDigest) {
		return errors.New("invalid pilot exercise key or binding digest")
	}
	if !validPilotPhase(claim.Phase) || (claim.Result != "passed" && claim.Result != "failed") {
		return errors.New("unsupported pilot exercise phase or result")
	}
	if claim.Result == "passed" && claim.ProblemCode != "" {
		return errors.New("passed pilot exercise cannot declare a problem code")
	}
	if claim.Result == "failed" && !slug.MatchString(claim.ProblemCode) {
		return errors.New("failed pilot exercise requires a sanitized problem code")
	}
	if claim.ObservedAt.IsZero() || claim.ObservedAt.After(now.Add(5*time.Minute)) || claim.ObservedAt.Before(now.Add(-90*24*time.Hour)) || claim.DurationMillis == 0 || claim.DurationMillis > uint64((7*24*time.Hour)/time.Millisecond) || len(claim.EvidenceDigests) == 0 || len(claim.EvidenceDigests) > 16 {
		return errors.New("pilot exercise timing or evidence count is invalid")
	}
	seen := map[string]bool{}
	for _, digest := range claim.EvidenceDigests {
		if !hexHash.MatchString(digest) || seen[digest] {
			return errors.New("pilot exercise evidence must use distinct sanitized SHA-256 digests")
		}
		seen[digest] = true
	}
	return nil
}

func verifySignedPilotExercise(receipt SignedPilotExercise, now time.Time) error {
	if err := validatePilotExerciseClaim(receipt.Claim, now); err != nil {
		return err
	}
	key, _ := hex.DecodeString(receipt.Claim.MaintenancePublicKey)
	signature, err := hex.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), CanonicalPilotExercise(receipt.Claim), signature) {
		return errors.New("invalid pilot exercise signature")
	}
	return nil
}

func (s *Store) localPilotAcceptance(now time.Time) (SignedPilotAcceptance, error) {
	var acceptance SignedPilotAcceptance
	member, _, err := s.maintenanceIdentity()
	if err != nil {
		return acceptance, err
	}
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, "maintenance", "pilot-acceptance.json"), 64<<10)
	if err != nil || strictJSON(raw, &acceptance) != nil || acceptance.Claim.InstanceID != member.InstanceID || acceptance.Claim.MaintenancePublicKey != member.PublicKey || verifySignedPilotAcceptance(acceptance, now) != nil {
		return acceptance, errors.New("valid local pilot acceptance unavailable")
	}
	return acceptance, nil
}

func (s *Store) RecordPilotExercise(request PilotExerciseRequest, now time.Time) (SignedPilotExercise, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	var empty SignedPilotExercise
	acceptance, err := s.localPilotAcceptance(now)
	if err != nil {
		return empty, err
	}
	if request.AcceptanceDigest != PilotAcceptanceDigest(acceptance) {
		return empty, errors.New("pilot exercise differs from the current local acceptance")
	}
	claim := PilotExerciseClaim{
		SchemaVersion:        request.SchemaVersion,
		ID:                   request.ID,
		SessionID:            request.SessionID,
		OperatorAlias:        acceptance.Claim.OperatorAlias,
		InstanceID:           acceptance.Claim.InstanceID,
		MaintenancePublicKey: acceptance.Claim.MaintenancePublicKey,
		PolicyDigest:         acceptance.Claim.PolicyDigest,
		AcceptanceDigest:     request.AcceptanceDigest,
		Phase:                request.Phase,
		Result:               request.Result,
		ObservedAt:           request.ObservedAt,
		DurationMillis:       request.DurationMillis,
		EvidenceDigests:      append([]string(nil), request.EvidenceDigests...),
		ProblemCode:          request.ProblemCode,
	}
	if claim.ObservedAt.Before(acceptance.Claim.AcceptedAt) || claim.ObservedAt.After(acceptance.Claim.ExpiresAt) {
		return empty, errors.New("pilot exercise falls outside the accepted responsibility window")
	}
	if err := validatePilotExerciseClaim(claim, now); err != nil {
		return empty, err
	}
	_, key, err := s.maintenanceIdentity()
	if err != nil {
		return empty, err
	}
	receipt := SignedPilotExercise{Claim: claim, Signature: hex.EncodeToString(ed25519.Sign(key, CanonicalPilotExercise(claim)))}
	dir := filepath.Join(s.dir, "maintenance", "pilot-receipts")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return empty, errors.New("cannot create private pilot receipt directory")
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return empty, errors.New("pilot receipt directory must be private")
	}
	path := filepath.Join(dir, request.ID+".json")
	if _, err := os.Lstat(path); err == nil {
		var old SignedPilotExercise
		raw, readErr := worker.ReadPrivateFile(path, 64<<10)
		if readErr != nil || strictJSON(raw, &old) != nil || maintenanceDigest(old) != maintenanceDigest(receipt) {
			return empty, errors.New("pilot exercise ID already binds different evidence")
		}
		return old, nil
	} else if !os.IsNotExist(err) {
		return empty, errors.New("cannot inspect existing pilot receipt")
	}
	raw, _ := json.Marshal(receipt)
	if err := atomicFile(dir, request.ID+".json", raw); err != nil {
		return empty, errors.New("cannot persist pilot exercise; no signature returned")
	}
	return receipt, nil
}

func (s *Store) pilotExerciseInventory(now time.Time) ([]SignedPilotExercise, string) {
	dir := filepath.Join(s.dir, "maintenance", "pilot-receipts")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []SignedPilotExercise{}, ""
	}
	if err != nil || len(entries) > 256 {
		return []SignedPilotExercise{}, "pilot exercise inventory unavailable or over capacity"
	}
	receipts := make([]SignedPilotExercise, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || !slug.MatchString(entry.Name()[:len(entry.Name())-5]) {
			return []SignedPilotExercise{}, "pilot exercise inventory contains an unexpected entry"
		}
		var receipt SignedPilotExercise
		raw, readErr := worker.ReadPrivateFile(filepath.Join(dir, entry.Name()), 64<<10)
		if readErr != nil || strictJSON(raw, &receipt) != nil || receipt.Claim.ID+".json" != entry.Name() || verifySignedPilotExercise(receipt, now) != nil {
			return []SignedPilotExercise{}, "pilot exercise inventory contains an invalid receipt"
		}
		receipts = append(receipts, receipt)
	}
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].Claim.ID < receipts[j].Claim.ID })
	return receipts, ""
}

func VerifyPilotExercise(acceptances []SignedPilotAcceptance, receipts []SignedPilotExercise, policyDigest string, now time.Time) (PilotExerciseVerification, error) {
	result := PilotExerciseVerification{
		State:           "invalid",
		PolicyDigest:    policyDigest,
		Operators:       []string{},
		PhaseReceipts:   map[string]int{},
		ActivationReady: false,
		Notice:          "Complete signed exercise evidence does not prove separate people or control domains and does not authorize production. Review the underlying sanitized evidence and operator independence separately.",
	}
	acceptanceReport, err := VerifyPilotAcceptances(acceptances, policyDigest, now)
	if err != nil {
		return result, err
	}
	result.Operators = acceptanceReport.Operators
	expected := len(pilotExercisePhases) * len(acceptances)
	if len(receipts) != expected {
		return result, errors.New("pilot audit requires one receipt from every operator for every required phase")
	}
	byAlias := map[string]SignedPilotAcceptance{}
	for _, acceptance := range acceptances {
		byAlias[acceptance.Claim.OperatorAlias] = acceptance
	}
	sessionID := ""
	seenIDs, seenPairs := map[string]bool{}, map[string]bool{}
	for _, receipt := range receipts {
		if err := verifySignedPilotExercise(receipt, now); err != nil {
			return result, err
		}
		claim := receipt.Claim
		acceptance, ok := byAlias[claim.OperatorAlias]
		if !ok || claim.InstanceID != acceptance.Claim.InstanceID || claim.MaintenancePublicKey != acceptance.Claim.MaintenancePublicKey || claim.PolicyDigest != policyDigest || claim.AcceptanceDigest != PilotAcceptanceDigest(acceptance) {
			return result, errors.New("pilot receipt does not match its signed operator acceptance")
		}
		if claim.ObservedAt.Before(acceptance.Claim.AcceptedAt) || claim.ObservedAt.After(acceptance.Claim.ExpiresAt) || claim.Result != "passed" {
			return result, errors.New("pilot audit contains failed or out-of-window evidence")
		}
		if sessionID == "" {
			sessionID = claim.SessionID
		}
		pair := claim.OperatorAlias + ":" + claim.Phase
		if claim.SessionID != sessionID || seenIDs[claim.ID] || seenPairs[pair] {
			return result, errors.New("pilot receipts must use one session and unique IDs and operator phases")
		}
		seenIDs[claim.ID], seenPairs[pair] = true, true
		result.PhaseReceipts[claim.Phase]++
	}
	for _, phase := range pilotExercisePhases {
		if result.PhaseReceipts[phase] != len(acceptances) {
			return result, errors.New("pilot phase lacks all three operator observations")
		}
	}
	result.State = "exercise-evidence-complete"
	result.SessionID = sessionID
	result.ReceiptCount = len(receipts)
	return result, nil
}

func ReadPilotExerciseRequest(path string) (PilotExerciseRequest, error) {
	var request PilotExerciseRequest
	raw, err := worker.ReadPrivateFile(path, 64<<10)
	if err != nil || strictJSON(raw, &request) != nil {
		return request, errors.New("pilot exercise request must be a private bounded JSON file")
	}
	return request, nil
}

func ReadPilotExerciseReceipts(path string) ([]SignedPilotExercise, error) {
	var receipts []SignedPilotExercise
	raw, err := worker.ReadPrivateFile(path, 2<<20)
	if err != nil || strictJSON(raw, &receipts) != nil {
		return nil, errors.New("pilot receipts must be one private bounded JSON array")
	}
	return receipts, nil
}
