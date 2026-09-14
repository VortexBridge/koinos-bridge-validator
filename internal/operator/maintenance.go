package operator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// Maintenance keys authenticate schedule reservations and fresh observations,
// never bridge signatures or executable installation. Policy is installed locally, not by a coordinator.
type MaintenanceMember struct {
	InstanceID string `json:"instanceId"`
	PublicKey  string `json:"publicKey"`
}
type MaintenanceStage struct {
	Name         string   `json:"name"`
	Required     int      `json:"required"`
	Participants []string `json:"participants"`
}
type MaintenanceRoute struct {
	ID       string             `json:"id"`
	EVM      Profile            `json:"evm"`
	Koinos   Profile            `json:"koinos"`
	Evidence string             `json:"evidence"`
	Stages   []MaintenanceStage `json:"stages"`
}
type MaintenancePolicy struct {
	SchemaVersion int                 `json:"schemaVersion"`
	ID            string              `json:"id"`
	ExpiresAt     time.Time           `json:"expiresAt"`
	Members       []MaintenanceMember `json:"members"`
	Routes        []MaintenanceRoute  `json:"routes"`
}
type MaintenanceWindow struct {
	InstanceID    string    `json:"instanceId"`
	ReleaseDigest string    `json:"releaseDigest"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
}
type MaintenancePlan struct {
	SchemaVersion int                 `json:"schemaVersion"`
	ID            string              `json:"id"`
	PolicyDigest  string              `json:"policyDigest"`
	CreatedAt     time.Time           `json:"createdAt"`
	Windows       []MaintenanceWindow `json:"windows"`
}
type MaintenanceEndorsement struct {
	InstanceID string `json:"instanceId"`
	PlanDigest string `json:"planDigest"`
	Signature  string `json:"signature"`
}
type MaintenanceEnvelope struct {
	Plan         MaintenancePlan          `json:"plan"`
	Endorsements []MaintenanceEndorsement `json:"endorsements"`
}
type MaintenanceVerification struct {
	Digest          string   `json:"digest"`
	State           string   `json:"state"`
	Endorsed        []string `json:"endorsed"`
	Missing         []string `json:"missing"`
	ActivationReady bool     `json:"activationReady"`
	Notice          string   `json:"notice"`
}
type maintenanceIdentity struct {
	InstanceID string `json:"instanceId"`
	Seed       string `json:"seed"`
}
type maintenanceJournal struct {
	SchemaVersion int                   `json:"schemaVersion"`
	Reservations  []MaintenanceEnvelope `json:"reservations"`
}

func maintenanceDigest(v interface{}) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func CanonicalMaintenancePlan(p MaintenancePlan) []byte {
	raw, _ := json.Marshal(p)
	return append([]byte("VORTEX-MAINTENANCE-PLAN-V1\n"), raw...)
}
func MaintenancePolicyDigest(p MaintenancePolicy) string { return maintenanceDigest(p) }
func maintenanceKey(member MaintenanceMember) (ed25519.PublicKey, error) {
	key, err := hex.DecodeString(member.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || member.PublicKey != hex.EncodeToString(key) || !slug.MatchString(member.InstanceID) {
		return nil, errors.New("invalid maintenance member identity")
	}
	return key, nil
}
func validateMaintenancePolicy(p MaintenancePolicy, now time.Time) error {
	if p.SchemaVersion != 1 || !slug.MatchString(p.ID) || !p.ExpiresAt.After(now) || len(p.Members) < 2 || len(p.Members) > 32 || len(p.Routes) == 0 || len(p.Routes) > 32 {
		return errors.New("invalid or expired local maintenance policy")
	}
	members, keys := map[string]bool{}, map[string]bool{}
	for _, m := range p.Members {
		if _, err := maintenanceKey(m); err != nil || members[m.InstanceID] || keys[m.PublicKey] {
			return errors.New("maintenance members and keys must be distinct")
		}
		members[m.InstanceID] = true
		keys[m.PublicKey] = true
	}
	routes, used := map[string]bool{}, map[string]bool{}
	for _, r := range p.Routes {
		if !slug.MatchString(r.ID) || routes[r.ID] || r.EVM.Validate() != nil || r.Koinos.Validate() != nil || r.EVM.Family != "evm" || r.Koinos.Family != "koinos" || r.EVM.Environment != r.Koinos.Environment || r.EVM.BridgeChainID == r.Koinos.BridgeChainID || len(r.Evidence) == 0 || len(r.Evidence) > 1024 || len(r.Stages) != 5 {
			return errors.New("maintenance route requires exact deployments, evidence and both contract thresholds and peer/API/frontend thresholds")
		}
		routes[r.ID] = true
		stages := map[string]bool{}
		for _, s := range r.Stages {
			if (s.Name != "evm-contract" && s.Name != "koinos-contract" && s.Name != "peer" && s.Name != "api" && s.Name != "frontend") || stages[s.Name] || s.Required < 1 || s.Required > len(s.Participants) || len(s.Participants) > len(members) {
				return errors.New("invalid or missing maintenance stage threshold")
			}
			stages[s.Name] = true
			seen := map[string]bool{}
			for _, id := range s.Participants {
				if !members[id] || seen[id] {
					return errors.New("unknown or duplicate stage participant")
				}
				seen[id] = true
				used[id] = true
			}
		}
	}
	for id := range members {
		if !used[id] {
			return errors.New("maintenance member is absent from every route")
		}
	}
	return nil
}
func validateMaintenancePlan(p MaintenancePlan, policy MaintenancePolicy, now time.Time) error {
	if err := validateMaintenancePolicy(policy, now); err != nil {
		return err
	}
	if p.SchemaVersion != 1 || !slug.MatchString(p.ID) || p.PolicyDigest != MaintenancePolicyDigest(policy) || p.CreatedAt.IsZero() || p.CreatedAt.After(now.Add(5*time.Minute)) || len(p.Windows) == 0 || len(p.Windows) > 32 {
		return errors.New("invalid maintenance plan or changed local policy")
	}
	if !p.Windows[len(p.Windows)-1].End.After(now) {
		return errors.New("maintenance plan expired")
	}
	members := map[string]bool{}
	for _, m := range policy.Members {
		members[m.InstanceID] = true
	}
	seen := map[string]bool{}
	for i, w := range p.Windows {
		if !members[w.InstanceID] || seen[w.InstanceID] || !hexHash.MatchString(w.ReleaseDigest) || w.Start.Before(p.CreatedAt) || !w.End.After(w.Start) || w.End.After(policy.ExpiresAt) || w.End.Sub(p.CreatedAt) > 7*24*time.Hour || w.End.Sub(w.Start) > 24*time.Hour {
			return errors.New("invalid, expired or duplicate maintenance window")
		}
		seen[w.InstanceID] = true
		// One operator at a time. Later waves additionally require fresh success
		// and participation checks; wall-clock schedules alone cannot start them.
		if i > 0 && w.Start.Before(p.Windows[i-1].End) {
			return errors.New("maintenance windows overlap or are not ordered")
		}
		for _, r := range policy.Routes {
			for _, s := range r.Stages {
				available := len(s.Participants)
				for _, id := range s.Participants {
					if id == w.InstanceID {
						available--
					}
				}
				if available < s.Required {
					return errors.New("planned outage violates a declared route stage threshold")
				}
			}
		}
	}
	return nil
}
func VerifyMaintenance(e MaintenanceEnvelope, policy MaintenancePolicy, now time.Time) (MaintenanceVerification, error) {
	if err := validateMaintenancePlan(e.Plan, policy, now); err != nil {
		return MaintenanceVerification{}, err
	}
	digest := maintenanceDigest(e.Plan)
	members := map[string]MaintenanceMember{}
	for _, m := range policy.Members {
		members[m.InstanceID] = m
	}
	if len(e.Endorsements) > len(members) {
		return MaintenanceVerification{}, errors.New("too many maintenance endorsements")
	}
	result := MaintenanceVerification{Digest: digest, State: "awaiting-endorsements", Endorsed: []string{}, Missing: []string{}, Notice: "Schedule consent only. Before activation, recheck current local release approval, reservations, all route-stage participation, previous-wave progress, compatibility and backup. Unknown or stale coordination blocks automatic activation. Declared thresholds and keys do not establish independent hosts or actual quorum."}
	seen := map[string]bool{}
	for _, s := range e.Endorsements {
		m, ok := members[s.InstanceID]
		key, err := maintenanceKey(m)
		sig, decodeErr := hex.DecodeString(s.Signature)
		if !ok || err != nil || decodeErr != nil || seen[s.InstanceID] || s.PlanDigest != digest || !ed25519.Verify(key, CanonicalMaintenancePlan(e.Plan), sig) {
			return MaintenanceVerification{}, errors.New("invalid, duplicate or wrong-plan maintenance endorsement")
		}
		seen[s.InstanceID] = true
		result.Endorsed = append(result.Endorsed, s.InstanceID)
	}
	for id := range members {
		if !seen[id] {
			result.Missing = append(result.Missing, id)
		}
	}
	sort.Strings(result.Endorsed)
	sort.Strings(result.Missing)
	if len(result.Missing) == 0 {
		result.State = "reserved"
	}
	return result, nil
}
func (s *Store) MaintenancePolicy(now time.Time) (MaintenancePolicy, error) {
	var p MaintenancePolicy
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, "maintenance-policy.json"), 256<<10)
	if err != nil || strictJSON(raw, &p) != nil {
		return p, errors.New("install a private locally reviewed maintenance-policy.json")
	}
	return p, validateMaintenancePolicy(p, now)
}
func (s *Store) maintenanceIdentity() (MaintenanceMember, ed25519.PrivateKey, error) {
	var id maintenanceIdentity
	dir := filepath.Join(s.dir, "maintenance")
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return MaintenanceMember{}, nil, errors.New("maintenance identity unavailable; initialize locally")
	}
	raw, err := worker.ReadPrivateFile(filepath.Join(dir, "identity.json"), 4096)
	if err != nil || strictJSON(raw, &id) != nil || id.InstanceID != s.InstanceID() {
		return MaintenanceMember{}, nil, errors.New("maintenance identity differs from local instance")
	}
	seed, err := hex.DecodeString(id.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return MaintenanceMember{}, nil, errors.New("invalid maintenance identity")
	}
	key := ed25519.NewKeyFromSeed(seed)
	return MaintenanceMember{id.InstanceID, hex.EncodeToString(key.Public().(ed25519.PublicKey))}, key, nil
}
func (s *Store) maintenanceJournal(key ed25519.PrivateKey) (maintenanceJournal, error) {
	var journal maintenanceJournal
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, "maintenance", "journal.json"), 2<<20)
	if err != nil || strictJSON(raw, &journal) != nil || journal.SchemaVersion != 1 || len(journal.Reservations) > 256 {
		return journal, errors.New("maintenance journal missing or corrupt; never reset while reservations may exist")
	}
	seen := map[string]bool{}
	for _, e := range journal.Reservations {
		digest := maintenanceDigest(e.Plan)
		if len(e.Endorsements) != 1 || len(e.Plan.Windows) == 0 || len(e.Plan.Windows) > 32 || seen[digest] {
			return journal, errors.New("invalid maintenance journal entry")
		}
		v := e.Endorsements[0]
		if v.InstanceID != s.InstanceID() || v.PlanDigest != digest || !verifyLocalMaintenanceSignature(e, key) {
			return journal, errors.New("maintenance journal signature mismatch")
		}
		seen[digest] = true
	}
	return journal, nil
}
func verifyLocalMaintenanceSignature(e MaintenanceEnvelope, key ed25519.PrivateKey) bool {
	sig, err := hex.DecodeString(e.Endorsements[0].Signature)
	return err == nil && ed25519.Verify(key.Public().(ed25519.PublicKey), CanonicalMaintenancePlan(e.Plan), sig)
}
func (s *Store) InitializeMaintenance() (MaintenanceMember, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	dir := filepath.Join(s.dir, "maintenance")
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		m, key, err := s.maintenanceIdentity()
		if err != nil {
			return m, err
		}
		_, err = s.maintenanceJournal(key)
		return m, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return MaintenanceMember{}, err
	}
	temp, err := os.MkdirTemp(s.dir, ".maintenance-")
	if err != nil {
		return MaintenanceMember{}, err
	}
	defer os.RemoveAll(temp)
	raw, _ := json.Marshal(maintenanceIdentity{s.InstanceID(), hex.EncodeToString(seed)})
	if err := atomicFile(temp, "identity.json", raw); err != nil {
		return MaintenanceMember{}, err
	}
	raw, _ = json.Marshal(maintenanceJournal{1, []MaintenanceEnvelope{}})
	if err := atomicFile(temp, "journal.json", raw); err != nil {
		return MaintenanceMember{}, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return MaintenanceMember{}, err
	}
	if err := syscall.Rename(temp, dir); err != nil {
		os.Remove(dir)
		return MaintenanceMember{}, err
	}
	if err := syncDirectory(s.dir); err != nil {
		return MaintenanceMember{}, err
	}
	m, _, err := s.maintenanceIdentity()
	return m, err
}

// EndorseMaintenance stores the reservation before exposing its signature. The
// entire plan is reserved, even when this operator has no scheduled outage.
// Unanimity plus durable refusal of overlapping plans prevents a coordinator
// from producing conflicting fully endorsed schedules under one honest roster.
func (s *Store) EndorseMaintenance(plan MaintenancePlan, expectedDigest string, revision uint64, now time.Time) (MaintenanceEndorsement, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	var empty MaintenanceEndorsement
	policy, err := s.MaintenancePolicy(now)
	if err != nil {
		return empty, err
	}
	if err := validateMaintenancePlan(plan, policy, now); err != nil {
		return empty, err
	}
	if maintenanceDigest(plan) != expectedDigest {
		return empty, errors.New("maintenance plan differs from reviewed digest")
	}
	member, key, err := s.maintenanceIdentity()
	if err != nil {
		return empty, err
	}
	matched := false
	for _, m := range policy.Members {
		if m == member {
			matched = true
		}
	}
	if !matched {
		return empty, errors.New("local maintenance identity is absent from reviewed policy")
	}
	journal, err := s.maintenanceJournal(key)
	if err != nil {
		return empty, err
	}
	// Lock current approval and revision until the durable vote is committed.
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range plan.Windows {
		if w.InstanceID == s.InstanceID() {
			approved := false
			for _, a := range s.data.Approvals {
				if a.InstanceID == s.InstanceID() && a.Component == "validator" && a.Digest == w.ReleaseDigest && !a.Revoked && !w.Start.Before(a.WindowStart) && !w.End.After(a.WindowEnd) {
					approved = true
				}
			}
			if !approved {
				return empty, errors.New("own maintenance window requires matching current local release approval")
			}
		}
	}
	for _, old := range journal.Reservations {
		if maintenanceDigest(old.Plan) == expectedDigest {
			return old.Endorsements[0], nil
		}
		oldStart, oldEnd := old.Plan.Windows[0].Start, old.Plan.Windows[len(old.Plan.Windows)-1].End
		start, end := plan.Windows[0].Start, plan.Windows[len(plan.Windows)-1].End
		if start.Before(oldEnd) && oldStart.Before(end) {
			return empty, errors.New("another locally endorsed plan already reserves this interval")
		}
	}
	if revision != s.data.Revision {
		return empty, errors.New("operator revision changed; review maintenance plan again")
	}
	if !now.Before(plan.Windows[0].Start) {
		return empty, errors.New("new maintenance endorsements must precede the first window")
	}
	if len(journal.Reservations) >= 256 {
		return empty, errors.New("maintenance journal full; reviewed retention required")
	}
	endorsement := MaintenanceEndorsement{s.InstanceID(), expectedDigest, hex.EncodeToString(ed25519.Sign(key, CanonicalMaintenancePlan(plan)))}
	journal.Reservations = append(journal.Reservations, MaintenanceEnvelope{plan, []MaintenanceEndorsement{endorsement}})
	raw, _ := json.Marshal(journal)
	if len(raw) > 2<<20 {
		return empty, errors.New("maintenance journal size limit reached")
	}
	if err := s.recordLifecycleLocked("maintenance plan endorsed: "+expectedDigest, ""); err != nil {
		return empty, err
	}
	if err := atomicFile(filepath.Join(s.dir, "maintenance"), "journal.json", raw); err != nil {
		return empty, errors.New("cannot persist maintenance reservation; no signature returned")
	}
	return endorsement, nil
}
func ReadMaintenanceEnvelope(path string) (MaintenanceEnvelope, error) {
	var e MaintenanceEnvelope
	raw, err := worker.ReadPrivateFile(path, 256<<10)
	if err != nil || strictJSON(raw, &e) != nil {
		return e, errors.New("maintenance envelope must be a private bounded JSON file")
	}
	return e, nil
}

type EndorseMaintenanceRequest struct {
	Envelope         MaintenanceEnvelope `json:"envelope"`
	Digest           string              `json:"digest"`
	ExpectedRevision uint64              `json:"expectedRevision"`
}

func (s *Store) EndorseMaintenanceEnvelope(req EndorseMaintenanceRequest, now time.Time) (MaintenanceEnvelope, error) {
	policy, err := s.MaintenancePolicy(now)
	if err != nil {
		return MaintenanceEnvelope{}, err
	}
	if _, err := VerifyMaintenance(req.Envelope, policy, now); err != nil {
		return MaintenanceEnvelope{}, err
	}
	endorsement, err := s.EndorseMaintenance(req.Envelope.Plan, req.Digest, req.ExpectedRevision, now)
	if err != nil {
		return MaintenanceEnvelope{}, err
	}
	for _, e := range req.Envelope.Endorsements {
		if e.InstanceID == endorsement.InstanceID {
			return req.Envelope, nil
		}
	}
	result := req.Envelope
	result.Endorsements = append(result.Endorsements, endorsement)
	return result, nil
}
func (s *Store) MaintenanceState(now time.Time) map[string]interface{} {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	revision, _, _ := s.Summary()
	result := map[string]interface{}{"revision": revision, "initialized": false, "policyConfigured": false, "reservations": []MaintenanceEnvelope{}}
	member, key, err := s.maintenanceIdentity()
	if err == nil {
		journal, journalErr := s.maintenanceJournal(key)
		if journalErr == nil {
			result["initialized"] = true
			result["member"] = member
			result["reservations"] = journal.Reservations
		} else {
			result["identityError"] = journalErr.Error()
		}
	} else {
		result["identityError"] = err.Error()
	}
	if policy, err := s.MaintenancePolicy(now); err == nil {
		result["policyConfigured"] = true
		result["policy"] = policy
		result["policyDigest"] = MaintenancePolicyDigest(policy)
	} else {
		result["policyError"] = err.Error()
	}
	return result
}
