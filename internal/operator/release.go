package operator

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// CanonicalRelease is the signed byte representation. External tools must use
// these exact bytes (available from the CLI), not serialize maps independently.
type ReleaseManifest struct {
	SchemaVersion     int               `json:"schemaVersion"`
	ID                string            `json:"id"`
	Component         string            `json:"component"`
	Version           string            `json:"version"`
	Sequence          uint64            `json:"sequence"`
	Channel           string            `json:"channel"`
	SourceCommit      string            `json:"sourceCommit"`
	CreatedAt         string            `json:"createdAt"`
	ExpiresAt         string            `json:"expiresAt"`
	CompatibleFrom    []string          `json:"compatibleFrom"`
	ConfigSchema      uint32            `json:"configSchema"`
	DatabaseSchema    uint32            `json:"databaseSchema"`
	SigningCodec      string            `json:"signingCodec"`
	MixedVersionsSafe bool              `json:"mixedVersionsSafe"`
	Recovery          string            `json:"recovery"`
	TestEvidence      []string          `json:"testEvidence"`
	Artifacts         []ReleaseArtifact `json:"artifacts"`
}
type ReleaseArtifact struct {
	Platform string `json:"platform"`
	SHA256   string `json:"sha256"`
	Size     uint64 `json:"size"`
}
type ReleaseSignature struct {
	Publisher string `json:"publisher"`
	Signature string `json:"signature"`
}
type SignedRelease struct {
	Manifest   ReleaseManifest    `json:"manifest"`
	Signatures []ReleaseSignature `json:"signatures"`
}
type ReleaseTrust struct {
	SchemaVersion      int               `json:"schemaVersion"`
	RequiredSignatures int               `json:"requiredSignatures"`
	Publishers         map[string]string `json:"publishers"` // ed25519 public keys in hex
}
type ReleaseVerification struct {
	Digest     string          `json:"digest"`
	Publishers []string        `json:"publishers"`
	Manifest   ReleaseManifest `json:"manifest"`
	State      string          `json:"state"`
	Notice     string          `json:"notice"`
}

func CanonicalRelease(m ReleaseManifest) ([]byte, error) { return json.Marshal(m) }

func VerifyRelease(signed SignedRelease, trust ReleaseTrust, now time.Time) (ReleaseVerification, error) {
	m := signed.Manifest
	if m.SchemaVersion != 1 || !slug.MatchString(m.ID) || !versionPattern.MatchString(m.Version) || m.Sequence == 0 || m.Sequence > 9007199254740991 {
		return ReleaseVerification{}, errors.New("invalid release schema, id, version or sequence")
	}
	if m.Component != "validator" && m.Component != "operator" && m.Component != "interface" {
		return ReleaseVerification{}, errors.New("unsupported release component")
	}
	if m.Channel != "candidate" && m.Channel != "stable" && m.Channel != "emergency" {
		return ReleaseVerification{}, errors.New("unsupported release channel")
	}
	if !commitPattern.MatchString(m.SourceCommit) || m.ConfigSchema == 0 || m.DatabaseSchema == 0 || m.SigningCodec == "" || len(m.SigningCodec) > 128 {
		return ReleaseVerification{}, errors.New("release requires exact source and compatibility metadata")
	}
	created, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return ReleaseVerification{}, errors.New("invalid release creation time")
	}
	expiry, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil || !expiry.After(now) || !expiry.After(created) || created.After(now.Add(5*time.Minute)) {
		return ReleaseVerification{}, errors.New("release is expired or not yet valid")
	}
	if len(m.TestEvidence) == 0 || len(m.TestEvidence) > 32 || len(m.Recovery) == 0 || len(m.Recovery) > 8192 || len(m.CompatibleFrom) == 0 || len(m.CompatibleFrom) > 32 {
		return ReleaseVerification{}, errors.New("release requires bounded test evidence, predecessor versions and recovery instructions")
	}
	for _, e := range m.TestEvidence {
		if len(e) == 0 || len(e) > 1024 {
			return ReleaseVerification{}, errors.New("invalid test evidence reference")
		}
	}
	for _, v := range m.CompatibleFrom {
		if !versionPattern.MatchString(v) {
			return ReleaseVerification{}, errors.New("invalid predecessor version")
		}
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > 16 {
		return ReleaseVerification{}, errors.New("release requires platform artifacts")
	}
	platforms := map[string]bool{}
	for _, a := range m.Artifacts {
		if (a.Platform != "linux-amd64" && a.Platform != "linux-arm64" && a.Platform != "darwin-arm64" && a.Platform != "web") || platforms[a.Platform] || !hexHash.MatchString(a.SHA256) || a.Size == 0 || a.Size > 1<<30 {
			return ReleaseVerification{}, errors.New("invalid, duplicate or oversized release artifact")
		}
		platforms[a.Platform] = true
	}
	if trust.SchemaVersion != 1 || trust.RequiredSignatures < 1 || trust.RequiredSignatures > len(trust.Publishers) || len(trust.Publishers) > 32 {
		return ReleaseVerification{}, errors.New("no valid local publisher trust policy installed")
	}
	raw, err := CanonicalRelease(m)
	if err != nil {
		return ReleaseVerification{}, err
	}
	hash := sha256.Sum256(raw)
	if len(signed.Signatures) > 32 {
		return ReleaseVerification{}, errors.New("too many release signatures")
	}
	seen := map[string]bool{}
	publishers := []string{}
	keys := map[string]bool{}
	for _, s := range signed.Signatures {
		if seen[s.Publisher] {
			return ReleaseVerification{}, errors.New("duplicate publisher signature")
		}
		seen[s.Publisher] = true
		keyHex, known := trust.Publishers[s.Publisher]
		if !known {
			return ReleaseVerification{}, errors.New("untrusted release publisher")
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return ReleaseVerification{}, errors.New("invalid local publisher key")
		}
		if keys[string(key)] {
			return ReleaseVerification{}, errors.New("publisher aliases cannot count as independent keys")
		}
		keys[string(key)] = true
		sig, err := hex.DecodeString(s.Signature)
		if err != nil || !ed25519.Verify(key, raw, sig) {
			return ReleaseVerification{}, errors.New("release signature verification failed")
		}
		publishers = append(publishers, s.Publisher)
	}
	if len(publishers) < trust.RequiredSignatures {
		return ReleaseVerification{}, errors.New("publisher signature threshold not met")
	}
	return ReleaseVerification{hex.EncodeToString(hash[:]), publishers, m, "signature-verified", "Publisher provenance verified. Artifact bytes and test claims are not independently verified; installation still requires local approval and rollout preflight."}, nil
}

type ReleaseApproval struct {
	InstanceID  string    `json:"instanceId"`
	Digest      string    `json:"digest"`
	Component   string    `json:"component"`
	Version     string    `json:"version"`
	Sequence    uint64    `json:"sequence"`
	WindowStart time.Time `json:"windowStart"`
	WindowEnd   time.Time `json:"windowEnd"`
	ApprovedAt  time.Time `json:"approvedAt"`
	Revoked     bool      `json:"revoked"`
}
type ApproveRelease struct {
	InstanceID       string        `json:"instanceId"`
	ExpectedRevision uint64        `json:"expectedRevision"`
	Release          SignedRelease `json:"release"`
	Digest           string        `json:"digest"`
	WindowStart      time.Time     `json:"windowStart"`
	WindowEnd        time.Time     `json:"windowEnd"`
}

// Trust roots are loaded from a local operator-owned file. They cannot be
// supplied in the same HTTP request as the release they are supposed to trust.
func (s *Store) ReleaseTrust() (ReleaseTrust, error) {
	path := filepath.Join(s.dir, "release-trust.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 32768 {
		return ReleaseTrust{}, errors.New("install a private reviewed release-trust.json on the operator host before verifying publishers")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ReleaseTrust{}, errors.New("cannot read local publisher policy")
	}
	var trust ReleaseTrust
	if err := strictJSON(b, &trust); err != nil {
		return ReleaseTrust{}, errors.New("invalid local publisher policy")
	}
	return trust, nil
}

func (s *Store) ApproveRelease(req ApproveRelease, now time.Time) (ReleaseApproval, error) {
	if req.InstanceID != s.InstanceID() {
		return ReleaseApproval{}, errors.New("approval targets another operator instance")
	}
	trust, err := s.ReleaseTrust()
	if err != nil {
		return ReleaseApproval{}, err
	}
	verified, err := VerifyRelease(req.Release, trust, now)
	if err != nil {
		return ReleaseApproval{}, err
	}
	if verified.Digest != req.Digest {
		return ReleaseApproval{}, errors.New("release digest changed since review")
	}
	if req.WindowStart.Before(now.Add(-time.Minute)) || !req.WindowEnd.After(req.WindowStart) || !req.WindowEnd.After(now) || req.WindowEnd.Sub(req.WindowStart) > 24*time.Hour {
		return ReleaseApproval{}, errors.New("approval requires a current or future activation window of at most 24 hours")
	}
	expiry, _ := time.Parse(time.RFC3339, verified.Manifest.ExpiresAt)
	if req.WindowEnd.After(expiry) {
		return ReleaseApproval{}, errors.New("activation window outlives signed release")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Approvals) >= 256 {
		return ReleaseApproval{}, errors.New("approval ledger full; reviewed compaction required")
	}
	if req.ExpectedRevision != s.data.Revision {
		return ReleaseApproval{}, errors.New("operator revision changed; refresh before approval")
	}
	for _, old := range s.data.Approvals {
		if old.Component == verified.Manifest.Component && old.Sequence >= verified.Manifest.Sequence {
			return ReleaseApproval{}, errors.New("release sequence already approved or superseded; explicit reviewed recovery is required for downgrade")
		}
	}
	approval := ReleaseApproval{s.InstanceID(), verified.Digest, verified.Manifest.Component, verified.Manifest.Version, verified.Manifest.Sequence, req.WindowStart, req.WindowEnd, now, false}
	raw, _ := json.Marshal(s.data)
	var next diskState
	json.Unmarshal(raw, &next)
	next.Approvals = append(next.Approvals, approval)
	next.Revision++
	next.Events = append(next.Events, Event{now, "release locally approved: " + approval.Digest, "", next.Revision})
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return ReleaseApproval{}, err
	}
	if err := atomicFile(s.dir, "state.json", encoded); err != nil {
		return ReleaseApproval{}, errors.New("cannot persist approval")
	}
	s.data = next
	return approval, nil
}

func (s *Store) ReleaseApprovals() []ReleaseApproval {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ReleaseApproval{}, s.data.Approvals...)
}
func (s *Store) RevokeRelease(digest string, revision uint64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.data.Revision {
		return errors.New("operator revision changed")
	}
	raw, _ := json.Marshal(s.data)
	var next diskState
	json.Unmarshal(raw, &next)
	found := false
	for i, a := range next.Approvals {
		if a.Digest == digest {
			if a.Revoked {
				return nil
			}
			next.Approvals[i].Revoked = true
			found = true
		}
	}
	if !found {
		return errors.New("unknown local approval")
	}
	next.Revision++
	next.Events = append(next.Events, Event{now, "release approval revoked: " + digest, "", next.Revision})
	encoded, _ := json.MarshalIndent(next, "", "  ")
	if err := atomicFile(s.dir, "state.json", encoded); err != nil {
		return errors.New("cannot persist revocation")
	}
	s.data = next
	return nil
}

// CheckActivation is mandatory again immediately before an installer stops a
// process. Approval alone never means that an artifact was installed.
func CheckActivation(approval ReleaseApproval, release ReleaseVerification, instanceID string, now time.Time) error {
	if instanceID == "" || approval.InstanceID != instanceID || approval.Revoked || approval.Digest != release.Digest || approval.Component != release.Manifest.Component || approval.Sequence != release.Manifest.Sequence {
		return errors.New("no matching active local approval")
	}
	if now.Before(approval.WindowStart) || !now.Before(approval.WindowEnd) {
		return errors.New("outside locally approved activation window")
	}
	expiry, err := time.Parse(time.RFC3339, release.Manifest.ExpiresAt)
	if err != nil || !now.Before(expiry) {
		return errors.New("release expired before activation")
	}
	return nil
}

func VerifyArtifact(artifact ReleaseArtifact, content []byte) error {
	if uint64(len(content)) != artifact.Size {
		return errors.New("artifact length differs from release")
	}
	hash := sha256.Sum256(content)
	if hex.EncodeToString(hash[:]) != artifact.SHA256 {
		return fmt.Errorf("artifact hash differs from release")
	}
	return nil
}
