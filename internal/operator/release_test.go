package operator

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureRelease(t *testing.T, now time.Time) (SignedRelease, ReleaseTrust) {
	t.Helper()
	content := []byte("synthetic artifact, not executable")
	hash := sha256.Sum256(content)
	m := ReleaseManifest{SchemaVersion: 1, ID: "security-fixture", Component: "validator", Version: "1.0.1", Sequence: 2, Channel: "candidate", SourceCommit: strings.Repeat("a", 40), CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339), CompatibleFrom: []string{"1.0.0"}, ConfigSchema: 1, DatabaseSchema: 1, SigningCodec: "fixture-v1", MixedVersionsSafe: true, Recovery: "Test fixture only: stop replacement before restarting predecessor.", TestEvidence: []string{"synthetic test report sha256:" + strings.Repeat("1", 64)}, Artifacts: []ReleaseArtifact{{"linux-arm64", hex.EncodeToString(hash[:]), uint64(len(content))}}}
	raw, _ := CanonicalRelease(m)
	signed := SignedRelease{Manifest: m}
	trust := ReleaseTrust{1, 2, map[string]string{}}
	for i := byte(1); i <= 2; i++ {
		seed := make([]byte, 32)
		seed[31] = i
		key := ed25519.NewKeyFromSeed(seed)
		id := string(rune('a' + i - 1))
		trust.Publishers[id] = hex.EncodeToString(key.Public().(ed25519.PublicKey))
		signed.Signatures = append(signed.Signatures, ReleaseSignature{id, hex.EncodeToString(ed25519.Sign(key, raw))})
	}
	return signed, trust
}

func TestReleaseProvenanceIsNotActivationAuthority(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	release, trust := fixtureRelease(t, now)
	verified, err := VerifyRelease(release, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckActivation(ReleaseApproval{}, verified, "another-instance", now); err == nil {
		t.Fatal("publisher signatures granted installation authority")
	}
	if err := VerifyArtifact(release.Manifest.Artifacts[0], []byte("synthetic artifact, not executable")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(release.Manifest.Artifacts[0], []byte("tampered")); err == nil {
		t.Fatal("accepted tampered binary")
	}
	for _, tc := range []struct {
		name   string
		change func(*SignedRelease, *ReleaseTrust)
	}{
		{"payload changed", func(s *SignedRelease, _ *ReleaseTrust) { s.Manifest.Version = "1.0.2" }},
		{"insufficient publishers", func(s *SignedRelease, _ *ReleaseTrust) { s.Signatures = s.Signatures[:1] }},
		{"duplicate publisher", func(s *SignedRelease, _ *ReleaseTrust) { s.Signatures[1] = s.Signatures[0] }},
		{"publisher key aliases", func(s *SignedRelease, p *ReleaseTrust) {
			p.Publishers["b"] = p.Publishers["a"]
			s.Signatures[1].Signature = s.Signatures[0].Signature
		}},
		{"unknown publisher", func(s *SignedRelease, _ *ReleaseTrust) { s.Signatures[0].Publisher = "untrusted" }},
		{"unsigned metadata", func(s *SignedRelease, _ *ReleaseTrust) { s.Manifest.MixedVersionsSafe = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := fixtureRelease(t, now)
			tc.change(&s, &p)
			if _, err := VerifyRelease(s, p, now); err == nil {
				t.Fatal("accepted invalid release")
			}
		})
	}
	if _, err := VerifyRelease(release, trust, now.Add(49*time.Hour)); err == nil {
		t.Fatal("accepted expired release")
	}
}

func TestLocalReleaseApprovalPersistedScopedRevocable(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	release, trust := fixtureRelease(t, now)
	verified, _ := VerifyRelease(release, trust, now)
	dir := privateDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(trust)
	if err := os.WriteFile(filepath.Join(dir, "release-trust.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	req := ApproveRelease{s.InstanceID(), 0, release, verified.Digest, now, now.Add(time.Hour)}
	approval, err := s.ApproveRelease(req, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckActivation(approval, verified, "other-operator", now); err == nil {
		t.Fatal("approval applied to another instance")
	}
	if err := CheckActivation(approval, verified, s.InstanceID(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := CheckActivation(approval, verified, s.InstanceID(), now.Add(2*time.Hour)); err == nil {
		t.Fatal("ignored activation window")
	}
	changed := verified
	changed.Digest = strings.Repeat("f", 64)
	if err := CheckActivation(approval, changed, s.InstanceID(), now); err == nil {
		t.Fatal("approval covered a different release")
	}
	req.ExpectedRevision = 1
	if _, err := s.ApproveRelease(req, now); err == nil {
		t.Fatal("replayed already approved sequence")
	}
	s.Close()
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.ReleaseApprovals()) != 1 {
		t.Fatal("approval lost across restart")
	}
	if err := s.RevokeRelease(approval.Digest, 1, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckActivation(s.ReleaseApprovals()[0], verified, s.InstanceID(), now); err == nil {
		t.Fatal("revoked approval still active")
	}
	other, err := OpenStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if len(other.ReleaseApprovals()) != 0 {
		t.Fatal("one operator approval affected another operator")
	}
	if _, err := other.ApproveRelease(req, now); err == nil {
		t.Fatal("release installed publisher trust remotely")
	}
}

func TestLegacyActualNetworkIdentityIsNotInSignedDomain(t *testing.T) {
	v := vectors(t)[0]
	a, _ := EncodeAction(v.Profile, v.Action)
	other := v.Profile
	other.NetworkID = "31338"
	b, _ := EncodeAction(other, v.Action)
	if a.Digest != b.Digest {
		t.Fatal("codec unexpectedly changed legacy signing domain")
	}
	if a.ProfileDigest == b.ProfileDigest {
		t.Fatal("off-chain profile context failed to distinguish networks")
	}
	// This documents a legacy limitation, not a passing on-chain replay defense.
	// Network/profile validation cannot change what an existing contract signs.
}
