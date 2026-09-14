package operator

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installedFixture(t *testing.T, now time.Time) (*Store, SignedRelease, string) {
	t.Helper()
	release, trust := fixtureRelease(t, now)
	dir := privateDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	policy, _ := json.Marshal(trust)
	if err := os.WriteFile(filepath.Join(dir, "release-trust.json"), policy, 0600); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "validator")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	config := []byte("bridge:\n  instance-id: installed-fixture\n  observation-only: true\n")
	if err := os.WriteFile(filepath.Join(base, "config.yml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("synthetic artifact, not executable")
	artifactPath := filepath.Join(t.TempDir(), "validator")
	if err := os.WriteFile(artifactPath, artifact, 0500); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(artifact)
	if _, err := s.RegisterWorker(base, artifactPath, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	staged, err := s.StageRelease(release, "linux-arm64", artifactPath, now)
	if err != nil {
		t.Fatal(err)
	}
	return s, release, staged.Digest
}

func signedFixtureManifest(t *testing.T, manifest ReleaseManifest) SignedRelease {
	t.Helper()
	raw, err := CanonicalRelease(manifest)
	if err != nil {
		t.Fatal(err)
	}
	release := SignedRelease{Manifest: manifest}
	for i := byte(1); i <= 2; i++ {
		seed := make([]byte, 32)
		seed[31] = i
		key := ed25519.NewKeyFromSeed(seed)
		release.Signatures = append(release.Signatures, ReleaseSignature{Publisher: string(rune('a' + i - 1)), Signature: hex.EncodeToString(ed25519.Sign(key, raw))})
	}
	return release
}

func TestAdoptInstalledReleaseBindsExactRegisteredWorker(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	s, _, digest := installedFixture(t, now)
	current, err := s.AdoptInstalledRelease(digest, "linux-arm64", now)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != "adopted-existing" || current.Digest != digest || current.Version != "1.0.1" || current.RegistrationDigest == "" || current.RegisteredConfigSHA256 == "" {
		t.Fatalf("unexpected installed release: %+v", current)
	}
	info, err := os.Stat(filepath.Join(s.dir, installedReleaseFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("installed release identity is not a private durable file")
	}
	again, err := s.AdoptInstalledRelease(digest, "linux-arm64", now.Add(time.Minute))
	if err != nil || !again.RecordedAt.Equal(current.RecordedAt) {
		t.Fatal("idempotent adoption rewrote release identity", err)
	}
	// Publisher expiry or later trust rotation must not erase the identity of
	// bytes already pinned on this operator.
	if err := os.WriteFile(filepath.Join(s.dir, "release-trust.json"), []byte(`{"schemaVersion":1,"requiredSignatures":1,"publishers":{"retired":"`+strings.Repeat("0", 64)+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CurrentRelease(); err != nil || got.Digest != digest {
		t.Fatal("current release identity depended on future publisher policy", err)
	}
	registration, _ := s.registration()
	if err := os.WriteFile(filepath.Join(registration.BaseDir, "config.yml"), []byte("bridge:\n  instance-id: changed\n  observation-only: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CurrentRelease(); err == nil {
		t.Fatal("changed worker configuration retained a trusted current-release identity")
	}
}

func TestAdoptInstalledReleaseRefusesMismatchAndReplacement(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	s, release, digest := installedFixture(t, now)
	if _, err := s.AdoptInstalledRelease(digest, "linux-amd64", now); err == nil {
		t.Fatal("adopted an unstaged platform")
	}
	current, err := s.AdoptInstalledRelease(digest, "linux-arm64", now)
	if err != nil {
		t.Fatal(err)
	}
	second := release.Manifest
	second.ID = "replacement-fixture"
	second.Version = "1.0.2"
	second.Sequence = 3
	second.CompatibleFrom = []string{"1.0.1"}
	secondRelease := signedFixtureManifest(t, second)
	registration, _ := s.registration()
	artifact := filepath.Join(s.dir, "worker-bin", registration.BinarySHA256)
	staged, err := s.StageRelease(secondRelease, "linux-arm64", artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdoptInstalledRelease(staged.Digest, "linux-arm64", now); err == nil {
		t.Fatal("adoption replaced an existing release identity")
	}
	if after, err := s.CurrentRelease(); err != nil || after.Digest != current.Digest {
		t.Fatal("failed replacement changed current release", err)
	}
}

func TestReleaseCompatibilityFailsClosed(t *testing.T) {
	current := &InstalledRelease{Digest: strings.Repeat("1", 64), Component: "validator", Version: "1.0.1", Sequence: 2, ConfigSchema: 1, DatabaseSchema: 1, SigningCodec: "fixture-v1"}
	candidate := ReleaseManifest{Component: "validator", Version: "1.0.2", Sequence: 3, CompatibleFrom: []string{"1.0.1"}, ConfigSchema: 1, DatabaseSchema: 1, SigningCodec: "fixture-v1", MixedVersionsSafe: true}
	if result := EvaluateReleaseCompatibility(current, strings.Repeat("2", 64), candidate); result.State != "rolling-update-compatible" || !result.RollingUpdate {
		t.Fatalf("compatible rolling release blocked: %+v", result)
	}
	if result := EvaluateReleaseCompatibility(nil, strings.Repeat("2", 64), candidate); result.State != "baseline-required" || result.RollingUpdate {
		t.Fatalf("missing baseline accepted: %+v", result)
	}
	if result := EvaluateReleaseCompatibility(current, current.Digest, candidate); result.State != "already-installed" || result.RollingUpdate {
		t.Fatalf("same release offered as update: %+v", result)
	}
	changes := []func(*ReleaseManifest){
		func(m *ReleaseManifest) { m.Component = "operator" },
		func(m *ReleaseManifest) { m.Sequence = 2 },
		func(m *ReleaseManifest) { m.CompatibleFrom = []string{"1.0.0"} },
		func(m *ReleaseManifest) { m.ConfigSchema = 2 },
		func(m *ReleaseManifest) { m.DatabaseSchema = 2 },
		func(m *ReleaseManifest) { m.SigningCodec = "fixture-v2" },
		func(m *ReleaseManifest) { m.MixedVersionsSafe = false },
	}
	for i, change := range changes {
		changed := candidate
		change(&changed)
		result := EvaluateReleaseCompatibility(current, strings.Repeat("2", 64), changed)
		if result.State != "coordinated-update-required" || result.RollingUpdate || len(result.Reasons) == 0 {
			t.Fatalf("incompatible case %d accepted: %+v", i, result)
		}
	}
}

func TestUpdatesEndpointReportsInstalledIdentityAndCompatibility(t *testing.T) {
	now := time.Now().UTC()
	s, _, digest := installedFixture(t, now)
	if _, err := s.AdoptInstalledRelease(digest, "linux-arm64", now); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	server := NewServer(s, token, "operator.test", nil)
	req := httptest.NewRequest(http.MethodGet, "http://operator.test/v1/updates", nil)
	req.Host = "operator.test"
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("updates returned %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		InstalledVersion *InstalledRelease `json:"installedVersion"`
		InstalledProblem string            `json:"installedProblem"`
		InstallerEnabled bool              `json:"installerEnabled"`
		Staged           []StagedSummary   `json:"staged"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.InstalledVersion == nil || body.InstalledVersion.Digest != digest || body.InstalledProblem != "" || body.InstallerEnabled || len(body.Staged) != 1 || body.Staged[0].Compatibility == nil || body.Staged[0].Compatibility.State != "already-installed" {
		t.Fatalf("updates hid or overstated installed release: %+v", body)
	}
}
