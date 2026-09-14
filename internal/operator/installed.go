package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

const installedReleaseFile = "installed-release.json"

type InstalledRelease struct {
	SchemaVersion          int       `json:"schemaVersion"`
	InstanceID             string    `json:"instanceId"`
	Digest                 string    `json:"digest"`
	Component              string    `json:"component"`
	Version                string    `json:"version"`
	Sequence               uint64    `json:"sequence"`
	Platform               string    `json:"platform"`
	ArtifactSHA256         string    `json:"artifactSha256"`
	SourceCommit           string    `json:"sourceCommit"`
	ConfigSchema           uint32    `json:"configSchema"`
	DatabaseSchema         uint32    `json:"databaseSchema"`
	SigningCodec           string    `json:"signingCodec"`
	MixedVersionsSafe      bool      `json:"mixedVersionsSafe"`
	RegistrationDigest     string    `json:"registrationDigest"`
	RegisteredConfigSHA256 string    `json:"registeredConfigSha256"`
	RecordedAt             time.Time `json:"recordedAt"`
	State                  string    `json:"state"`
}

type ReleaseCompatibility struct {
	State            string   `json:"state"`
	RollingUpdate    bool     `json:"rollingUpdate"`
	CurrentVersion   string   `json:"currentVersion,omitempty"`
	CandidateVersion string   `json:"candidateVersion"`
	Reasons          []string `json:"reasons"`
}

func validateInstalledRelease(r InstalledRelease) error {
	if r.SchemaVersion != 1 || !slug.MatchString(r.InstanceID) || !hexHash.MatchString(r.Digest) || r.Component != "validator" || !versionPattern.MatchString(r.Version) || r.Sequence == 0 || r.Sequence > 9007199254740991 {
		return errors.New("invalid installed release identity")
	}
	if r.Platform != "linux-amd64" && r.Platform != "linux-arm64" && r.Platform != "darwin-arm64" {
		return errors.New("invalid installed validator platform")
	}
	if !hexHash.MatchString(r.ArtifactSHA256) || !commitPattern.MatchString(r.SourceCommit) || r.ConfigSchema == 0 || r.DatabaseSchema == 0 || r.SigningCodec == "" || len(r.SigningCodec) > 128 {
		return errors.New("installed release lacks exact compatibility metadata")
	}
	if !hexHash.MatchString(r.RegistrationDigest) || !hexHash.MatchString(r.RegisteredConfigSHA256) || r.RecordedAt.IsZero() || (r.State != "adopted-existing" && r.State != "installed") {
		return errors.New("invalid installed release binding")
	}
	return nil
}

func (s *Store) registeredReleaseBinding(expectedArtifact string) (WorkerRegistration, error) {
	registration, err := s.registration()
	if err != nil {
		return registration, errors.New("a valid registered worker is required before recording its release")
	}
	if registration.BinarySHA256 != expectedArtifact {
		return registration, errors.New("staged release artifact does not match the registered worker binary")
	}
	config, parsed, err := workerConfig(registration.BaseDir)
	if err != nil {
		return registration, err
	}
	configHash := sha256.Sum256(config)
	if hex.EncodeToString(configHash[:]) != registration.ConfigSHA256 || parsed.Bridge.InstanceID != registration.InstanceID {
		return registration, errors.New("worker configuration changed since local registration")
	}
	binary, err := worker.ReadPrivateFile(filepath.Join(s.dir, "worker-bin", registration.BinarySHA256), maxStagedArtifact)
	if err != nil {
		return registration, err
	}
	binaryHash := sha256.Sum256(binary)
	if hex.EncodeToString(binaryHash[:]) != registration.BinarySHA256 {
		return registration, errors.New("registered worker binary changed since local review")
	}
	return registration, nil
}

func (s *Store) currentRelease() (*InstalledRelease, error) {
	path := filepath.Join(s.dir, installedReleaseFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, errors.New("current validator release is not recorded; stage and locally adopt the exact registered binary release")
	}
	raw, err := worker.ReadPrivateFile(path, 32768)
	if err != nil {
		return nil, errors.New("installed release record is unavailable or unsafe")
	}
	var current InstalledRelease
	if strictJSON(raw, &current) != nil || validateInstalledRelease(current) != nil {
		return nil, errors.New("installed release record is invalid; restore it from reviewed local evidence")
	}
	if current.InstanceID != s.InstanceID() {
		return nil, errors.New("installed release record belongs to another operator instance")
	}
	registration, err := s.registeredReleaseBinding(current.ArtifactSHA256)
	if err != nil {
		return nil, err
	}
	if registrationDigest(registration) != current.RegistrationDigest || registration.ConfigSHA256 != current.RegisteredConfigSHA256 {
		return nil, errors.New("worker registration changed after the installed release was recorded")
	}
	return &current, nil
}

// CurrentRelease verifies the durable release identity against the current
// pinned worker and configuration. It deliberately does not reapply publisher
// expiry or trust rotation: those policies govern future releases, while the
// operator must retain an honest identity for software it is already running.
func (s *Store) CurrentRelease() (*InstalledRelease, error) {
	return s.currentRelease()
}

// AdoptInstalledRelease is a local-CLI-only bootstrap operation. It binds an
// already registered worker to an exact signed and staged release; it never
// installs bytes and cannot replace an existing release identity.
func (s *Store) AdoptInstalledRelease(digest, platform string, now time.Time) (*InstalledRelease, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	s.workerMu.Lock()
	defer s.workerMu.Unlock()

	staged, err := s.loadStaged(digest, platform, now)
	if err != nil {
		return nil, err
	}
	manifest := staged.Release.Manifest
	if manifest.Component != "validator" || platform == "web" {
		return nil, errors.New("only a validator executable release can identify the registered worker")
	}
	registration, err := s.registeredReleaseBinding(staged.Artifact.SHA256)
	if err != nil {
		return nil, err
	}

	if _, err := os.Lstat(filepath.Join(s.dir, installedReleaseFile)); err == nil {
		current, loadErr := s.currentRelease()
		if loadErr != nil {
			return nil, loadErr
		}
		if current.Digest == digest && current.Platform == platform && current.ArtifactSHA256 == staged.Artifact.SHA256 {
			return current, nil
		}
		return nil, errors.New("an installed release is already recorded; adoption cannot replace it")
	} else if !os.IsNotExist(err) {
		return nil, errors.New("installed release path is unavailable")
	}

	current := InstalledRelease{
		SchemaVersion:          1,
		InstanceID:             s.InstanceID(),
		Digest:                 digest,
		Component:              manifest.Component,
		Version:                manifest.Version,
		Sequence:               manifest.Sequence,
		Platform:               platform,
		ArtifactSHA256:         staged.Artifact.SHA256,
		SourceCommit:           manifest.SourceCommit,
		ConfigSchema:           manifest.ConfigSchema,
		DatabaseSchema:         manifest.DatabaseSchema,
		SigningCodec:           manifest.SigningCodec,
		MixedVersionsSafe:      manifest.MixedVersionsSafe,
		RegistrationDigest:     registrationDigest(registration),
		RegisteredConfigSHA256: registration.ConfigSHA256,
		RecordedAt:             now.UTC(),
		State:                  "adopted-existing",
	}
	if err := validateInstalledRelease(current); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicFile(s.dir, installedReleaseFile, raw); err != nil {
		return nil, errors.New("cannot persist installed release identity")
	}
	return &current, nil
}

func EvaluateReleaseCompatibility(current *InstalledRelease, candidateDigest string, candidate ReleaseManifest) ReleaseCompatibility {
	result := ReleaseCompatibility{State: "baseline-required", CandidateVersion: candidate.Version, Reasons: []string{}}
	if current == nil {
		result.Reasons = append(result.Reasons, "Record the exact current validator release before evaluating an update.")
		return result
	}
	result.CurrentVersion = current.Version
	if candidateDigest == current.Digest {
		result.State = "already-installed"
		result.Reasons = append(result.Reasons, "This staged release matches the recorded current validator release.")
		return result
	}
	if candidate.Component != "validator" {
		result.Reasons = append(result.Reasons, "The staged component is not a validator release.")
	}
	if candidate.Sequence <= current.Sequence {
		result.Reasons = append(result.Reasons, "The release sequence is not newer than the recorded validator release; reviewed recovery is required.")
	}
	predecessor := false
	for _, version := range candidate.CompatibleFrom {
		if version == current.Version {
			predecessor = true
			break
		}
	}
	if !predecessor {
		result.Reasons = append(result.Reasons, "The publisher did not declare the recorded version as a compatible predecessor.")
	}
	if candidate.ConfigSchema != current.ConfigSchema {
		result.Reasons = append(result.Reasons, "The configuration schema changes and requires a coordinated migration plan.")
	}
	if candidate.DatabaseSchema != current.DatabaseSchema {
		result.Reasons = append(result.Reasons, "The database schema changes and requires backup and recovery review.")
	}
	if candidate.SigningCodec != current.SigningCodec {
		result.Reasons = append(result.Reasons, "The signing codec changes and cannot use an ordinary rolling update.")
	}
	if !candidate.MixedVersionsSafe {
		result.Reasons = append(result.Reasons, "The release does not declare mixed validator versions safe.")
	}
	if len(result.Reasons) > 0 {
		result.State = "coordinated-update-required"
		return result
	}
	result.State = "rolling-update-compatible"
	result.RollingUpdate = true
	result.Reasons = append(result.Reasons, "Signed compatibility metadata permits rolling qualification from the recorded release; local testing, approval and activation checks are still required.")
	return result
}
