package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

const maxStagedArtifact = 256 * 1024 * 1024

type StagedRelease struct {
	Digest   string          `json:"digest"`
	Platform string          `json:"platform"`
	Artifact ReleaseArtifact `json:"artifact"`
	Release  SignedRelease   `json:"release"`
	StagedAt time.Time       `json:"stagedAt"`
}
type StagedSummary struct {
	Candidate      *CandidateResult `json:"candidate,omitempty"`
	Digest         string           `json:"digest"`
	Platform       string           `json:"platform"`
	Version        string           `json:"version"`
	Component      string           `json:"component"`
	ArtifactSHA256 string           `json:"artifactSha256"`
	StagedAt       time.Time        `json:"stagedAt"`
	State          string           `json:"state"`
	Message        string           `json:"message"`
}

// OpenBoundedArtifact rejects non-regular files and symlinks before reading any
// bytes. A single file descriptor is retained for copying and hashing.
func OpenBoundedArtifact(path string, max int64) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("artifact file unavailable")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > max {
		f.Close()
		return nil, errors.New("artifact must be a bounded regular file")
	}
	return f, nil
}
func ReadSignedRelease(path string) (SignedRelease, error) {
	f, err := OpenBoundedArtifact(path, 128*1024)
	if err != nil {
		return SignedRelease{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 128*1024+1))
	if err != nil || len(b) > 128*1024 {
		return SignedRelease{}, errors.New("release file unreadable or oversized")
	}
	var release SignedRelease
	if err := strictJSON(b, &release); err != nil {
		return release, errors.New("invalid signed release JSON")
	}
	return release, nil
}
func stagedPlatform(m ReleaseManifest, platform string) (ReleaseArtifact, error) {
	for _, a := range m.Artifacts {
		if a.Platform == platform {
			return a, nil
		}
	}
	return ReleaseArtifact{}, errors.New("signed release has no artifact for selected platform")
}
func (s *Store) StageRelease(release SignedRelease, platform, source string, now time.Time) (StagedRelease, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	trust, err := s.ReleaseTrust()
	if err != nil {
		return StagedRelease{}, err
	}
	verified, err := VerifyRelease(release, trust, now)
	if err != nil {
		return StagedRelease{}, err
	}
	artifact, err := stagedPlatform(release.Manifest, platform)
	if err != nil {
		return StagedRelease{}, err
	}
	if artifact.Size > maxStagedArtifact {
		return StagedRelease{}, errors.New("artifact exceeds local 256 MiB staging limit")
	}
	f, err := OpenBoundedArtifact(source, maxStagedArtifact)
	if err != nil {
		return StagedRelease{}, err
	}
	defer f.Close()
	root := filepath.Join(s.dir, "releases")
	if err := worker.PrivateDir(root); err != nil {
		return StagedRelease{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return StagedRelease{}, err
	}
	if len(entries) >= 16 {
		if _, err := os.Stat(filepath.Join(root, verified.Digest)); err != nil {
			return StagedRelease{}, errors.New("staging store full; local reviewed retention required")
		}
	}
	parent := filepath.Join(root, verified.Digest)
	if err := worker.PrivateDir(parent); err != nil {
		return StagedRelease{}, err
	}
	destination := filepath.Join(parent, platform)
	if _, err := os.Lstat(destination); err == nil {
		return s.loadStaged(verified.Digest, platform, now)
	} else if !os.IsNotExist(err) {
		return StagedRelease{}, err
	}
	temp, err := os.MkdirTemp(parent, ".staging-")
	if err != nil {
		return StagedRelease{}, err
	}
	defer os.RemoveAll(temp)
	target, err := os.OpenFile(filepath.Join(temp, "artifact"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		return StagedRelease{}, err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(target, hash), io.LimitReader(f, int64(artifact.Size)+1))
	if err != nil || uint64(n) != artifact.Size || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		target.Close()
		return StagedRelease{}, errors.New("staged artifact bytes differ from signed length or SHA-256")
	}
	if err = target.Sync(); err != nil {
		target.Close()
		return StagedRelease{}, err
	}
	if err = target.Close(); err != nil {
		return StagedRelease{}, err
	}
	record := StagedRelease{verified.Digest, platform, artifact, release, now}
	encoded, _ := json.Marshal(record)
	if err := atomicFile(temp, "release.json", encoded); err != nil {
		return StagedRelease{}, err
	}
	if err := os.Rename(temp, destination); err != nil {
		return StagedRelease{}, err
	}
	fd, err := os.Open(parent)
	if err != nil {
		return StagedRelease{}, err
	}
	err = fd.Sync()
	fd.Close()
	if err != nil {
		return StagedRelease{}, err
	}
	return record, nil
}
func (s *Store) loadStaged(digest, platform string, now time.Time, verifyBytes ...bool) (StagedRelease, error) {
	if !hexHash.MatchString(digest) || !(platform == "linux-arm64" || platform == "linux-amd64" || platform == "darwin-arm64" || platform == "web") {
		return StagedRelease{}, errors.New("invalid staged release identity")
	}
	directory := filepath.Join(s.dir, "releases", digest, platform)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return StagedRelease{}, errors.New("staged release unavailable")
	}
	b, err := worker.ReadPrivateFile(filepath.Join(directory, "release.json"), 128*1024)
	if err != nil {
		return StagedRelease{}, err
	}
	var record StagedRelease
	if strictJSON(b, &record) != nil || record.Digest != digest || record.Platform != platform {
		return record, errors.New("staged release metadata mismatch")
	}
	trust, err := s.ReleaseTrust()
	if err != nil {
		return record, err
	}
	verified, err := VerifyRelease(record.Release, trust, now)
	if err != nil {
		return record, err
	}
	expected, err := stagedPlatform(verified.Manifest, platform)
	if err != nil || verified.Digest != digest || record.Artifact != expected || expected.Size > maxStagedArtifact {
		return record, errors.New("staged artifact identity mismatch")
	}
	if len(verifyBytes) > 0 && !verifyBytes[0] {
		return record, nil
	}
	f, err := OpenBoundedArtifact(filepath.Join(directory, "artifact"), maxStagedArtifact)
	if err != nil {
		return record, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, int64(expected.Size)+1))
	if err != nil || uint64(n) != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
		return record, errors.New("staged artifact was corrupted or replaced")
	}
	return record, nil
}
func (s *Store) StagedReleases(now time.Time) []StagedSummary {
	summaries := []StagedSummary{}
	entries, err := os.ReadDir(filepath.Join(s.dir, "releases"))
	if err != nil {
		return summaries
	}
	for _, entry := range entries {
		if !entry.IsDir() || !hexHash.MatchString(entry.Name()) {
			continue
		}
		platforms, _ := os.ReadDir(filepath.Join(s.dir, "releases", entry.Name()))
		for _, platform := range platforms {
			if !platform.IsDir() || platform.Name()[0] == '.' {
				continue
			}
			record, err := s.loadStaged(entry.Name(), platform.Name(), now, false)
			if err != nil {
				summaries = append(summaries, StagedSummary{Digest: entry.Name(), Platform: platform.Name(), State: "blocked", Message: "Staged artifact or current publisher policy failed verification."})
				continue
			}
			summaries = append(summaries, StagedSummary{Candidate: s.candidateResult(record.Digest, record.Platform, record.Artifact.SHA256), Digest: record.Digest, Platform: record.Platform, Version: record.Release.Manifest.Version, Component: record.Release.Manifest.Component, ArtifactSHA256: record.Artifact.SHA256, StagedAt: record.StagedAt, State: "staged", Message: "Manifest verified against current publisher policy. Bytes must be rechecked before candidate testing or activation."})
		}
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Digest == summaries[j].Digest {
			return summaries[i].Platform < summaries[j].Platform
		}
		return summaries[i].Digest < summaries[j].Digest
	})
	return summaries
}
