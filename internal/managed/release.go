package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// InstalledVerifier joins independently verified chain evidence to the exact
// running executable, configuration bytes, publisher policy and local approval.
// It accepts no artifact or approval booleans from a network response.
type InstalledVerifier struct {
	root       string
	trust      string
	config     string
	candidate  string
	executable string
	chain      Verifier
}

func NewInstalledVerifier(root, trust, config, candidate string, chain Verifier) (*InstalledVerifier, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(trust) || !filepath.IsAbs(config) || !filepath.IsAbs(candidate) || chain == nil {
		return nil, errors.New("absolute local evidence paths and chain verifier required")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, errors.New("running executable unavailable")
	}
	return &InstalledVerifier{root, trust, config, candidate, executable, chain}, nil
}
func fileDigest(path string, max int64) (string, error) {
	raw, err := worker.ReadPrivateFile(path, max)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
func (v *InstalledVerifier) Inspect(ctx context.Context, p Policy) (Evidence, error) {
	if ctx.Err() != nil {
		return Evidence{}, ctx.Err()
	}
	raw, err := worker.ReadPrivateFile(v.trust, 65536)
	if err != nil {
		return Evidence{}, errors.New("publisher policy unavailable")
	}
	var trust operator.ReleaseTrust
	if host.JSON(raw, &trust) != nil {
		return Evidence{}, errors.New("publisher policy invalid")
	}
	installation, err := host.Authorize(v.root, trust, p.Instance, time.Now())
	if err != nil {
		return Evidence{}, errors.New("installed release or local approval is no longer valid")
	}
	artifact, err := fileDigest(v.executable, host.MaxBundle)
	if err != nil || artifact != p.ArtifactSHA256 {
		return Evidence{}, errors.New("running executable differs from signer policy")
	}
	bundled := false
	for name, hash := range installation.Files {
		if name != "vortex-operator.service" && hash == artifact {
			bundled = true
		}
	}
	if !bundled {
		return Evidence{}, errors.New("running executable is not part of approved bundle")
	}
	config, err := fileDigest(v.config, 128<<10)
	if err != nil || config != p.ConfigSHA256 {
		return Evidence{}, errors.New("configuration differs from signer policy")
	}
	candidateExpiry, err := checkCandidate(v.candidate, v.root, installation, trust, time.Now())
	if err != nil {
		return Evidence{}, err
	}
	e, err := v.chain.Inspect(ctx, p)
	if err != nil || ctx.Err() != nil {
		return Evidence{}, errors.New("live chain verification failed")
	}
	// Local approval may expire during the chain query; cap the evidence lifetime.
	now := time.Now()
	releaseExpiry, parseErr := time.Parse(time.RFC3339, installation.Release.Manifest.ExpiresAt)
	if parseErr != nil || !now.Before(candidateExpiry) || !now.Before(releaseExpiry) || !now.Before(installation.Approval.WindowEnd) || now.Before(installation.Approval.WindowStart) {
		return Evidence{}, errors.New("local approval expired during chain verification")
	}
	if e.ExpiresAt.After(candidateExpiry) {
		e.ExpiresAt = candidateExpiry
	}
	if e.ExpiresAt.After(releaseExpiry) {
		e.ExpiresAt = releaseExpiry
	}
	if e.ExpiresAt.After(installation.Approval.WindowEnd) {
		e.ExpiresAt = installation.Approval.WindowEnd
	}
	e.ReleaseApproved = true // Set only after local cryptographic/byte checks above.
	return e, nil
}
func (v *InstalledVerifier) Reconcile(ctx context.Context, p Policy, j Journal) (string, error) {
	return v.chain.Reconcile(ctx, p, j)
}
func (v *InstalledVerifier) Operation(ctx context.Context, p Policy, id string) (Operation, error) {
	return v.chain.Operation(ctx, p, id)
}
