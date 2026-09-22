package managed

import (
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

// UnsignedHostReviewRequest is deliberately incompatible with SignedHostReview.
// CanonicalHex contains the exact bytes an independent reviewer would sign after
// inspecting every referenced control record. Generating a request proves none.
type UnsignedHostReviewRequest struct {
	Review       HostReview `json:"review"`
	CanonicalHex string     `json:"canonicalHex"`
	Notice       string     `json:"notice"`
}

func draftHostReview(p Policy, evidence, profile, binding string, now time.Time) (UnsignedHostReviewRequest, error) {
	var out UnsignedHostReviewRequest
	if !filepath.IsAbs(evidence) || !validHash(binding) {
		return out, errors.New("private evidence directory and host binding required")
	}
	controls := append([]string{}, hostControls...)
	if profile == "restricted" {
		controls = append(controls, "restricted-overlay-posture")
	} else if profile != "standard" {
		return out, errors.New("unknown host review profile")
	}
	r := HostReview{Schema: 1, Instance: p.Instance, HostBinding: binding, ArtifactSHA256: p.ArtifactSHA256, ConfigSHA256: p.ConfigSHA256, Profile: profile, IssuedAt: now.UTC(), ExpiresAt: now.Add(24 * time.Hour).UTC(), Evidence: map[string]string{}}
	for _, control := range controls {
		raw, e := worker.ReadPrivateFile(filepath.Join(evidence, control+".txt"), 65536)
		if e != nil || len(raw) == 0 {
			return out, errors.New("all private host control records must exist before requesting review")
		}
		hash := sha256.Sum256(raw)
		r.Evidence[control] = hex.EncodeToString(hash[:])
	}
	canonical, e := CanonicalHostReview(r)
	if e != nil {
		return out, e
	}
	return UnsignedHostReviewRequest{r, hex.EncodeToString(canonical), "Unsigned request only. Inspect every control record before independent review; this file cannot authorize signing."}, nil
}

// CreateHostReviewRequest owns the installation lease while preparing the draft.
// It never reads reviewer private keys, opens a vault or supplies a signature.
func CreateHostReviewRequest(root, configPath string, trust operator.ReleaseTrust, profile string, now time.Time) (string, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(configPath) {
		return "", errors.New("absolute private runtime paths required")
	}
	lease, e := worker.Acquire(root, "host.lock")
	if e != nil {
		return "", e
	}
	defer lease.Close()
	raw, e := worker.ReadPrivateFile(configPath, 128<<10)
	if e != nil {
		return "", e
	}
	var cfg RuntimeConfig
	if host.JSON(raw, &cfg) != nil || cfg.Schema != 1 || cfg.Instance == "" {
		return "", errors.New("invalid runtime configuration")
	}
	installation, e := host.Authorize(root, trust, cfg.Instance, now)
	if e != nil {
		return "", e
	}
	executable, e := os.Executable()
	if e != nil {
		return "", e
	}
	artifact, e := fileDigest(executable, host.MaxBundle)
	if e != nil || artifact != installation.Files["vortex-host"] {
		return "", errors.New("request must use exact privately installed host executable")
	}
	binding, e := localHostBinding()
	if e != nil {
		return "", e
	}
	configHash := sha256.Sum256(raw)
	draft, e := draftHostReview(Policy{Instance: cfg.Instance, ArtifactSHA256: artifact, ConfigSHA256: hex.EncodeToString(configHash[:])}, cfg.HostEvidence, profile, binding, now)
	if e != nil {
		return "", e
	}
	if e = host.Atomic(root, "host-review-request.json", draft); e != nil {
		return "", e
	}
	return filepath.Join(root, "host-review-request.json"), nil
}
