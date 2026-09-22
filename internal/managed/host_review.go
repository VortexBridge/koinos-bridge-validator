package managed

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// Host controls outside the signer process require authenticated human review.
// Evidence hashes bind locally inspected records, not automatic attestations of
// firewall, disk encryption, hypervisor policy or administrator independence.
var hostControls = []string{"patched-linux-service", "administrative-access-firewall", "private-management", "encrypted-storage-vault", "hibernation-hypervisor", "patch-response", "monitoring-alerts", "log-retention", "encrypted-offhost-backup-restore", "release-maintenance", "emergency-access"}

type HostReview struct {
	Schema         int               `json:"schemaVersion"`
	Instance       string            `json:"instance"`
	HostBinding    string            `json:"hostBinding"`
	ArtifactSHA256 string            `json:"artifactSha256"`
	ConfigSHA256   string            `json:"configSha256"`
	Profile        string            `json:"profile"`
	IssuedAt       time.Time         `json:"issuedAt"`
	ExpiresAt      time.Time         `json:"expiresAt"`
	Evidence       map[string]string `json:"evidence"`
}
type SignedHostReview struct {
	Review    HostReview `json:"review"`
	Signature string     `json:"signature"`
}

// HostVerifier consumes a locally pinned reviewer public key and signed review.
// It is distinct from publisher release approval; neither replaces the other.
type HostVerifier struct {
	base                       Verifier
	review, reviewer, evidence string
	binding                    func() (string, error)
	protect                    func() error
}

func NewHostVerifier(base Verifier, review, reviewer, evidence string) (*HostVerifier, error) {
	if base == nil || !filepath.IsAbs(review) || !filepath.IsAbs(reviewer) || !filepath.IsAbs(evidence) {
		return nil, errors.New("absolute private host-review, reviewer and evidence paths required")
	}
	return &HostVerifier{base, review, reviewer, evidence, localHostBinding, keyvault.ProtectProcess}, nil
}
func CanonicalHostReview(r HostReview) ([]byte, error) { return jsonBytes(r) }
func (v *HostVerifier) Inspect(ctx context.Context, p Policy) (Evidence, error) {
	out, e := v.base.Inspect(ctx, p)
	if e != nil {
		return Evidence{}, e
	}
	// A base verifier must not supply host readiness on this path.
	out.HostSecure = false
	raw, e := worker.ReadPrivateFile(v.review, 65536)
	if e != nil {
		return Evidence{}, errors.New("signed host review unavailable")
	}
	var signed SignedHostReview
	if host.JSON(raw, &signed) != nil {
		return Evidence{}, errors.New("invalid host review")
	}
	key, e := worker.ReadPrivateFile(v.reviewer, 1024)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return Evidence{}, errors.New("private pinned reviewer public key unavailable")
	}
	canonical, e := CanonicalHostReview(signed.Review)
	signature, se := hex.DecodeString(signed.Signature)
	if e != nil || se != nil || !ed25519.Verify(ed25519.PublicKey(key), canonical, signature) {
		return Evidence{}, errors.New("host review signature invalid")
	}
	r := signed.Review
	now := time.Now()
	binding, e := v.binding()
	if e != nil || !validHash(binding) || r.HostBinding != binding {
		return Evidence{}, errors.New("host review belongs to another machine, boot or user")
	}
	if r.Schema != 1 || r.Instance != p.Instance || r.ArtifactSHA256 != p.ArtifactSHA256 || r.ConfigSHA256 != p.ConfigSHA256 || r.IssuedAt.IsZero() || r.IssuedAt.After(now) || !r.ExpiresAt.After(now) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 24*time.Hour {
		return Evidence{}, errors.New("host review is stale or not bound to this installation")
	}
	controls := append([]string{}, hostControls...)
	if r.Profile == "restricted" {
		controls = append(controls, "restricted-overlay-posture")
	} else if r.Profile != "standard" {
		return Evidence{}, errors.New("unknown host security profile")
	}
	if len(r.Evidence) != len(controls) {
		return Evidence{}, errors.New("host review lacks required control evidence")
	}
	for _, control := range controls {
		digest, ok := r.Evidence[control]
		if !ok || !validHash(digest) {
			return Evidence{}, errors.New("invalid host control evidence reference")
		}
		record, e := worker.ReadPrivateFile(filepath.Join(v.evidence, control+".txt"), 65536)
		if e != nil || len(record) == 0 {
			return Evidence{}, errors.New("private host control evidence unavailable")
		}
		hash := sha256.Sum256(record)
		if hex.EncodeToString(hash[:]) != digest {
			return Evidence{}, errors.New("host control evidence changed after review")
		}
	}
	if ctx.Err() != nil {
		return Evidence{}, ctx.Err()
	}
	// Live Linux enforcement: non-root, swap disabled or all process mappings
	// locked, zero core limits and non-dumpable process. Never inferred from JSON.
	if e = v.protect(); e != nil {
		return Evidence{}, e
	}
	if !time.Now().Before(r.ExpiresAt) || ctx.Err() != nil {
		return Evidence{}, errors.New("host review expired during verification")
	}
	if out.ExpiresAt.After(r.ExpiresAt) {
		out.ExpiresAt = r.ExpiresAt
	}
	out.HostSecure = true
	return out, nil
}
func (v *HostVerifier) Reconcile(ctx context.Context, p Policy, j Journal) (string, error) {
	return v.base.Reconcile(ctx, p, j)
}
func (v *HostVerifier) Operation(ctx context.Context, p Policy, id string) (Operation, error) {
	return v.base.Operation(ctx, p, id)
}
