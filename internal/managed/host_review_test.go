package managed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
)

func reviewedHostFixture(t *testing.T) (*HostVerifier, Policy, HostReview, ed25519.PrivateKey) {
	t.Helper()
	root := dir(t)
	p := policy()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	review := HostReview{Schema: 1, Instance: p.Instance, HostBinding: strings.Repeat("f", 64), ArtifactSHA256: p.ArtifactSHA256, ConfigSHA256: p.ConfigSHA256, Profile: "standard", IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), Evidence: map[string]string{}}
	evidence := filepath.Join(root, "evidence")
	if e := os.Mkdir(evidence, 0700); e != nil {
		t.Fatal(e)
	}
	for _, control := range hostControls {
		raw := []byte("Synthetic reviewed control: " + control)
		hash := sha256.Sum256(raw)
		review.Evidence[control] = hex.EncodeToString(hash[:])
		if e := os.WriteFile(filepath.Join(evidence, control+".txt"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	key := filepath.Join(root, "reviewer.pub")
	if e := os.WriteFile(key, pub, 0600); e != nil {
		t.Fatal(e)
	}
	v, e := NewHostVerifier(&fixtureVerifier{edit: func(e *Evidence) { e.HostSecure = false; e.ReleaseApproved = false }}, filepath.Join(root, "host-review.json"), key, evidence)
	if e != nil {
		t.Fatal(e)
	}
	v.binding = func() (string, error) { return strings.Repeat("f", 64), nil }
	v.protect = func() error { return nil }
	return v, p, review, priv
}
func writeHostReview(t *testing.T, v *HostVerifier, r HostReview, key ed25519.PrivateKey) {
	t.Helper()
	raw, _ := CanonicalHostReview(r)
	s := SignedHostReview{r, hex.EncodeToString(ed25519.Sign(key, raw))}
	if e := host.Atomic(filepath.Dir(v.review), filepath.Base(v.review), s); e != nil {
		t.Fatal(e)
	}
}
func TestHostReviewRequiresAuthenticatedBoundEvidenceAndLiveProtection(t *testing.T) {
	for _, kind := range []string{"good", "signature", "expired", "too-long", "wrong-host", "wrong-config", "missing-control", "extra-control", "changed-record", "missing-record", "weak-protection", "unknown-profile", "restricted-missing", "public-review-key", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			v, p, r, key := reviewedHostFixture(t)
			protected := false
			v.protect = func() error { protected = true; return nil }
			switch kind {
			case "expired":
				r.ExpiresAt = time.Now().Add(-time.Second)
			case "too-long":
				r.ExpiresAt = r.IssuedAt.Add(25 * time.Hour)
			case "wrong-host":
				r.HostBinding = strings.Repeat("a", 64)
			case "wrong-config":
				r.ConfigSHA256 = strings.Repeat("f", 64)
			case "missing-control":
				delete(r.Evidence, hostControls[0])
			case "extra-control":
				r.Evidence["unknown"] = strings.Repeat("a", 64)
			case "changed-record":
				os.WriteFile(filepath.Join(v.evidence, hostControls[0]+".txt"), []byte("changed"), 0600)
			case "missing-record":
				os.Remove(filepath.Join(v.evidence, hostControls[0]+".txt"))
			case "weak-protection":
				v.protect = func() error { return errors.New("live protections failed") }
			case "unknown-profile":
				r.Profile = "automatic"
			case "restricted-missing":
				r.Profile = "restricted"
			case "public-review-key":
				os.Chmod(v.reviewer, 0644)
			}
			writeHostReview(t, v, r, key)
			if kind == "signature" {
				raw, _ := CanonicalHostReview(r)
				host.Atomic(filepath.Dir(v.review), filepath.Base(v.review), SignedHostReview{r, hex.EncodeToString(raw)})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			out, e := v.Inspect(ctx, p)
			if kind == "good" {
				if e != nil || !protected || !out.HostSecure || out.ReleaseApproved {
					t.Fatal("valid host gate failed or granted release approval", e)
				}
			} else if e == nil {
				t.Fatal("unverified host accepted")
			}
		})
	}
}
