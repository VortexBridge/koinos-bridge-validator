package managed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type upgradeVerifier struct {
	*fixtureVerifier
	deny bool
}

func (v *upgradeVerifier) authorizeUpgrade(context.Context, Policy, SignedHostReview) error {
	if v.deny {
		return errors.New("wrong host")
	}
	return nil
}
func TestArtifactUpgradePreservesSignaturesAndFailsClosed(t *testing.T) {
	for _, kind := range []string{"pending", "completed", "wrong-host", "changed-config", "changed-identity", "changed-instance", "changed-retirement", "active", "digest-change", "completion-regression", "unapproved", "late-revocation", "checkpoint-failure"} {
		t.Run(kind, func(t *testing.T) {
			previous := policy()
			previous.KoinosAddress = "1CAtc7wPVn9JUAcbV8jo8UfyzMoAHRaTPC"
			next := previous
			next.ArtifactSHA256 = strings.Repeat("d", 64)
			op := Operation{ID: "evm-to-koinos/a69784eddaa3aceb5afac7d93e9d01454dd73e7ade5b11d59e41a96241823486:0", Family: "koinos", Digest: "c88a0106baf4428f10c4816de12f70a92871999c84bc2c5186d995fada8fb167", State: "signed", Signature: "1fc777e0def2d6f7005c57e779d3e6825566629e7c2bf551d5603240cd6e4add465f37d3762ea78f5401ea17489dc27f1d0ad22358f5e0957dea06377c2c4cde5d"}
			current := op
			current.Signature = ""
			current.State = "pending"
			v := &upgradeVerifier{fixtureVerifier: &fixtureVerifier{operation: current}}
			root := dir(t)
			s, err := Open(root, previous, v)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.journal.Operations[op.ID] = op
			switch kind {
			case "completed":
				v.operation.State = "completed"
			case "wrong-host":
				v.deny = true
			case "changed-config":
				next.ConfigSHA256 = strings.Repeat("e", 64)
			case "changed-identity":
				next.KoinosAddress = "another"
			case "changed-instance":
				next.Instance = "another"
			case "changed-retirement":
				next.PreviousEVM = "old"
				next.PreviousKoinos = "old"
			case "active":
				s.journal.State = "active"
			case "digest-change":
				v.operation.Digest = strings.Repeat("f", 64)
			case "completion-regression":
				op.State = "completed"
				s.journal.Operations[op.ID] = op
			case "unapproved":
				v.edit = func(e *Evidence) { e.ReleaseApproved = false }
			case "late-revocation":
				checks := 0
				v.edit = func(e *Evidence) {
					checks++
					if checks > 1 {
						e.ReleaseApproved = false
					}
				}
			case "checkpoint-failure":
				v.reconcileErr = true
			}
			if err = s.save(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(root, "session.json"))
			if err != nil {
				t.Fatal(err)
			}
			err = s.UpgradeArtifact(context.Background(), next, SignedHostReview{})
			if kind != "pending" && kind != "completed" {
				after, e := os.ReadFile(filepath.Join(root, "session.json"))
				if e != nil {
					t.Fatal(e)
				}
				if err == nil || s.policy != previous || string(before) != string(after) {
					t.Fatal("unsafe upgrade or failed upgrade changed state")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := s.Status()
			if got.State != "locked" || got.PolicySHA256 != Digest(next) || got.Operations[op.ID].Signature != op.Signature {
				t.Fatal("upgrade lost signature or unlocked")
			}
			if kind == "completed" && got.Operations[op.ID].State != "completed" {
				t.Fatal("completion not reconciled")
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			if old, e := Open(root, previous, v); e == nil {
				old.Close()
				t.Fatal("old policy reopened upgraded state")
			}
			reopened, e := Open(root, next, v)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if reopened.Status().Operations[op.ID].Signature != op.Signature {
				t.Fatal("signature not retained on reopen")
			}
		})
	}
}
func TestUpgradeContinuityRequiresPinnedSignatureAndSameHostPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := policy()
	now := time.Now()
	binding := strings.Repeat("c", 64)
	r := HostReview{Schema: 1, Instance: p.Instance, ArtifactSHA256: p.ArtifactSHA256, ConfigSHA256: p.ConfigSHA256, HostBinding: binding, IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-24 * time.Hour)}
	raw, _ := CanonicalHostReview(r)
	signed := SignedHostReview{Review: r, Signature: hex.EncodeToString(ed25519.Sign(priv, raw))}
	// Expired historical approval is continuity only; fresh approval is mandatory separately.
	if err = verifyUpgradeContinuity(p, signed, pub, binding, now); err != nil {
		t.Fatal(err)
	}
	if err = verifyUpgradeContinuity(p, signed, pub, strings.Repeat("d", 64), now); err == nil {
		t.Fatal("cross-host copy accepted")
	}
	changed := p
	changed.ConfigSHA256 = strings.Repeat("e", 64)
	if err = verifyUpgradeContinuity(changed, signed, pub, binding, now); err == nil {
		t.Fatal("different policy accepted")
	}
	signed.Review.HostBinding = strings.Repeat("f", 64)
	if err = verifyUpgradeContinuity(p, signed, pub, signed.Review.HostBinding, now); err == nil {
		t.Fatal("tampered review accepted")
	}
}
