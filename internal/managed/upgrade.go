package managed

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// UpgradeArtifact changes only the approved executable on the same reviewed
// machine, boot and user. It never imports another host's journal or unlocks keys.
// The caller must hold the installation lease and use the new runtime verifier.
func (s *Session) UpgradeArtifact(ctx context.Context, next Policy, priorReview SignedHostReview) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.keys != nil || s.journal.State != "locked" {
		return errors.New("stop the managed signer before upgrading")
	}
	previous := s.policy
	if !artifactOnlyTransition(previous, next) {
		return errors.New("artifact upgrade must preserve instance, configuration and identities")
	}
	authorizer, ok := s.verifier.(interface {
		authorizeUpgrade(context.Context, Policy, SignedHostReview) error
	})
	if !ok {
		return errors.New("same-host upgrade review unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := authorizer.authorizeUpgrade(ctx, previous, priorReview); err != nil {
		return err
	}
	candidate := &Session{policy: next, verifier: s.verifier, journal: clone(s.journal)}
	candidate.journal.PolicySHA256 = Digest(next)
	if err := candidate.check(ctx); err != nil {
		return err
	}
	if err := s.validateJournal(); err != nil {
		return err
	}
	ids := make([]string, 0, len(candidate.journal.Operations))
	for id := range candidate.journal.Operations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		old := candidate.journal.Operations[id]
		op, err := s.verifier.Operation(ctx, next, id)
		if err != nil || ctx.Err() != nil || op.ID != id || op.Digest != old.Digest || op.Family != old.Family || op.Signature != "" || (op.State != "pending" && op.State != "completed") || (old.State == "completed" && op.State != "completed") {
			return errors.New("retained operation differs under new artifact")
		}
		if op.State == "completed" {
			old.State = "completed"
		}
		candidate.journal.Operations[id] = old
	}
	checkpoint, err := s.verifier.Reconcile(ctx, next, clone(candidate.journal))
	if err != nil || !validHash(checkpoint) {
		return errors.New("upgrade reconciliation unavailable")
	}
	if err = candidate.check(ctx); err != nil {
		return err
	}
	candidate.journal.PolicySHA256 = Digest(next)
	candidate.journal.Checkpoint = checkpoint
	if err = candidate.validateJournal(); err != nil {
		return err
	}
	before := s.journal
	s.policy = next
	s.journal = candidate.journal
	if err = s.save(); err != nil {
		s.policy = previous
		s.journal = before
		return err
	}
	return nil
}

// The old review proves continuity only. Its approval is never substituted for
// the fresh review checked by Inspect for the newly installed artifact.
func (v *HostVerifier) authorizeUpgrade(ctx context.Context, previous Policy, signed SignedHostReview) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	key, err := worker.ReadPrivateFile(v.reviewer, 1024)
	if err != nil {
		return errors.New("pinned reviewer unavailable")
	}
	binding, err := v.binding()
	if err != nil {
		return errors.New("current machine binding unavailable")
	}
	return verifyUpgradeContinuity(previous, signed, key, binding, time.Now())
}
func verifyUpgradeContinuity(previous Policy, signed SignedHostReview, key []byte, binding string, now time.Time) error {
	r := signed.Review
	canonical, err := CanonicalHostReview(r)
	signature, decodeErr := hex.DecodeString(signed.Signature)
	if err != nil || decodeErr != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key), canonical, signature) {
		return errors.New("previous host review signature invalid")
	}
	if !validHash(binding) || r.HostBinding != binding || r.Schema != 1 || r.Instance != previous.Instance || r.ArtifactSHA256 != previous.ArtifactSHA256 || r.ConfigSHA256 != previous.ConfigSHA256 || r.IssuedAt.IsZero() || r.IssuedAt.After(now) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 24*time.Hour {
		return errors.New("previous review does not bind this host and policy")
	}
	return nil
}

func artifactOnlyTransition(previous, next Policy) bool {
	comparable := next
	comparable.ArtifactSHA256 = previous.ArtifactSHA256
	return comparable == previous && validHash(previous.ArtifactSHA256) && validHash(next.ArtifactSHA256) && previous.ArtifactSHA256 != next.ArtifactSHA256
}
