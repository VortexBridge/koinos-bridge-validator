package managed

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// ImportRetiredJournal carries public intents into a fresh replacement session.
// The source remains untouched. Old signatures are verified, then excluded from
// the new journal: retired identities must never masquerade as the new signer.
// This does not unlock keys. Activation repeats every live gate and reconciliation.
func (s *Session) ImportRetiredJournal(ctx context.Context, previous Policy, source Journal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.keys != nil || s.journal.State != "locked" || len(s.journal.Operations) != 0 || s.journal.Checkpoint != "" {
		return errors.New("recovery requires a fresh locked replacement session")
	}
	if s.policy.PreviousEVM == "" || s.policy.PreviousKoinos == "" || !strings.EqualFold(s.policy.PreviousEVM, previous.EVMAddress) || s.policy.PreviousKoinos != previous.KoinosAddress {
		return errors.New("source identities do not match the reviewed replacement")
	}
	source = clone(source)
	if source.Schema != 1 || source.PolicySHA256 != Digest(previous) || source.Operations == nil {
		return errors.New("source journal does not match its policy")
	}
	old := &Session{policy: previous, journal: source}
	if err := old.validateJournal(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.check(ctx); err != nil {
		return err
	}
	next := Journal{Schema: 1, PolicySHA256: Digest(s.policy), State: "locked", Operations: map[string]Operation{}}
	ids := make([]string, 0, len(source.Operations))
	for id := range source.Operations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		prior := source.Operations[id]
		op, err := s.verifier.Operation(ctx, s.policy, id)
		if err != nil || ctx.Err() != nil || op.ID != id || op.Digest != prior.Digest || op.Family != prior.Family || op.Signature != "" || (op.State != "pending" && op.State != "completed") || (prior.State == "completed" && op.State != "completed") {
			return errors.New("source operation cannot be reconciled for replacement")
		}
		next.Operations[id] = op
	}
	checkpoint, err := s.verifier.Reconcile(ctx, s.policy, clone(next))
	if err != nil || !validHash(checkpoint) {
		return errors.New("replacement checkpoint unavailable")
	}
	if err = s.check(ctx); err != nil {
		return err
	}
	next.Checkpoint = checkpoint
	before := s.journal
	s.journal = next
	if err = s.save(); err != nil {
		s.journal = before
		return err
	}
	return nil
}
