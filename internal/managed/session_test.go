package managed

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
)

type fixtureVerifier struct {
	mu           sync.Mutex
	edit         func(*Evidence)
	reconcileErr bool
	operation    Operation
}

// Slow independent remote reads must each retain a bounded window. A single
// deadline across all phases previously rejected a healthy second Linux host.
type pacedVerifier struct {
	fixtureVerifier
	inspectDelay   time.Duration
	reconcileDelay time.Duration
	operationDelay time.Duration
}

func pause(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (v *pacedVerifier) Inspect(ctx context.Context, p Policy) (Evidence, error) {
	if err := pause(ctx, v.inspectDelay); err != nil {
		return Evidence{}, err
	}
	return v.fixtureVerifier.Inspect(ctx, p)
}
func (v *pacedVerifier) Reconcile(ctx context.Context, p Policy, j Journal) (string, error) {
	if err := pause(ctx, v.reconcileDelay); err != nil {
		return "", err
	}
	return v.fixtureVerifier.Reconcile(ctx, p, j)
}
func (v *pacedVerifier) Operation(ctx context.Context, p Policy, id string) (Operation, error) {
	if err := pause(ctx, v.operationDelay); err != nil {
		return Operation{}, err
	}
	return v.fixtureVerifier.Operation(ctx, p, id)
}

func TestActivationAllowsCumulativeLiveReadLatency(t *testing.T) {
	v := &pacedVerifier{inspectDelay: 3500 * time.Millisecond, reconcileDelay: 3500 * time.Millisecond}
	s, err := Open(dir(t), policy(), v)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if checkpoint, err := s.activationCheckpoint(context.Background()); err != nil || checkpoint != strings.Repeat("c", 64) {
		t.Fatalf("bounded live phases failed: checkpoint=%q error=%v", checkpoint, err)
	}
}

func TestSigningAllowsCumulativeLiveReadLatency(t *testing.T) {
	v := &pacedVerifier{inspectDelay: 3100 * time.Millisecond, operationDelay: 2100 * time.Millisecond}
	v.operation = Operation{ID: "synthetic-transfer", Family: "evm", Digest: strings.Repeat("d", 64), State: "pending"}
	s, err := Open(dir(t), policy(), v)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	private, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s.keys = &keyvault.Keys{EVM: private, Koinos: make([]byte, 32)}
	s.journal.State = "active"
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	op, err := s.Sign(context.Background(), "synthetic-transfer")
	if err != nil || op.State != "signed" || op.Signature == "" {
		t.Fatalf("bounded signing phases failed: state=%q error=%v", op.State, err)
	}
}

func policy() Policy {
	return Policy{Instance: "synthetic-host", ArtifactSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), EVMAddress: "fixture-evm", KoinosAddress: "fixture-koinos"}
}
func (v *fixtureVerifier) Inspect(ctx context.Context, p Policy) (Evidence, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	e := Evidence{CheckedAt: now, ExpiresAt: now.Add(10 * time.Second), PolicySHA256: Digest(p), ArtifactSHA256: p.ArtifactSHA256, ConfigSHA256: p.ConfigSHA256, LocalDevelopment: true, ReleaseApproved: true, HostSecure: true, NetworksMatch: true, ProvenanceVerified: true, MembershipFinal: true, EVMMember: p.EVMAddress, KoinosMember: p.KoinosAddress, RemovedEVM: p.PreviousEVM, RemovedKoinos: p.PreviousKoinos, RotationFinal: true}
	if v.edit != nil {
		v.edit(&e)
	}
	return e, nil
}
func (v *fixtureVerifier) Reconcile(ctx context.Context, p Policy, j Journal) (string, error) {
	if v.reconcileErr {
		return "", errors.New("unresolved pending operation")
	}
	return strings.Repeat("c", 64), nil
}
func (v *fixtureVerifier) Operation(ctx context.Context, p Policy, id string) (Operation, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.operation, nil
}
func dir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestActivationGatesBeforeSecretInput(t *testing.T) {
	cases := map[string]func(*Evidence){"unapproved": func(e *Evidence) { e.ReleaseApproved = false }, "weak-host": func(e *Evidence) { e.HostSecure = false }, "wrong-network": func(e *Evidence) { e.NetworksMatch = false }, "unknown-code": func(e *Evidence) { e.ProvenanceVerified = false }, "head-only": func(e *Evidence) { e.MembershipFinal = false }, "wrong-identity": func(e *Evidence) { e.EVMMember = "other" }, "stale": func(e *Evidence) { e.CheckedAt = time.Now().Add(-time.Minute) }, "wrong-release": func(e *Evidence) { e.ArtifactSHA256 = strings.Repeat("d", 64) }, "public": func(e *Evidence) { e.LocalDevelopment = false }, "old-active": func(e *Evidence) { e.RotationFinal = false }}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			p := policy()
			p.PreviousEVM = "old-evm"
			p.PreviousKoinos = "old-koinos"
			s, e := Open(dir(t), p, &fixtureVerifier{edit: edit})
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			called := false
			e = s.Activate(context.Background(), "/nonexistent", func() ([]byte, error) { called = true; return nil, nil })
			if e == nil || called {
				t.Fatal("gate reached secret input")
			}
			if s.Status().State != "locked" {
				t.Fatal("wrong state")
			}
		})
	}
}
func TestRecoveryAndLocalExclusion(t *testing.T) {
	root := dir(t)
	p := policy()
	s, e := Open(root, p, &fixtureVerifier{})
	if e != nil {
		t.Fatal(e)
	}
	if other, e := Open(root, p, &fixtureVerifier{}); e == nil {
		other.Close()
		t.Fatal("duplicate owner")
	}
	s.journal.State = "active"
	s.journal.Operations["pending"] = Operation{ID: "pending", Family: "evm", Digest: strings.Repeat("d", 64), State: "pending"}
	if e = s.save(); e != nil {
		t.Fatal(e)
	}
	// Emulate OS releasing the descriptor after a crash, without a clean stop.
	s.lease.Close()
	s.closed = true
	recovered, e := Open(root, p, &fixtureVerifier{reconcileErr: true})
	if e != nil {
		t.Fatal(e)
	}
	defer recovered.Close()
	if recovered.Status().State != "recovery-required" || len(recovered.Status().Operations) != 1 {
		t.Fatal("lost crash state")
	}
	called := false
	if e = recovered.Activate(context.Background(), "/nonexistent", func() ([]byte, error) { called = true; return nil, nil }); e == nil || called {
		t.Fatal("recovery bypass")
	}
	if _, e = recovered.Sign(context.Background(), "pending"); e == nil {
		t.Fatal("locked signing")
	}
}
func TestReplacementCannotReuseEitherKey(t *testing.T) {
	p := policy()
	p.PreviousEVM = p.EVMAddress
	p.PreviousKoinos = "different"
	if s, e := Open(dir(t), p, &fixtureVerifier{}); e == nil {
		s.Close()
		t.Fatal("reused key")
	}
}

func TestUnknownJournalAndCancelledEvidenceRefused(t *testing.T) {
	root := dir(t)
	p := policy()
	s, e := Open(root, p, &fixtureVerifier{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.check(ctx) == nil {
		t.Fatal("cancelled verification accepted")
	}
	s.journal.State = "invented"
	if e = s.save(); e != nil {
		t.Fatal(e)
	}
	s.lease.Close()
	s.closed = true
	if r, e := Open(root, p, &fixtureVerifier{}); e == nil {
		r.Close()
		t.Fatal("unknown persisted state accepted")
	}
}

func TestCompletedUnsignedIntentSurvivesRecovery(t *testing.T) {
	root := dir(t)
	p := policy()
	s, e := Open(root, p, &fixtureVerifier{})
	if e != nil {
		t.Fatal(e)
	}
	s.journal.Operations["other-quorum"] = Operation{ID: "other-quorum", Family: "evm", Digest: strings.Repeat("d", 64), State: "completed"}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	recovered, e := Open(root, p, &fixtureVerifier{})
	if e != nil {
		t.Fatal(e)
	}
	defer recovered.Close()
	if recovered.Status().Operations["other-quorum"].State != "completed" {
		t.Fatal("completion lost")
	}
}

type drainVerifier struct {
	fixtureVerifier
	current map[string]Operation
}

func (v *drainVerifier) Operation(ctx context.Context, p Policy, id string) (Operation, error) {
	op, ok := v.current[id]
	if !ok {
		return Operation{}, errors.New("missing finalized receipt")
	}
	return op, nil
}

func TestDrainRequiresEveryRetainedOperationFinalAndKeepsSignatures(t *testing.T) {
	root := dir(t)
	private, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := policy()
	p.EVMAddress = crypto.PubkeyToAddress(private.PublicKey).Hex()
	v := &drainVerifier{current: map[string]Operation{}}
	s, err := Open(root, p, v)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.keys = &keyvault.Keys{EVM: private, Koinos: make([]byte, 32)}
	s.journal.State = "active"
	completed := Operation{ID: "first", Family: "evm", Digest: strings.Repeat("d", 64), State: "completed"}
	pending := Operation{ID: "second", Family: "evm", Digest: strings.Repeat("e", 64), State: "signed"}
	digest, _ := hex.DecodeString(pending.Digest)
	signature, err := crypto.Sign(digest, private)
	if err != nil {
		t.Fatal(err)
	}
	pending.Signature = hex.EncodeToString(signature)
	s.journal.Operations[completed.ID] = completed
	s.journal.Operations[pending.ID] = pending
	if err = s.save(); err != nil {
		t.Fatal(err)
	}
	v.current[completed.ID] = completed
	v.current[pending.ID] = Operation{ID: pending.ID, Family: pending.Family, Digest: pending.Digest, State: "pending"}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.Drain(cancelled); err == nil || s.Status().State != "active" {
		t.Fatal("cancelled drain changed active signer state")
	}
	if err = s.Drain(context.Background()); err == nil || s.Status().State != "active" || s.keys == nil || s.Status().Operations[pending.ID].State != "signed" {
		t.Fatal("unfinished operation was silently drained or signer closed")
	}
	v.current[pending.ID] = Operation{ID: pending.ID, Family: pending.Family, Digest: strings.Repeat("f", 64), State: "completed"}
	if err = s.Drain(context.Background()); err == nil || s.Status().State != "active" {
		t.Fatal("changed operation digest was accepted")
	}
	v.current[pending.ID] = Operation{ID: pending.ID, Family: pending.Family, Digest: pending.Digest, State: "completed"}
	if err = s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Status().State != "locked" || s.keys != nil || s.Status().Operations[pending.ID].State != "completed" || s.Status().Operations[pending.ID].Signature != pending.Signature {
		t.Fatal("verified drain failed to persist locked completed state")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root, p, v)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Status().State != "locked" || reopened.Status().Operations[pending.ID].State != "completed" || reopened.Status().Operations[pending.ID].Signature != pending.Signature {
		t.Fatal("drained journal did not survive restart")
	}
}
