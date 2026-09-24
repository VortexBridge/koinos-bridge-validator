// Package managed is the narrow signer boundary. Evidence must come from a
// reviewed in-process verifier, never dashboard booleans or a cached JSON file.
// No production verifier is registered while deployment provenance is blocked.
package managed

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

type Policy struct {
	Instance       string
	ArtifactSHA256 string
	ConfigSHA256   string
	EVMAddress     string
	KoinosAddress  string
	PreviousEVM    string
	PreviousKoinos string
}

// Evidence is returned by the verifier after live reads. Both chain families
// must have final membership and code provenance; a head bracket never qualifies.
type Evidence struct {
	CheckedAt          time.Time
	ExpiresAt          time.Time
	PolicySHA256       string
	ArtifactSHA256     string
	ConfigSHA256       string
	LocalDevelopment   bool
	ReleaseApproved    bool
	HostSecure         bool
	NetworksMatch      bool
	ProvenanceVerified bool
	MembershipFinal    bool
	EVMMember          string
	KoinosMember       string
	RemovedEVM         string
	RemovedKoinos      string
	RotationFinal      bool
	Checkpoint         string
}
type Operation struct {
	ID        string `json:"id"`
	Family    string `json:"family"`
	Digest    string `json:"digest"`
	State     string `json:"state"` // pending, signed, completed
	Signature string `json:"signature,omitempty"`
}
type Journal struct {
	Schema       int                  `json:"schema"`
	PolicySHA256 string               `json:"policySha256"`
	State        string               `json:"state"`
	Checkpoint   string               `json:"checkpoint"`
	Operations   map[string]Operation `json:"operations"`
}

// Verifier reconstructs the operation digest from finalized chain data. The
// caller supplies an identifier only. Reconcile must account for every retained
// signed/pending operation before approving a restart, including final receipts.
type Verifier interface {
	Inspect(context.Context, Policy) (Evidence, error)
	Reconcile(context.Context, Policy, Journal) (string, error)
	Operation(context.Context, Policy, string) (Operation, error)
}
type Session struct {
	mu             sync.Mutex
	dir            string
	policy         Policy
	verifier       Verifier
	journal        Journal
	lease          *worker.Lease
	keys           *keyvault.Keys
	identityLeases []*worker.Lease
	closed         bool
}

func Digest(p Policy) string {
	b, _ := jsonBytes(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func Open(dir string, p Policy, v Verifier) (*Session, error) {
	if !filepath.IsAbs(dir) || p.Instance == "" || p.EVMAddress == "" || p.KoinosAddress == "" || !validHash(p.ArtifactSHA256) || !validHash(p.ConfigSHA256) || v == nil {
		return nil, errors.New("incomplete managed signer policy")
	}
	if (p.PreviousEVM == "") != (p.PreviousKoinos == "") {
		return nil, errors.New("replacement requires both previous identities")
	}
	if p.PreviousEVM != "" && (strings.EqualFold(p.PreviousEVM, p.EVMAddress) || p.PreviousKoinos == p.KoinosAddress) {
		return nil, errors.New("replacement must rotate both signing identities")
	}
	l, err := worker.Acquire(dir, "session.lock")
	if err != nil {
		return nil, err
	}
	s := &Session{dir: dir, policy: p, verifier: v, lease: l, journal: Journal{1, Digest(p), "locked", "", map[string]Operation{}}}
	path := filepath.Join(dir, "session.json")
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		raw, e := worker.ReadPrivateFile(path, 4<<20)
		if e != nil {
			l.Close()
			return nil, e
		}
		if host.JSON(raw, &s.journal) != nil || s.journal.Schema != 1 || s.journal.PolicySHA256 != Digest(p) || s.journal.Operations == nil {
			l.Close()
			return nil, errors.New("journal differs from reviewed policy; recovery review required")
		}
		if s.journal.State != "locked" && s.journal.State != "active" && s.journal.State != "recovery-required" {
			l.Close()
			return nil, errors.New("unknown journal lifecycle state")
		}
		if s.journal.State != "locked" {
			s.journal.State = "recovery-required"
		}
	}
	if err = s.validateJournal(); err != nil {
		l.Close()
		return nil, err
	}
	if err = s.save(); err != nil {
		l.Close()
		return nil, err
	}
	return s, nil
}
func (s *Session) save() error { return host.Atomic(s.dir, "session.json", s.journal) }
func (s *Session) check(ctx context.Context) error {
	e, err := s.verifier.Inspect(ctx, s.policy)
	if err != nil {
		return errors.New("live activation evidence unavailable")
	}
	if ctx.Err() != nil {
		return errors.New("activation evidence timed out")
	}
	now := time.Now()
	if e.CheckedAt.After(now) || now.Sub(e.CheckedAt) > 15*time.Second || !e.ExpiresAt.After(now) || e.ExpiresAt.After(e.CheckedAt.Add(15*time.Second)) {
		return errors.New("stale activation evidence")
	}
	if e.PolicySHA256 != Digest(s.policy) || e.ArtifactSHA256 != s.policy.ArtifactSHA256 || e.ConfigSHA256 != s.policy.ConfigSHA256 {
		return errors.New("activation evidence does not bind exact policy and artifact")
	}
	if !e.LocalDevelopment {
		return errors.New("public managed signing remains unsupported")
	}
	if !e.ReleaseApproved || !e.HostSecure || !e.NetworksMatch || !e.ProvenanceVerified || !e.MembershipFinal {
		return errors.New("release, host, network, provenance or final membership gate failed")
	}
	if !strings.EqualFold(e.EVMMember, s.policy.EVMAddress) || e.KoinosMember != s.policy.KoinosAddress {
		return errors.New("signer identities are not current members")
	}
	if s.policy.PreviousEVM != "" && (!e.RotationFinal || !strings.EqualFold(e.RemovedEVM, s.policy.PreviousEVM) || e.RemovedKoinos != s.policy.PreviousKoinos) {
		return errors.New("old signing identities are not irreversibly retired on both chains")
	}
	return nil
}

// Every live check has its own deadline. A single ten-second budget for the
// complete check/reconcile/check sequence rejected healthy but slower remote
// chain readers before the operator could unlock. The final check still reads
// current approval and membership immediately before admitting the signer.
func (s *Session) checkPhase(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	return s.check(ctx)
}

// activationCheckpoint bounds live checks separately from human secret entry.
// It must run again after unlock: both approvals and pending operations can
// change while the operator is typing. Caller holds the session lock.
func (s *Session) activationCheckpoint(parent context.Context) (string, error) {
	if err := s.checkPhase(parent); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	checkpoint, err := s.verifier.Reconcile(ctx, s.policy, clone(s.journal))
	deadline := ctx.Err()
	cancel()
	if err != nil || deadline != nil || !validHash(checkpoint) {
		return "", errors.New("pending operations and checkpoints require reconciliation")
	}
	if err = s.checkPhase(parent); err != nil {
		return "", err
	}
	return checkpoint, nil
}

// Activate never accepts keys from an HTTP caller. Unlock performs the Linux
// host protections and public-identity checks before returning any private keys.
func (s *Session) Activate(ctx context.Context, vault string, passphrase func() ([]byte, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.keys != nil {
		return errors.New("session closed or already unlocked")
	}
	if _, err := s.activationCheckpoint(ctx); err != nil {
		return err
	}
	// Share the existing standalone signer's same-user identity locks. A second
	// data directory is not a second signing identity. Cross-host replacement
	// additionally requires final retirement of BOTH old identities.
	configHome, err := os.UserConfigDir()
	if err != nil {
		return errors.New("local signer lock directory unavailable")
	}
	held := []*worker.Lease{}
	defer func() {
		for _, lease := range held {
			_ = lease.Close()
		}
	}()
	for _, name := range []string{"evm-" + common.HexToAddress(s.policy.EVMAddress).Hex(), "koinos-" + s.policy.KoinosAddress} {
		lease, e := worker.Acquire(filepath.Join(configHome, "vortex", "signer-locks"), name+".lock")
		if e != nil {
			return errors.New("signing identity is already active or its local lock is unavailable")
		}
		held = append(held, lease)
	}
	keys, _, err := keyvault.Unlock(vault, s.policy.EVMAddress, s.policy.KoinosAddress, passphrase)
	if err != nil {
		return err
	}
	// Unlock can take time; recheck immediately before admitting requests.
	checkpoint, err := s.activationCheckpoint(ctx)
	if err != nil {
		keys.Close()
		return err
	}
	s.keys = keys
	s.identityLeases = held
	held = nil
	s.journal.Checkpoint = checkpoint
	s.journal.State = "active"
	if err = s.save(); err != nil {
		s.keys.Close()
		s.keys = nil
		s.releaseIdentities()
		s.journal.State = "recovery-required"
		return err
	}
	return nil
}

// Sign resolves an operation from the verifier; it is not a sign-arbitrary-hash
// interface. Intent is fsynced before signing, result before returning to caller.
func (s *Session) Sign(ctx context.Context, id string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.keys == nil || s.journal.State != "active" {
		return Operation{}, errors.New("signer is locked")
	}
	if len(id) == 0 || len(id) > 128 {
		return Operation{}, errors.New("invalid operation identifier")
	}
	if err := s.checkPhase(ctx); err != nil {
		s.lock()
		return Operation{}, err
	}
	readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	op, err := s.verifier.Operation(readCtx, s.policy, id)
	readDeadline := readCtx.Err()
	cancel()
	if readDeadline != nil {
		s.lock()
		return Operation{}, errors.New("operation verification timed out")
	}
	if err != nil || op.ID != id || !validHash(op.Digest) || (op.Family != "evm" && op.Family != "koinos") || op.Signature != "" || (op.State != "pending" && op.State != "completed") {
		return Operation{}, errors.New("operation is not independently verified")
	}
	// Receipt reconstruction can outlive approval or membership. Recheck before
	// either returning a retained signature or preparing a new one.
	if err = s.checkPhase(ctx); err != nil {
		s.lock()
		return Operation{}, err
	}
	if old, ok := s.journal.Operations[id]; ok {
		if old.Digest != op.Digest || old.Family != op.Family {
			s.lock()
			return Operation{}, errors.New("operation changed; recovery review required")
		}
		if op.State == "completed" {
			old.State = "completed"
			s.journal.Operations[id] = old
			if err = s.save(); err != nil {
				s.lock()
				return Operation{}, err
			}
			return old, nil
		}
		if old.State == "signed" {
			return old, nil
		}
		if old.State == "completed" {
			return Operation{}, errors.New("completed operation cannot be reopened")
		}
	}
	if op.State == "completed" {
		return Operation{}, errors.New("operation already completed")
	}
	if len(s.journal.Operations) >= 4096 {
		s.lock()
		return Operation{}, errors.New("journal capacity reached; reviewed archival required")
	}
	s.journal.Operations[id] = op
	if err = s.save(); err != nil {
		s.lock()
		return Operation{}, err
	}
	// Durable intent must precede signing, but slow persistence must not extend
	// a permit. A failed final check leaves an unsigned recoverable intent.
	if err = s.checkPhase(ctx); err != nil {
		s.lock()
		return Operation{}, err
	}
	if ctx.Err() != nil {
		s.lock()
		return Operation{}, errors.New("operation cancelled before signing")
	}
	digest, _ := hex.DecodeString(op.Digest)
	// No private key leaves the session. Signature encodings are explicit.
	if op.Family == "evm" {
		sig, e := crypto.Sign(digest, s.keys.EVM)
		if e != nil {
			s.lock()
			return Operation{}, errors.New("signing failed")
		}
		op.Signature = hex.EncodeToString(sig)
	} else {
		op.Signature = hex.EncodeToString(util.SignKoinosHash(s.keys.Koinos, digest))
	}
	op.State = "signed"
	s.journal.Operations[id] = op
	if err = s.save(); err != nil {
		s.lock()
		return Operation{}, err
	}
	return op, nil
}
func (s *Session) lock() error {
	if s.keys != nil {
		s.keys.Close()
		s.keys = nil
	}
	s.releaseIdentities()
	s.journal.State = "locked"
	return s.save()
}

// Stop serializes after the bounded in-flight request; it never releases the
// local lease while a key or signing operation remains active.
func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.lock()
}
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	err := s.lock()
	s.closed = true
	e := s.lease.Close()
	if err != nil {
		return err
	}
	return e
}
func (s *Session) Status() Journal { s.mu.Lock(); defer s.mu.Unlock(); return clone(s.journal) }

// Recovered journals contain public signatures only, but still require integrity
// checks before an old result can be reused. A filesystem copy is not authority.
func (s *Session) validateJournal() error {
	if len(s.journal.Operations) > 4096 {
		return errors.New("journal capacity exceeded")
	}
	switch s.journal.State {
	case "locked", "active", "recovery-required":
	default:
		return errors.New("invalid journal state")
	}
	for id, op := range s.journal.Operations {
		if id != op.ID || len(id) == 0 || len(id) > 128 || !validHash(op.Digest) || (op.Family != "evm" && op.Family != "koinos") {
			return errors.New("corrupt operation journal")
		}
		if op.State == "pending" {
			if op.Signature != "" {
				return errors.New("pending operation has unexpected signature")
			}
			continue
		}
		if op.State != "signed" && op.State != "completed" {
			return errors.New("unknown operation state")
		}
		// Another quorum can complete an intent before this process emits a signature.
		if op.State == "completed" && op.Signature == "" {
			continue
		}
		digest, _ := hex.DecodeString(op.Digest)
		sig, e := hex.DecodeString(op.Signature)
		if e != nil {
			return errors.New("invalid retained signature")
		}
		if op.Family == "evm" {
			address, e := util.RecoverEthereumAddressFromSignature("0x"+op.Signature, digest)
			if e != nil || !strings.EqualFold(address, s.policy.EVMAddress) {
				return errors.New("retained EVM signature mismatch")
			}
		} else {
			address, e := util.RecoverKoinosAddressFromSignature(base64.URLEncoding.EncodeToString(sig), digest)
			if e != nil || address != s.policy.KoinosAddress {
				return errors.New("retained Koinos signature mismatch")
			}
		}
	}
	return nil
}

func (s *Session) releaseIdentities() {
	for _, lease := range s.identityLeases {
		_ = lease.Close()
	}
	s.identityLeases = nil
}
