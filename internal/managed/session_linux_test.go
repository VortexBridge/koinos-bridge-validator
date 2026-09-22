//go:build linux
// +build linux

package managed

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
)

var syntheticPassword = []byte("SYNTHETIC ONLY never use for real keys")

func password() ([]byte, error) { return append([]byte{}, syntheticPassword...), nil }
func makeVault(t *testing.T, root string) (string, Policy) {
	t.Helper()
	path := filepath.Join(root, "keys.vault")
	pub, e := keyvault.Create(path, nil, nil, password)
	if e != nil {
		t.Fatal(e)
	}
	p := policy()
	p.EVMAddress = pub.EVMAddress
	p.KoinosAddress = pub.KoinosAddress
	return path, p
}
func operation(id string) Operation {
	return Operation{ID: id, Family: "evm", Digest: strings.Repeat("d", 64), State: "pending"}
}
func signer(t *testing.T, op Operation) string {
	t.Helper()
	sig, e := hex.DecodeString(op.Signature)
	if e != nil {
		t.Fatal(e)
	}
	digest, _ := hex.DecodeString(op.Digest)
	pub, e := crypto.SigToPub(digest, sig)
	if e != nil {
		t.Fatal(e)
	}
	return crypto.PubkeyToAddress(*pub).Hex()
}
func TestLinuxManagedUnlockSignStopAndRotation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Linux acceptance must run as non-root with supported memory protections")
	}
	ctx := context.Background()
	root := dir(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "user-config"))
	vault, p := makeVault(t, root)
	v := &fixtureVerifier{operation: operation("transfer-1")}
	s, e := Open(filepath.Join(root, "session"), p, v)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Activate(ctx, vault, func() ([]byte, error) { return []byte("incorrect synthetic passphrase"), nil }); e == nil {
		t.Fatal("wrong password accepted")
	}
	if e = s.Activate(ctx, vault, password); e != nil {
		t.Fatal(e)
	}
	clone, e := Open(filepath.Join(root, "other-session"), p, v)
	if e != nil {
		t.Fatal(e)
	}
	defer clone.Close()
	if e = clone.Activate(ctx, vault, password); e == nil {
		t.Fatal("same identity active in another directory")
	}
	op, e := s.Sign(ctx, "transfer-1")
	if e != nil || signer(t, op) != p.EVMAddress {
		t.Fatal("signature mismatch", e)
	}
	again, e := s.Sign(ctx, "transfer-1")
	if e != nil || again.Signature != op.Signature {
		t.Fatal("idempotent signing", e)
	}
	v.operation = Operation{ID: "koinos-transfer", Family: "koinos", Digest: strings.Repeat("e", 64), State: "pending"}
	ko, e := s.Sign(ctx, "koinos-transfer")
	if e != nil {
		t.Fatal(e)
	}
	ks, _ := hex.DecodeString(ko.Signature)
	kd, _ := hex.DecodeString(ko.Digest)
	ka, e := util.RecoverKoinosAddressFromSignature(base64.URLEncoding.EncodeToString(ks), kd)
	if e != nil || ka != p.KoinosAddress {
		t.Fatal("Koinos signature mismatch", e)
	}
	v.operation = operation("transfer-1")
	if e = s.Stop(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Sign(ctx, "transfer-1"); e == nil {
		t.Fatal("stop did not lock")
	}
	if e = s.Activate(ctx, vault, password); e != nil {
		t.Fatal(e)
	}
	root2 := dir(t)
	vault2, p2 := makeVault(t, root2)
	p2.Instance = "replacement"
	p2.PreviousEVM = p.EVMAddress
	p2.PreviousKoinos = p.KoinosAddress
	v2 := &fixtureVerifier{operation: operation("transfer-1"), edit: func(e *Evidence) { e.RotationFinal = false }}
	replacement, e := Open(filepath.Join(root2, "session"), p2, v2)
	if e != nil {
		t.Fatal(e)
	}
	defer replacement.Close()
	if e = replacement.Activate(ctx, vault2, password); e == nil {
		t.Fatal("old active signer not fenced")
	}
	// A synthetic final membership transition retires BOTH old identities. A
	// public adapter must derive this from each chain, never an operator assertion.
	v2.edit = nil
	v.edit = func(e *Evidence) { e.EVMMember = p2.EVMAddress; e.KoinosMember = p2.KoinosAddress }
	if e = replacement.Activate(ctx, vault2, password); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Sign(ctx, "transfer-1"); e == nil {
		t.Fatal("retired signer still active")
	}
	result, e := replacement.Sign(ctx, "transfer-1")
	if e != nil || signer(t, result) != p2.EVMAddress {
		t.Fatal("replacement signing", e)
	}
	if signer(t, op) == p2.EVMAddress {
		t.Fatal("pre-rotation signature counted as new member")
	}
	for _, base := range []string{root, root2} {
		_ = filepath.Walk(base, func(path string, info os.FileInfo, e error) error {
			if e != nil {
				t.Fatal(e)
			}
			if !info.IsDir() {
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if bytes.Contains(b, syntheticPassword) {
					t.Fatal("password leaked to artifact")
				}
			}
			return nil
		})
	}
}
func TestManagedCrashChild(t *testing.T) {
	if os.Getenv("VORTEX_SYNTHETIC_CRASH_CHILD") != "yes" {
		t.Skip("subprocess fixture")
	}
	root := os.Getenv("VORTEX_SYNTHETIC_DIR")
	vault, p := makeVault(t, root)
	s, e := Open(filepath.Join(root, "session"), p, &fixtureVerifier{operation: operation("transfer-1")})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Activate(context.Background(), vault, password); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Sign(context.Background(), "transfer-1"); e != nil {
		t.Fatal(e)
	}
	// No deferred close: simulate abrupt process loss with a durable signed intent.
	os.Exit(37)
}
func TestLinuxAbruptLossRequiresReconciliation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root acceptance required")
	}
	root := dir(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "user-config"))
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	child := exec.Command(exe, "-test.run=^TestManagedCrashChild$")
	child.Env = append(os.Environ(), "VORTEX_SYNTHETIC_CRASH_CHILD=yes", "VORTEX_SYNTHETIC_DIR="+root)
	out, e := child.CombinedOutput()
	if e == nil {
		t.Fatal("child did not terminate abruptly")
	}
	if child.ProcessState.ExitCode() != 37 {
		t.Fatalf("fixture startup failed: %s", out)
	}
	if bytes.Contains(out, syntheticPassword) {
		t.Fatal("secret in child output")
	}
	keys, pub, e := keyvault.Unlock(filepath.Join(root, "keys.vault"), "", "", password)
	if e != nil {
		t.Fatal(e)
	}
	keys.Close()
	p := policy()
	p.EVMAddress = pub.EVMAddress
	p.KoinosAddress = pub.KoinosAddress
	v := &fixtureVerifier{operation: operation("transfer-1"), reconcileErr: true}
	s, e := Open(filepath.Join(root, "session"), p, v)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.Status().State != "recovery-required" {
		t.Fatal("crash silently resumed")
	}
	if e = s.Activate(context.Background(), filepath.Join(root, "keys.vault"), password); e == nil {
		t.Fatal("unreconciled operation allowed restart")
	}
	v.reconcileErr = false
	if e = s.Activate(context.Background(), filepath.Join(root, "keys.vault"), password); e != nil {
		t.Fatal(e)
	}
	op, e := s.Sign(context.Background(), "transfer-1")
	if e != nil || signer(t, op) != p.EVMAddress {
		t.Fatal("retained signature lost", e)
	}
}
