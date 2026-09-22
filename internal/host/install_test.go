package host

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

func fixture(t *testing.T, seq uint64, mutate func(*tar.Header)) ([]byte, operator.SignedRelease, operator.ReleaseTrust, operator.ReleaseApproval) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range Files {
		data := []byte("#!/bin/sh\nexit 0\n")
		h := &tar.Header{Name: name, Mode: 0700, Size: int64(len(data))}
		if mutate != nil {
			mutate(h)
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeSymlink {
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m := operator.ReleaseManifest{SchemaVersion: 1, ID: "host-fixture", Component: "operator", Version: "0.3.0", Sequence: seq, Channel: "candidate", SourceCommit: "1111111111111111111111111111111111111111", CreatedAt: now.Add(-time.Minute).UTC().Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339), CompatibleFrom: []string{"0.3.0"}, ConfigSchema: 1, DatabaseSchema: 1, SigningCodec: "observation-v1", Recovery: "preserve state", TestEvidence: []string{"synthetic fixture"}, Artifacts: []operator.ReleaseArtifact{{Platform: "linux-" + runtime.GOARCH, SHA256: hash(buf.Bytes()), Size: uint64(buf.Len())}}}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := operator.CanonicalRelease(m)
	signed := operator.SignedRelease{Manifest: m, Signatures: []operator.ReleaseSignature{{Publisher: "fixture", Signature: hex.EncodeToString(ed25519.Sign(priv, raw))}}}
	trust := operator.ReleaseTrust{SchemaVersion: 1, RequiredSignatures: 1, Publishers: map[string]string{"fixture": hex.EncodeToString(pub)}}
	v, err := operator.VerifyRelease(signed, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	a := operator.ReleaseApproval{InstanceID: "fixture-host", Digest: v.Digest, Component: "operator", Version: m.Version, Sequence: seq, WindowStart: now.Add(-time.Minute), WindowEnd: now.Add(time.Hour), ApprovedAt: now}
	return buf.Bytes(), signed, trust, a
}
func private(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestInstallIdempotentUpgradeAndUninstallPreservesState(t *testing.T) {
	root := private(t)
	b, s, trust, a := fixture(t, 1, nil)
	i, e := Install(root, "fixture-host", b, s, trust, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(root, "state", "must-survive")
	if e = os.WriteFile(state, []byte("public checkpoint"), 0600); e != nil {
		t.Fatal(e)
	}
	again, e := Install(root, "fixture-host", b, s, trust, a, time.Now())
	if e != nil || again.Artifact != i.Artifact {
		t.Fatal("idempotent install", e)
	}
	if e = Uninstall(root); e != nil {
		t.Fatal(e)
	}
	if e = Uninstall(root); e != nil {
		t.Fatal(e)
	}
	if got, e := os.ReadFile(state); e != nil || string(got) != "public checkpoint" {
		t.Fatal("state lost")
	}
	b, s, trust, a = fixture(t, 2, nil)
	if _, e = Install(root, "fixture-host", b, s, trust, a, time.Now()); e != nil {
		t.Fatal("upgrade", e)
	}
	b, s, trust, a = fixture(t, 1, nil)
	if _, e = Install(root, "fixture-host", b, s, trust, a, time.Now()); e == nil {
		t.Fatal("accepted downgrade")
	}
}
func TestInstallRejectsTamperApprovalAndArchiveEscape(t *testing.T) {
	for _, kind := range []string{"bytes", "approval", "publisher", "expired", "escape", "symlink", "missing"} {
		t.Run(kind, func(t *testing.T) {
			mutate := func(h *tar.Header) {
				if h.Name == Files[0] {
					switch kind {
					case "escape":
						h.Name = "../outside"
					case "symlink":
						h.Typeflag = tar.TypeSymlink
						h.Linkname = "/tmp/outside"
						h.Size = 0
					case "missing":
						h.Name = "unexpected"
					}
				}
			}
			b, s, trust, a := fixture(t, 1, mutate)
			switch kind {
			case "bytes":
				b[0] ^= 1
			case "approval":
				a.Revoked = true
			case "publisher":
				trust.Publishers = map[string]string{}
			case "expired":
				a.WindowEnd = time.Now().Add(-time.Second)
			}
			root := private(t)
			if _, e := Install(root, "fixture-host", b, s, trust, a, time.Now()); e == nil {
				t.Fatal("unsafe install accepted")
			}
			if _, e := os.Stat(filepath.Join(root, "installation.json")); !os.IsNotExist(e) {
				t.Fatal("published invalid installation")
			}
		})
	}
}
func TestTamperedInstallAndExclusiveHostLock(t *testing.T) {
	root := private(t)
	b, s, trust, a := fixture(t, 1, nil)
	i, e := Install(root, "fixture-host", b, s, trust, a, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "releases", i.Artifact, Files[0]), []byte("tampered"), 0700); e != nil {
		t.Fatal(e)
	}
	if Verify(root, i) == nil {
		t.Fatal("tamper accepted")
	}
	if _, e = Install(root, "fixture-host", b, s, trust, a, time.Now()); e == nil {
		t.Fatal("silent repair hid tamper")
	}
	l, e := worker.Acquire(root, "host.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if other, e := worker.Acquire(root, "host.lock"); e == nil {
		other.Close()
		t.Fatal("concurrent owner")
	}
}

func TestAuthorizationRechecksApprovalAndSignedArchive(t *testing.T) {
	for _, kind := range []string{"good", "revoked", "expired", "disabled", "publisher-removed", "tampered-map", "tampered-archive", "wrong-version"} {
		t.Run(kind, func(t *testing.T) {
			root := private(t)
			b, s, trust, a := fixture(t, 1, nil)
			i, e := Install(root, "fixture-host", b, s, trust, a, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "revoked":
				i.Approval.Revoked = true
			case "expired":
				i.Approval.WindowEnd = time.Now().Add(-time.Minute)
			case "disabled":
				i.Enabled = false
			case "publisher-removed":
				trust.Publishers = map[string]string{}
			case "wrong-version":
				i.Version = "9.0.0"
			case "tampered-map":
				replacement := []byte("malicious replacement")
				if e = os.WriteFile(filepath.Join(root, "releases", i.Artifact, Files[0]), replacement, 0700); e != nil {
					t.Fatal(e)
				}
				i.Files[Files[0]] = hash(replacement)
			case "tampered-archive":
				if e = os.WriteFile(filepath.Join(root, "releases", i.Artifact, "approved-bundle.tar"), []byte("changed"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e = Atomic(root, "installation.json", i); e != nil {
				t.Fatal(e)
			}
			_, e = Authorize(root, trust, "fixture-host", time.Now())
			if (e == nil) != (kind == "good") {
				t.Fatalf("authorization result %v", e)
			}
		})
	}
}
