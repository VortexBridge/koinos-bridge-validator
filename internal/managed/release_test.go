package managed

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func installedFixture(t *testing.T) (*InstalledVerifier, Policy) {
	t.Helper()
	root := dir(t)
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, name := range host.Files {
		b := []byte("approved fixture executable")
		if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0700, Size: int64(len(b))}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(root, "bundle.tar")
	if e := os.WriteFile(file, archive.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	archiveHash, e := fileDigest(file, host.MaxBundle)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	m := operator.ReleaseManifest{SchemaVersion: 1, ID: "managed-fixture", Component: "operator", Version: "0.3.0", Sequence: 1, Channel: "candidate", SourceCommit: "1111111111111111111111111111111111111111", CreatedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), CompatibleFrom: []string{"0.3.0"}, ConfigSchema: 1, DatabaseSchema: 1, SigningCodec: "fixture", Recovery: "fixture recovery", TestEvidence: []string{"synthetic test"}, Artifacts: []operator.ReleaseArtifact{{Platform: "linux-" + runtime.GOARCH, SHA256: archiveHash, Size: uint64(archive.Len())}}}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := operator.CanonicalRelease(m)
	signed := operator.SignedRelease{Manifest: m, Signatures: []operator.ReleaseSignature{{Publisher: "synthetic", Signature: hex.EncodeToString(ed25519.Sign(priv, raw))}}}
	trust := operator.ReleaseTrust{SchemaVersion: 1, RequiredSignatures: 1, Publishers: map[string]string{"synthetic": hex.EncodeToString(pub)}}
	verified, e := operator.VerifyRelease(signed, trust, now)
	if e != nil {
		t.Fatal(e)
	}
	p := policy()
	approval := operator.ReleaseApproval{InstanceID: p.Instance, Digest: verified.Digest, Component: "operator", Version: m.Version, Sequence: 1, WindowStart: now.Add(-time.Minute), WindowEnd: now.Add(time.Hour), ApprovedAt: now}
	installation, e := host.Install(root, p.Instance, archive.Bytes(), signed, trust, approval, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = host.Atomic(root, "publishers.json", trust); e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(root, "config.json")
	if e = os.WriteFile(config, []byte(`{"synthetic":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	p.ConfigSHA256, e = fileDigest(config, 128<<10)
	if e != nil {
		t.Fatal(e)
	}
	executable := filepath.Join(root, "releases", installation.Artifact, "koinos-bridge-validator")
	p.ArtifactSHA256, e = fileDigest(executable, host.MaxBundle)
	if e != nil {
		t.Fatal(e)
	}
	// Independent signed validator release binds the member executable, not TAR.
	vm := m
	vm.Component = "validator"
	vm.ID = "validator-fixture"
	vm.Artifacts = []operator.ReleaseArtifact{{Platform: installation.Platform, SHA256: installation.Files["koinos-bridge-validator"], Size: uint64(len("approved fixture executable"))}}
	vb, _ := operator.CanonicalRelease(vm)
	vs := operator.SignedRelease{Manifest: vm, Signatures: []operator.ReleaseSignature{{Publisher: "synthetic", Signature: hex.EncodeToString(ed25519.Sign(priv, vb))}}}
	vv, err := operator.VerifyRelease(vs, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	report := operator.CandidateReport{SchemaVersion: 2, Scope: "isolated-observation-transfer-v2", ArtifactSHA256: installation.Files["koinos-bridge-validator"], State: "checks-passed", Checks: []string{"pinned-networks-and-both-direction-transfer-records", "observation-produced-zero-signatures", "signature-exchange-refused", "duplicate-process-excluded", "network-mismatch-pauses-and-recovers", "crash-restart-checkpoints-and-records-retained", "graceful-stop", "only-read-rpc-methods"}}
	qualification := CandidateQualification{Schema: 1, ValidatorRelease: vs, Result: operator.CandidateResult{ReleaseDigest: vv.Digest, Platform: installation.Platform, ArtifactSHA256: report.ArtifactSHA256, CheckerSHA256: installation.Files["vortex-candidate-check"], StartedAt: now.Add(-20 * time.Second), FinishedAt: now.Add(-10 * time.Second), Report: report, Isolation: "local-docker-network-none-readonly-no-host-mounts-uid65532"}}
	if e = host.Atomic(root, "candidate.json", qualification); e != nil {
		t.Fatal(e)
	}
	v, e := NewInstalledVerifier(root, filepath.Join(root, "publishers.json"), config, filepath.Join(root, "candidate.json"), &fixtureVerifier{edit: func(e *Evidence) { e.ReleaseApproved = false }})
	if e != nil {
		t.Fatal(e)
	}
	// Test only substitution. Production constructor always uses os.Executable.
	v.executable = executable
	return v, p
}
func TestInstalledVerifierUsesLiveApprovalAndExactBytes(t *testing.T) {
	for _, kind := range []string{"good", "configuration", "executable", "revoked", "publisher", "instance", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			v, p := installedFixture(t)
			switch kind {
			case "configuration":
				if e := os.WriteFile(v.config, []byte("changed config"), 0600); e != nil {
					t.Fatal(e)
				}
			case "executable":
				if e := os.WriteFile(v.executable, []byte("changed executable"), 0700); e != nil {
					t.Fatal(e)
				}
			case "publisher":
				if e := host.Atomic(v.root, "publishers.json", operator.ReleaseTrust{}); e != nil {
					t.Fatal(e)
				}
			case "instance":
				p.Instance = "other-host"
			case "revoked", "disabled":
				i, e := host.Read(v.root)
				if e != nil {
					t.Fatal(e)
				}
				if kind == "revoked" {
					i.Approval.Revoked = true
				} else {
					i.Enabled = false
				}
				if e = host.Atomic(v.root, "installation.json", i); e != nil {
					t.Fatal(e)
				}
			}
			e, err := v.Inspect(context.Background(), p)
			if kind == "good" {
				if err != nil || !e.ReleaseApproved {
					t.Fatal("approved artifact refused", err)
				}
			} else if err == nil {
				t.Fatal("invalid local evidence accepted")
			}
		})
	}
}
