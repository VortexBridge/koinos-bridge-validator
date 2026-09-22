//go:build linux
// +build linux

package host

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

var hostBinary = flag.String("host-binary", "", "compiled exact Linux host tool")
var hostChecker = flag.String("host-checker", "", "actual isolated candidate checker; requires no host mounts and /candidate/validator")

var hostBundle = flag.String("host-bundle", "", "compiled exact Linux tar bundle")

func TestLinuxBundleCLIInstallRunStop(t *testing.T) {
	if *hostBinary == "" || *hostBundle == "" {
		t.Skip("supply host binary and bundle for CLI acceptance")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as dedicated non-root user")
	}
	root := private(t)
	home := filepath.Join(root, "home")
	if e := os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(*hostBundle)
	if e != nil {
		t.Fatal(e)
	}
	_, s, _, a := fixture(t, 1, nil)
	s.Manifest.Artifacts[0].SHA256 = hash(b)
	s.Manifest.Artifacts[0].Size = uint64(len(b))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := operator.CanonicalRelease(s.Manifest)
	s.Signatures = []operator.ReleaseSignature{{Publisher: "fixture", Signature: hex.EncodeToString(ed25519.Sign(priv, raw))}}
	trust := operator.ReleaseTrust{SchemaVersion: 1, RequiredSignatures: 1, Publishers: map[string]string{"fixture": hex.EncodeToString(pub)}}
	v, e := operator.VerifyRelease(s, trust, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	a.Digest = v.Digest
	var candidate operator.CandidateResult
	var validatorRelease operator.SignedRelease
	if *hostChecker != "" {
		validatorBytes, e := os.ReadFile("/candidate/validator")
		if e != nil {
			t.Fatal(e)
		}
		checkerBytes, e := os.ReadFile(*hostChecker)
		if e != nil {
			t.Fatal(e)
		}
		vm := s.Manifest
		vm.Component = "validator"
		vm.ID = "actual-validator-fixture"
		vm.Artifacts = []operator.ReleaseArtifact{{Platform: s.Manifest.Artifacts[0].Platform, SHA256: hash(validatorBytes), Size: uint64(len(validatorBytes))}}
		canonical, e := operator.CanonicalRelease(vm)
		if e != nil {
			t.Fatal(e)
		}
		validatorRelease = operator.SignedRelease{Manifest: vm, Signatures: []operator.ReleaseSignature{{Publisher: "fixture", Signature: hex.EncodeToString(ed25519.Sign(priv, canonical))}}}
		verified, e := operator.VerifyRelease(validatorRelease, trust, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		candidate = operator.CandidateResult{ReleaseDigest: verified.Digest, Platform: vm.Artifacts[0].Platform, ArtifactSHA256: hash(validatorBytes), CheckerSHA256: hash(checkerBytes), StartedAt: time.Now(), Isolation: "local-docker-network-none-readonly-no-host-mounts-uid65532"}
		output, e := exec.Command(*hostChecker).Output()
		candidate.FinishedAt = time.Now()
		if e != nil {
			t.Fatalf("actual candidate checker failed: %v; report: %s", e, output)
		}
		if json.Unmarshal(output, &candidate.Report) != nil || operator.ValidateCandidateObservation(candidate.Report, candidate.ArtifactSHA256) != nil {
			t.Fatal("actual candidate report invalid")
		}
		a.ApprovedAt = time.Now() // Approve only after this actual candidate run finished.
		for name, value := range map[string]interface{}{"validator-release.json": validatorRelease, "candidate-result.json": candidate} {
			if e = Atomic(root, name, value); e != nil {
				t.Fatal(e)
			}
		}
		t.Log("actual isolated checker completed all eight observation-transfer checks")
	}
	for name, value := range map[string]interface{}{"release.json": s, "trust.json": trust, "approval.json": a} {
		if e = Atomic(root, name, value); e != nil {
			t.Fatal(e)
		}
	}
	localBundle := filepath.Join(root, "bundle.tar")
	if e = os.WriteFile(localBundle, b, 0600); e != nil {
		t.Fatal(e)
	}
	installed := filepath.Join(root, "installed")
	base := []string{"--root", installed}
	invoke := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(*hostBinary, append(base, args...)...)
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("CLI failed: %s", out)
		}
		return out
	}
	install := []string{"--instance", "fixture-host", "--bundle", localBundle, "--release", filepath.Join(root, "release.json"), "--trust", filepath.Join(root, "trust.json"), "--approval", filepath.Join(root, "approval.json"), "install"}
	invoke(install...)
	invoke(install...)
	before, _ := Read(installed)
	invoke("doctor")
	if *hostChecker != "" {
		args := []string{"--instance", "fixture-host", "--trust", filepath.Join(root, "trust.json"), "--validator-release", filepath.Join(root, "validator-release.json"), "--candidate-result", filepath.Join(root, "candidate-result.json"), "qualify"}
		invoke(args...)
		invoke(args...)
		var record struct {
			Schema int                      `json:"schemaVersion"`
			Result operator.CandidateResult `json:"result"`
		}
		evidence, e := os.ReadFile(filepath.Join(installed, "candidate.json"))
		if e != nil || json.Unmarshal(evidence, &record) != nil || record.Schema != 1 || record.Result.ArtifactSHA256 != before.Files["koinos-bridge-validator"] {
			t.Fatal("actual candidate import not bound to installed bytes")
		}
		t.Log("actual checker result imported twice into exact installed bundle")
	}
	invoke("--trust", filepath.Join(root, "trust.json"), "--instance", "fixture-host", "authorize")
	// Real bundled operator, no RPC bindings, no vault, isolated container network.
	cmd := exec.Command(*hostBinary, append(base, "run")...)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer cmd.Process.Kill()
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		conn, e := net.DialTimeout("tcp", "127.0.0.1:3021", 50*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		<-done
		t.Fatalf("operator did not listen: %s", output.String())
	}
	invoke("doctor") // Doctor is read-only and works while service holds its lease.
	other := exec.Command(*hostBinary, append(base, "uninstall")...)
	if other.Run() == nil {
		t.Fatal("uninstalled running host")
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case e = <-done:
		if e != nil {
			t.Fatal("stop failed", e)
		}
	case <-time.After(23 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("stop exceeded bound")
	}
	invoke("uninstall")
	invoke("uninstall")
	after, e := Read(installed)
	if e != nil || after.Enabled || after.Artifact != before.Artifact {
		t.Fatal("uninstall removed records")
	}
	state, e := os.Open(filepath.Join(installed, "state"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = state.Readdirnames(1)
	state.Close()
	if e == io.EOF {
		t.Fatal("operator state missing")
	}
	var public map[string]interface{}
	if json.Unmarshal(invoke("doctor"), &public) != nil || public["managedSigning"] != false {
		t.Fatal("misleading readiness")
	}
}
