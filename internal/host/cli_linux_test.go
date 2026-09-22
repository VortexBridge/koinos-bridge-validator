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
