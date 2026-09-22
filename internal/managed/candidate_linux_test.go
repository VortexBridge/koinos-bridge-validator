//go:build linux
// +build linux

package managed

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

var candidateHostBinary = flag.String("candidate-host-binary", "", "actual Linux host command for candidate import acceptance")

func TestLinuxHostCandidateImportCommand(t *testing.T) {
	if *candidateHostBinary == "" {
		t.Skip("provide actual host binary for CLI acceptance")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as non-root")
	}
	v, p := installedFixture(t)
	raw, e := worker.ReadPrivateFile(v.candidate, 128<<10)
	if e != nil {
		t.Fatal(e)
	}
	var q CandidateQualification
	if host.JSON(raw, &q) != nil {
		t.Fatal("fixture decode")
	}
	if e = host.Atomic(v.root, "validator-release.json", q.ValidatorRelease); e != nil {
		t.Fatal(e)
	}
	if e = host.Atomic(v.root, "candidate-result.json", q.Result); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(v.candidate); e != nil {
		t.Fatal(e)
	}
	run := func() ([]byte, error) {
		return exec.Command(*candidateHostBinary, "--root", v.root, "--instance", p.Instance, "--trust", v.trust, "--validator-release", filepath.Join(v.root, "validator-release.json"), "--candidate-result", filepath.Join(v.root, "candidate-result.json"), "qualify").CombinedOutput()
	}
	for i := 0; i < 2; i++ {
		output, e := run()
		if e != nil {
			t.Fatalf("actual import command failed: %v %s", e, output)
		}
		var result struct {
			CandidateQualified bool `json:"candidateQualified"`
			ManagedSigning     bool `json:"managedSigning"`
		}
		if json.Unmarshal(output, &result) != nil || !result.CandidateQualified || result.ManagedSigning {
			t.Fatal("incorrect readiness response")
		}
	}
	before, e := worker.ReadPrivateFile(v.candidate, 128<<10)
	if e != nil {
		t.Fatal(e)
	}
	q.Result.CheckerSHA256 = strings.Repeat("f", 64)
	if e = host.Atomic(v.root, "candidate-result.json", q.Result); e != nil {
		t.Fatal(e)
	}
	if _, e = run(); e == nil {
		t.Fatal("CLI accepted wrong checker")
	}
	after, e := worker.ReadPrivateFile(v.candidate, 128<<10)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("CLI destroyed previous qualification")
	}
}
