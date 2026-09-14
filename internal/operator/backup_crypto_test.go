package operator

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupCryptoPrivateExecution(t *testing.T) {
	provider := backupTestCrypto(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	recipient := backupTestIdentity(t, provider, filepath.Join(dir, "identity"))
	private, err := provider.prepare(dir)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(private, "--recipient", recipient, "encrypt")
	cmd.Stdin = strings.NewReader("disposable synthetic encryption fixture")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	// This test supplies only the fixed synthetic message and a newly generated
	// public recipient, so its captured process diagnostic cannot contain user data.
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("private helper execution: %v %s", err, out)
	}
}
