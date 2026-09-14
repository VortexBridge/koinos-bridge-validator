package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"gopkg.in/yaml.v2"
)

func managedBackupFixture(t *testing.T) (*Store, string, CryptoProvider, string, ManagedBackupRequest) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	base, s := backupTestSource(t, root)
	provider := backupTestCrypto(t)
	helper, err := os.ReadFile(provider.Path)
	if err != nil {
		t.Fatal(err)
	}
	provider.Path = filepath.Join(root, "fixture-backup-crypto")
	if err := os.WriteFile(provider.Path, helper, 0700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "recovery-identity")
	recipient := backupTestIdentity(t, provider, identity)
	_, cfg, err := readBackupConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	cfg = publicBackupConfig(cfg)
	cfg.Bridge.EthereumRpc = "http://127.0.0.1:18599"
	cfg.Bridge.KoinosRpc = "http://127.0.0.1:18599"
	raw, _ := yaml.Marshal(cfg)
	mustBackupWrite(t, filepath.Join(base, "config.yml"), raw)
	mustBackupWrite(t, filepath.Join(base, "bridge", ".operator", "data-mode"), []byte("observation-only"))
	binary := filepath.Join(root, "validator")
	cmd := exec.Command("go", "build", "-o", binary, "../../cmd/koinos-bridge-validator")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture validator: %v %s", err, out)
	}
	executable, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(executable)
	registration, err := s.RegisterWorker(base, binary, hex.EncodeToString(hash[:]))
	if err != nil {
		t.Fatal(err)
	}
	policy := BackupPolicy{1, recipient, provider.Path, provider.SHA256}
	if err := s.ConfigureBackups(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	return s, base, provider, identity, ManagedBackupRequest{"snapshot-one", registrationDigest(registration), maintenanceDigest(policy)}
}
func waitManagedBackup(t *testing.T, s *Store, id string) ManagedBackup {
	t.Helper()
	until := time.Now().Add(20 * time.Second)
	for time.Now().Before(until) {
		inventory := s.ManagedBackups()
		for _, job := range inventory.Jobs {
			if job.Request.ID == id && job.State != "running" {
				return job
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("backup job did not complete")
	return ManagedBackup{}
}
func TestManagedBackupRoundTripIdempotenceAndIntegrity(t *testing.T) {
	s, _, provider, identity, req := managedBackupFixture(t)
	first, err := s.BeginManagedBackup(req)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := s.BeginManagedBackup(req)
	if err != nil || retry.Request != first.Request || !retry.StartedAt.Equal(first.StartedAt) {
		t.Fatal("retry created a different job", err)
	}
	job := waitManagedBackup(t, s, req.ID)
	if job.State != "complete" || job.Receipt == nil || job.Receipt.EthereumCheckpoint != 5 || job.Receipt.KoinosCheckpoint != 9 {
		t.Fatal("backup failed", job.Message)
	}
	verified, err := s.VerifyManagedBackup(req.ID)
	if err != nil || verified.State != "intact" {
		t.Fatal("archive integrity failed", err)
	}
	originalRecipient := s.ManagedBackups().Recipient
	if job.RecoveryRecipient != originalRecipient {
		t.Fatal("job lost its original recovery recipient")
	}
	rotated, err := s.readBackupPolicy()
	if err != nil {
		t.Fatal(err)
	}
	rotated.Recipient = backupTestIdentity(t, provider, filepath.Join(filepath.Dir(identity), "rotated-identity"))
	if err := s.ConfigureBackups(context.Background(), rotated); err != nil {
		t.Fatal(err)
	}
	if s.ManagedBackups().Jobs[0].RecoveryRecipient != originalRecipient {
		t.Fatal("new policy relabeled an old backup")
	}
	dir := s.dir
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.BeginManagedBackup(req)
	if err != nil || again.State != "complete" || again.Receipt.CiphertextSHA256 != job.Receipt.CiphertextSHA256 {
		t.Fatal("completed result lost after restart", err)
	}
	archive := filepath.Join(dir, "backups", req.ID, "archive.age")
	recovered, err := RestoreBackup(context.Background(), archive, filepath.Join(filepath.Dir(dir), "recovered"), identity, provider)
	if err != nil || recovered.EthereumCheckpoint != 5 || recovered.KoinosCheckpoint != 9 {
		t.Fatal("managed archive could not restore", err)
	}
	altered := req
	altered.PolicyDigest = strings.Repeat("a", 64)
	if _, err := reopened.BeginManagedBackup(altered); err == nil {
		t.Fatal("ID reused with changed recipient policy")
	}
	ciphertext, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	mustBackupWrite(t, archive, ciphertext)
	verified, err = reopened.VerifyManagedBackup(req.ID)
	if err != nil || verified.State != "damaged-or-missing" {
		t.Fatal("tampered ciphertext accepted", err)
	}
	if _, err := RestoreBackup(context.Background(), archive, filepath.Join(filepath.Dir(dir), "bad-restore"), identity, provider); err == nil {
		t.Fatal("corrupt archive restored")
	}
}
func TestManagedBackupFailuresRemainDurable(t *testing.T) {
	s, base, provider, _, req := managedBackupFixture(t)
	lease, err := worker.Acquire(filepath.Join(base, "bridge", ".operator"), "process.lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginManagedBackup(req); err != nil {
		t.Fatal(err)
	}
	job := waitManagedBackup(t, s, req.ID)
	if job.State != "failed" || job.Receipt != nil || !strings.Contains(job.Message, "stop the validator") {
		t.Fatal("active validator accepted", job)
	}
	lease.Close()
	if _, err := os.Stat(filepath.Join(s.dir, "backups", req.ID, "archive.age")); !os.IsNotExist(err) {
		t.Fatal("failed job published archive")
	}
	if again, err := s.BeginManagedBackup(req); err != nil || again.State != "failed" {
		t.Fatal("failed retry was restarted", err)
	}
	raw, err := os.ReadFile(filepath.Join(base, "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	mustBackupWrite(t, filepath.Join(base, "config.yml"), append(raw, []byte("\n# changed after review\n")...))
	req.ID = "changed-config"
	if _, err := s.BeginManagedBackup(req); err != nil {
		t.Fatal(err)
	}
	if job := waitManagedBackup(t, s, req.ID); job.State != "failed" || !strings.Contains(job.Message, "configuration changed") {
		t.Fatal("changed configuration accepted", job)
	}
	mustBackupWrite(t, filepath.Join(base, "config.yml"), raw)
	// Replacing the reviewed helper cannot cause the replacement to execute.
	mustBackupWrite(t, provider.Path, []byte("unreviewed replacement"))
	req.ID = "changed-helper"
	if _, err := s.BeginManagedBackup(req); err != nil {
		t.Fatal(err)
	}
	if job := waitManagedBackup(t, s, req.ID); job.State != "failed" || !strings.Contains(job.Message, "differs from local review") {
		t.Fatal("changed crypto helper accepted", job)
	}
}
func TestManagedBackupInterruptedJobCannotRestartOrOverwrite(t *testing.T) {
	s, _, _, _, req := managedBackupFixture(t)
	dir := filepath.Join(s.dir, "backups", req.ID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	job := ManagedBackup{SchemaVersion: 1, InstanceID: s.InstanceID(), Request: req, StartedAt: time.Now().UTC(), State: "running", Message: "synthetic interruption"}
	if err := s.writeManagedBackup(job); err != nil {
		t.Fatal(err)
	}
	mustBackupWrite(t, filepath.Join(dir, "archive.age"), []byte("unknown interrupted artifact"))
	root := s.dir
	s.Close()
	reopened, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	inventory := reopened.ManagedBackups()
	if len(inventory.Jobs) != 1 || inventory.Jobs[0].State != "recovery-required" {
		t.Fatal("interrupted work claimed success")
	}
	retry, err := reopened.BeginManagedBackup(req)
	if err != nil || retry.State != "recovery-required" {
		t.Fatal("interrupted backup restarted", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "archive.age"))
	if string(raw) != "unknown interrupted artifact" {
		t.Fatal("interrupted archive overwritten")
	}
	if _, err := reopened.VerifyManagedBackup(req.ID); err == nil {
		t.Fatal("interrupted artifact declared intact")
	}
}
func TestManagedBackupAPIHasNoPathOrRecipientAuthority(t *testing.T) {
	s, _, _, _, req := managedBackupFixture(t)
	server := NewServer(s, strings.Repeat("a", 64), "127.0.0.1:3021", []string{"http://127.0.0.1:5173"})
	call := func(path string, body interface{}, auth bool) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "http://127.0.0.1:3021"+path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if auth {
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		return w
	}
	if w := call("/v1/worker/backups/create", req, false); w.Code != 401 {
		t.Fatal("unauthenticated backup accepted", w.Code)
	}
	for _, field := range []string{"baseDir", "destination", "recipient", "cryptoPath", "identityFile"} {
		body := map[string]interface{}{"id": req.ID, "registrationDigest": req.RegistrationDigest, "policyDigest": req.PolicyDigest, field: "not-authorized"}
		if w := call("/v1/worker/backups/create", body, true); w.Code != 400 {
			t.Fatal("HTTP supplied backup authority", field, w.Code, w.Body.String())
		}
	}
	if w := call("/v1/worker/backups/create", req, true); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	if job := waitManagedBackup(t, s, req.ID); job.State != "complete" {
		t.Fatal(job.Message)
	}
	if w := call("/v1/worker/backups/verify", map[string]string{"id": "../outside"}, true); w.Code != 409 {
		t.Fatal("path traversal accepted", w.Code)
	}
}

func TestManagedBackupShutdownRetainsOwnershipUntilJobEnds(t *testing.T) {
	s, _, _, _, req := managedBackupFixture(t)
	s.workerMu.Lock()
	if _, err := s.BeginManagedBackup(req); err != nil {
		s.workerMu.Unlock()
		t.Fatal(err)
	}
	other := req
	other.ID = "overlapping"
	if _, err := s.BeginManagedBackup(other); err == nil {
		s.workerMu.Unlock()
		t.Fatal("overlapping backup accepted")
	}
	policy, err := s.readBackupPolicy()
	if err != nil {
		s.workerMu.Unlock()
		t.Fatal(err)
	}
	if err := s.ConfigureBackups(context.Background(), policy); err == nil {
		s.workerMu.Unlock()
		t.Fatal("policy replaced during active backup")
	}
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	until := time.Now().Add(time.Second)
	closed := false
	for time.Now().Before(until) {
		s.backupMu.Lock()
		closed = s.backupClosed
		s.backupMu.Unlock()
		if closed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !closed {
		s.workerMu.Unlock()
		t.Fatal("shutdown did not cancel backup")
	}
	if duplicate, err := OpenStore(s.dir); err == nil {
		duplicate.Close()
		s.workerMu.Unlock()
		t.Fatal("store ownership released while backup job was active")
	}
	s.workerMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	reopened, err := OpenStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	jobs := reopened.ManagedBackups().Jobs
	if len(jobs) != 1 || jobs[0].State != "failed" || jobs[0].Receipt != nil {
		t.Fatal("cancelled job claimed completion", jobs)
	}
}

func TestBackupReceiptCheckpointPrecisionAndLegacyRead(t *testing.T) {
	receipt := BackupReceipt{EthereumCheckpoint: ^uint64(0), KoinosCheckpoint: 1 << 63}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"ethereumCheckpoint":"18446744073709551615"`)) || !bytes.Contains(raw, []byte(`"koinosCheckpoint":"9223372036854775808"`)) {
		t.Fatal("browser receipt loses checkpoint precision")
	}
	legacy := bytes.ReplaceAll(bytes.ReplaceAll(raw, []byte(`"18446744073709551615"`), []byte(`18446744073709551615`)), []byte(`"9223372036854775808"`), []byte(`9223372036854775808`))
	for _, value := range [][]byte{raw, legacy} {
		var decoded BackupReceipt
		if err := json.Unmarshal(value, &decoded); err != nil || decoded != receipt {
			t.Fatal("receipt precision or legacy compatibility lost", err)
		}
	}
	for _, value := range []string{`{"ethereumCheckpoint":1e3,"koinosCheckpoint":0}`, `{"ethereumCheckpoint":-1,"koinosCheckpoint":0}`, `{"ethereumCheckpoint":null,"koinosCheckpoint":0}`, `{"ethereumCheckpoint":"18446744073709551616","koinosCheckpoint":"0"}`, `{"ethereumCheckpoint":"0","koinosCheckpoint":"0","extra":true}`} {
		var decoded BackupReceipt
		if json.Unmarshal([]byte(value), &decoded) == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
}
