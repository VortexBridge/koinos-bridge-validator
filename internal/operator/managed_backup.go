package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// BackupPolicy is installed locally. No management request supplies paths,
// executable bytes, recovery identities or a replacement encryption recipient.
type BackupPolicy struct {
	SchemaVersion int    `json:"schemaVersion"`
	Recipient     string `json:"recipient"`
	CryptoPath    string `json:"cryptoPath"`
	CryptoSHA256  string `json:"cryptoSha256"`
}
type ManagedBackupRequest struct {
	ID                 string `json:"id"`
	RegistrationDigest string `json:"registrationDigest"`
	PolicyDigest       string `json:"policyDigest"`
}
type ManagedBackup struct {
	RecoveryRecipient string               `json:"recoveryRecipient,omitempty"`
	SchemaVersion     int                  `json:"schemaVersion"`
	InstanceID        string               `json:"instanceId"`
	Request           ManagedBackupRequest `json:"request"`
	StartedAt         time.Time            `json:"startedAt"`
	FinishedAt        time.Time            `json:"finishedAt,omitempty"`
	State             string               `json:"state"`
	Message           string               `json:"message"`
	Receipt           *BackupReceipt       `json:"receipt,omitempty"`
}
type BackupInventory struct {
	Configured   bool            `json:"configured"`
	PolicyDigest string          `json:"policyDigest,omitempty"`
	Recipient    string          `json:"recipient,omitempty"`
	CryptoSHA256 string          `json:"cryptoSha256,omitempty"`
	Jobs         []ManagedBackup `json:"jobs"`
	Problem      string          `json:"problem,omitempty"`
	Notice       string          `json:"notice"`
}
type BackupVerification struct {
	ID        string    `json:"id"`
	CheckedAt time.Time `json:"checkedAt"`
	State     string    `json:"state"`
	Message   string    `json:"message"`
}

func (s *Store) readBackupPolicy() (BackupPolicy, error) {
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, "backup-policy.json"), 8192)
	if err != nil {
		return BackupPolicy{}, errors.New("configure a reviewed backup helper and public recovery recipient with the local backup-configure command")
	}
	var p BackupPolicy
	if strictJSON(raw, &p) != nil || p.SchemaVersion != 1 || !filepath.IsAbs(p.CryptoPath) || !hexHash.MatchString(p.CryptoSHA256) || !strings.HasPrefix(p.Recipient, "age1") || len(p.Recipient) != 62 {
		return BackupPolicy{}, errors.New("local backup policy is invalid")
	}
	return p, nil
}
func (s *Store) ConfigureBackups(ctx context.Context, p BackupPolicy) error {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	if s.backupClosed || s.backupActive != "" {
		return errors.New("backup service is closed or a backup is active")
	}
	if p.SchemaVersion != 1 || !filepath.IsAbs(p.CryptoPath) || !hexHash.MatchString(p.CryptoSHA256) || !strings.HasPrefix(p.Recipient, "age1") || len(p.Recipient) != 62 {
		return errors.New("reviewed absolute helper path, SHA-256 and public age X25519 recipient required")
	}
	temp, err := os.MkdirTemp(s.dir, ".backup-policy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	binary, err := (CryptoProvider{p.CryptoPath, p.CryptoSHA256}).prepare(temp)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Validate the public recipient using the exact reviewed provider before saving.
	if err := runCrypto(ctx, binary, strings.NewReader("Vortex backup recipient validation"), io.Discard, "--recipient", p.Recipient, "encrypt"); err != nil {
		return err
	}
	raw, _ := json.Marshal(p)
	return atomicFile(s.dir, "backup-policy.json", raw)
}
func (s *Store) readManagedBackup(id string) (ManagedBackup, error) {
	if !slug.MatchString(id) {
		return ManagedBackup{}, errors.New("invalid backup ID")
	}
	dir := filepath.Join(s.dir, "backups", id)
	if err := existingPrivateDir(dir); err != nil {
		return ManagedBackup{}, err
	}
	raw, err := worker.ReadPrivateFile(filepath.Join(dir, "job.json"), 16384)
	if err != nil {
		return ManagedBackup{}, errors.New("backup job unavailable or incomplete")
	}
	var job ManagedBackup
	if strictJSON(raw, &job) != nil || job.SchemaVersion != 1 || job.InstanceID != s.InstanceID() || job.Request.ID != id || !hexHash.MatchString(job.Request.PolicyDigest) || !hexHash.MatchString(job.Request.RegistrationDigest) || job.StartedAt.IsZero() {
		return job, errors.New("invalid backup job record")
	}
	if job.RecoveryRecipient != "" && (!strings.HasPrefix(job.RecoveryRecipient, "age1") || len(job.RecoveryRecipient) != 62) {
		return job, errors.New("invalid recorded recovery recipient")
	}
	switch job.State {
	case "running":
		if job.Receipt != nil || !job.FinishedAt.IsZero() {
			return job, errors.New("contradictory running backup record")
		}
	case "failed":
		if job.Receipt != nil || job.FinishedAt.Before(job.StartedAt) {
			return job, errors.New("invalid failed backup record")
		}
	case "complete":
		r := job.Receipt
		if r == nil || job.FinishedAt.Before(job.StartedAt) || r.CreatedAt.Before(job.StartedAt) || r.CreatedAt.After(job.FinishedAt) || !hexHash.MatchString(r.ManifestSHA256) || !hexHash.MatchString(r.CiphertextSHA256) || r.Bytes <= 0 || r.Bytes > backupArchiveLimit+16<<20 || r.State != "encrypted-backup-created" {
			return job, errors.New("invalid completed backup receipt")
		}
	default:
		return job, errors.New("unknown backup job state")
	}
	return job, nil
}
func existingPrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("backup directory is missing, nonprivate or a symlink")
	}
	return nil
}
func (s *Store) writeManagedBackup(job ManagedBackup) error {
	raw, _ := json.Marshal(job)
	return atomicFile(filepath.Join(s.dir, "backups", job.Request.ID), "job.json", raw)
}
func (s *Store) ManagedBackups() BackupInventory {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	result := BackupInventory{Jobs: []ManagedBackup{}, Notice: "Encrypted snapshots of a stopped validator. Recovery keys and RPC credentials are excluded. A created or intact archive is not a tested restore or permission to activate a signer. Archives stay under this operator's backups/<ID>/archive.age directory."}
	p, err := s.readBackupPolicy()
	if err == nil {
		result.Configured = true
		result.PolicyDigest = maintenanceDigest(p)
		result.Recipient = p.Recipient
		result.CryptoSHA256 = p.CryptoSHA256
	} else {
		result.Problem = err.Error()
	}
	root := filepath.Join(s.dir, "backups")
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return result
	}
	if err := existingPrivateDir(root); err != nil {
		result.Problem = err.Error()
		return result
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 32 {
		result.Problem = "backup inventory unavailable or exceeds 32 jobs"
		return result
	}
	for _, e := range entries {
		job, err := s.readManagedBackup(e.Name())
		if err != nil {
			result.Problem = "one or more backup records require local recovery"
			continue
		}
		if job.State == "running" && s.backupActive != job.Request.ID {
			job.State = "recovery-required"
			job.Message = "Operator stopped before recording a terminal result. Inspect the retained files locally; this job will not restart or overwrite them."
		}
		result.Jobs = append(result.Jobs, job)
	}
	sort.Slice(result.Jobs, func(i, j int) bool { return result.Jobs[i].StartedAt.After(result.Jobs[j].StartedAt) })
	return result
}
func (s *Store) BeginManagedBackup(req ManagedBackupRequest) (ManagedBackup, error) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	empty := ManagedBackup{}
	if s.backupClosed {
		return empty, errors.New("backup service is closing")
	}
	if !slug.MatchString(req.ID) || !hexHash.MatchString(req.RegistrationDigest) || !hexHash.MatchString(req.PolicyDigest) {
		return empty, errors.New("backup ID and reviewed registration/policy digests required")
	}
	root := filepath.Join(s.dir, "backups")
	if err := worker.PrivateDir(root); err != nil {
		return empty, err
	}
	dir := filepath.Join(root, req.ID)
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		job, err := s.readManagedBackup(req.ID)
		if err != nil {
			return empty, err
		}
		if job.Request != req {
			return empty, errors.New("backup ID was already used with different inputs")
		}
		if job.State == "running" && s.backupActive != req.ID {
			job.State = "recovery-required"
			job.Message = "Interrupted job requires local review; retry cannot replace its files."
		}
		return job, nil
	}
	if s.backupActive != "" {
		return empty, errors.New("another backup is still running")
	}
	p, err := s.readBackupPolicy()
	if err != nil {
		return empty, err
	}
	if maintenanceDigest(p) != req.PolicyDigest {
		return empty, errors.New("backup policy changed; review the recovery recipient again")
	}
	r, err := s.registration()
	if err != nil || registrationDigest(r) != req.RegistrationDigest {
		return empty, errors.New("worker registration changed or is unavailable")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) >= 32 {
		return empty, errors.New("backup store is full; locally review retention before creating another archive")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return empty, err
	}
	job := ManagedBackup{RecoveryRecipient: p.Recipient, SchemaVersion: 1, InstanceID: s.InstanceID(), Request: req, StartedAt: time.Now().UTC(), State: "running", Message: "Checking the stopped worker and creating an encrypted snapshot. The worker will not be stopped or restarted by this job."}
	if err := s.writeManagedBackup(job); err != nil {
		return empty, err
	}
	if err := syncDirectory(root); err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	s.backupActive = req.ID
	s.backupCancel = cancel
	s.backupWG.Add(1)
	go func(job ManagedBackup) {
		defer s.backupWG.Done()
		defer cancel()
		receipt, err := s.runManagedBackup(ctx, req, p)
		s.backupMu.Lock()
		defer s.backupMu.Unlock()
		job.FinishedAt = time.Now().UTC()
		job.State = "complete"
		job.Message = "Encrypted snapshot created. Copy the archive off this host and test recovery using the local recovery identity."
		job.Receipt = &receipt
		if err != nil {
			job.State = "failed"
			job.Message = err.Error()
			var fsError *os.PathError
			if errors.As(err, &fsError) {
				job.Message = "Backup filesystem operation failed; check private directory access and free disk space on this host."
			}
			job.Receipt = nil
		}
		// If this write fails, the durable running record remains explicitly uncertain.
		s.writeManagedBackup(job)
		s.backupActive = ""
		s.backupCancel = nil
	}(job)
	return job, nil
}
func (s *Store) runManagedBackup(ctx context.Context, req ManagedBackupRequest, p BackupPolicy) (BackupReceipt, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	r, err := s.registration()
	if err != nil || registrationDigest(r) != req.RegistrationDigest {
		return BackupReceipt{}, errors.New("worker registration changed before backup")
	}
	raw, _, err := workerConfig(r.BaseDir)
	if err != nil {
		return BackupReceipt{}, errors.New("registered worker configuration is unavailable or unsafe")
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != r.ConfigSHA256 {
		return BackupReceipt{}, errors.New("worker configuration changed since registration")
	}
	return s.createBackupLocked(ctx, r.BaseDir, filepath.Join(s.dir, "backups", req.ID, "archive.age"), p.Recipient, CryptoProvider{p.CryptoPath, p.CryptoSHA256}, r.ConfigSHA256)
}
func (s *Store) VerifyManagedBackup(id string) (BackupVerification, error) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	result := BackupVerification{ID: id, CheckedAt: time.Now().UTC(), State: "unverified", Message: "Ciphertext integrity only; decrypt and restore locally to establish recoverability."}
	if err := existingPrivateDir(filepath.Join(s.dir, "backups")); err != nil {
		return result, err
	}
	job, err := s.readManagedBackup(id)
	if err != nil {
		return result, err
	}
	if job.State != "complete" {
		return result, errors.New("backup has no complete receipt")
	}
	f, err := OpenBoundedArtifact(filepath.Join(s.dir, "backups", id, "archive.age"), backupArchiveLimit+16<<20)
	if err != nil {
		result.State = "damaged-or-missing"
		return result, nil
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, job.Receipt.Bytes+1))
	if err != nil || n != job.Receipt.Bytes || hex.EncodeToString(h.Sum(nil)) != job.Receipt.CiphertextSHA256 {
		result.State = "damaged-or-missing"
	} else {
		result.State = "intact"
	}
	result.CheckedAt = time.Now().UTC()
	return result, nil
}
func (s *Store) closeBackupJobs() {
	s.backupMu.Lock()
	s.backupClosed = true
	if s.backupCancel != nil {
		s.backupCancel()
	}
	s.backupMu.Unlock()
	s.backupWG.Wait()
}
