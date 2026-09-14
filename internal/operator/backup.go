package operator

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"gopkg.in/yaml.v2"
)

const backupFileLimit int64 = 256 << 20
const backupArchiveLimit int64 = 1 << 30

var backupDatabases = []string{"metadata", "ethereum_transactions", "koinos_transactions"}

type BackupEntry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type BackupManifest struct {
	SchemaVersion      int           `json:"schemaVersion"`
	Format             string        `json:"format"`
	CreatedAt          time.Time     `json:"createdAt"`
	SourceInstanceID   string        `json:"sourceInstanceId"`
	SourceMode         string        `json:"sourceMode"`
	SourceConfigSHA256 string        `json:"sourceConfigSha256"`
	Entries            []BackupEntry `json:"entries"`
}
type BackupReceipt struct {
	ManifestSHA256     string    `json:"manifestSha256"`
	CiphertextSHA256   string    `json:"ciphertextSha256"`
	Bytes              int64     `json:"bytes"`
	CreatedAt          time.Time `json:"createdAt"`
	State              string    `json:"state"`
	EthereumCheckpoint uint64    `json:"ethereumCheckpoint"`
	KoinosCheckpoint   uint64    `json:"koinosCheckpoint"`
}
type CryptoProvider struct {
	Path   string
	SHA256 string
}
type sizeWriter struct {
	writer io.Writer
	left   int64
}

func (w *sizeWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.left {
		return 0, errors.New("backup size limit exceeded")
	}
	n, err := w.writer.Write(p)
	w.left -= int64(n)
	return n, err
}
func (p CryptoProvider) prepare(dir string) (string, error) {
	if !hexHash.MatchString(p.SHA256) {
		return "", errors.New("reviewed backup crypto SHA-256 required")
	}
	source, err := OpenBoundedArtifact(p.Path, 64<<20)
	if err != nil {
		return "", err
	}
	defer source.Close()
	name := filepath.Join(dir, "backup-crypto")
	out, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0500)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), io.LimitReader(source, 64<<20+1))
	closeErr := out.Close()
	if err != nil || closeErr != nil || hex.EncodeToString(h.Sum(nil)) != p.SHA256 {
		return "", errors.New("backup crypto binary differs from local review")
	}
	return name, nil
}
func runCrypto(ctx context.Context, binary string, input io.Reader, output io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = input
	cmd.Stdout = output
	cmd.Stderr = &limitedBuffer{limit: 1024}
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if err := cmd.Run(); err != nil {
		var launch *os.PathError
		if errors.As(err, &launch) {
			return errors.New("reviewed backup crypto helper could not start; the private staging filesystem must permit executable files")
		}
		return errors.New("backup encryption/decryption failed; check recovery identity, provider and archive integrity")
	}
	return nil
}
func readBackupConfig(base string) ([]byte, util.YamlConfig, error) {
	raw, err := worker.ReadPrivateFile(filepath.Join(base, "config.yml"), 128<<10)
	if err != nil {
		return nil, util.YamlConfig{}, err
	}
	var cfg util.YamlConfig
	if yaml.UnmarshalStrict(raw, &cfg) != nil {
		return nil, cfg, errors.New("backup requires valid typed config.yml")
	}
	return raw, cfg, nil
}
func publicBackupConfig(cfg util.YamlConfig) util.YamlConfig {
	b := cfg.Bridge
	b.ObservationOnly = true
	b.Reset = false
	b.EthereumPK = ""
	b.KoinosPK = ""
	b.EthereumPKFile = ""
	b.KoinosPKFile = ""
	b.EthereumRpc = ""
	b.KoinosRpc = ""
	b.ApiUrl = ""
	b.LogLevel = "info"
	b.EthereumBlockStart = 0
	b.KoinosBlockStart = 0
	vals := map[string]util.ValidatorConfig{}
	for name, v := range b.Validators {
		v.ApiUrl = ""
		vals[name] = v
	}
	b.Validators = vals
	tokens := map[string]util.TokenConfig{}
	for name, v := range b.Tokens {
		tokens[name] = v
	}
	b.Tokens = tokens
	return util.YamlConfig{Bridge: b}
}
func openSnapshotDatabases(base string) ([]*badger.DB, error) {
	dbs := []*badger.DB{}
	for _, name := range backupDatabases {
		path := filepath.Join(base, "bridge", name)
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			for _, db := range dbs {
				db.Close()
			}
			return nil, errors.New("all three validator databases must exist")
		}
		// The real Badger directory locks also exclude legacy writers that do not use
		// the new worker process lease. All three are held for the entire snapshot.
		db, err := badger.Open(badger.DefaultOptions(path).WithReadOnly(true).WithLogger(nil))
		if err != nil {
			for _, db := range dbs {
				db.Close()
			}
			return nil, errors.New("database is active, corrupt or requires recovery before backup")
		}
		dbs = append(dbs, db)
	}
	return dbs, nil
}
func fileEntry(dir, name string) (BackupEntry, error) {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return BackupEntry{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > backupFileLimit {
		return BackupEntry{}, errors.New("invalid backup export")
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	return BackupEntry{name, n, hex.EncodeToString(h.Sum(nil))}, err
}

func (s *Store) CreateBackup(ctx context.Context, base, destination, recipient string, provider CryptoProvider) (BackupReceipt, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if recipient == "" {
		return BackupReceipt{}, errors.New("age public recovery recipient required")
	}
	if !filepath.IsAbs(base) || !filepath.IsAbs(destination) {
		return BackupReceipt{}, errors.New("backup paths must be absolute")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return BackupReceipt{}, errors.New("backup destination must not exist")
	}
	lease, err := worker.Acquire(filepath.Join(base, "bridge", ".operator"), "process.lock")
	if err != nil {
		return BackupReceipt{}, errors.New("stop the validator before a consistent backup")
	}
	defer lease.Close()
	raw, cfg, err := readBackupConfig(base)
	if err != nil {
		return BackupReceipt{}, err
	}
	if err := worker.CheckNetworkBinding(filepath.Join(base, "bridge", ".operator"), networkBinding(cfg), true); err != nil {
		return BackupReceipt{}, err
	}
	dbs, err := openSnapshotDatabases(base)
	if err != nil {
		return BackupReceipt{}, err
	}
	defer func() {
		for _, db := range dbs {
			db.Close()
		}
	}()
	metadata, err := store.NewMetadataStore(&store.BadgerBackend{DB: dbs[0]}).Get()
	if err != nil {
		return BackupReceipt{}, errors.New("source checkpoint metadata is invalid")
	}
	temp, err := os.MkdirTemp(s.dir, ".backup-")
	if err != nil {
		return BackupReceipt{}, err
	}
	defer os.RemoveAll(temp)
	crypto, err := provider.prepare(temp)
	if err != nil {
		return BackupReceipt{}, err
	}
	if err := os.Mkdir(filepath.Join(temp, "databases"), 0700); err != nil {
		return BackupReceipt{}, err
	}
	names := []string{"config.yml", "operator-public.json"}
	publicCfg, _ := yaml.Marshal(publicBackupConfig(cfg))
	if err := os.WriteFile(filepath.Join(temp, "config.yml"), publicCfg, 0600); err != nil {
		return BackupReceipt{}, err
	}
	revision, profiles, events := s.Summary()
	public, _ := json.Marshal(map[string]interface{}{"schemaVersion": 1, "revision": revision, "profiles": profiles, "events": events, "notice": "Historical public configuration only. RPC credentials, keys, access tokens, live release approvals and executable registrations are excluded."})
	if err := os.WriteFile(filepath.Join(temp, "operator-public.json"), public, 0600); err != nil {
		return BackupReceipt{}, err
	}
	for i, db := range dbs {
		name := "databases/" + backupDatabases[i] + ".backup"
		out, err := os.OpenFile(filepath.Join(temp, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return BackupReceipt{}, err
		}
		_, err = db.Backup(&sizeWriter{out, backupFileLimit}, 0)
		closeErr := out.Close()
		if err != nil || closeErr != nil {
			return BackupReceipt{}, errors.New("database export failed or exceeded size limit")
		}
		if err := validateDatabaseExport(filepath.Join(temp, name)); err != nil {
			return BackupReceipt{}, err
		}
		names = append(names, name)
	}
	mode := "legacy-unknown"
	if b, err := worker.ReadPrivateFile(filepath.Join(base, "bridge", ".operator", "data-mode"), 32); err == nil {
		mode = string(b)
	}
	configHash := sha256.Sum256(raw)
	manifest := BackupManifest{1, "badger-v3-logical-v1", time.Now().UTC(), cfg.Bridge.InstanceID, mode, hex.EncodeToString(configHash[:]), []BackupEntry{}}
	sort.Strings(names)
	for _, name := range names {
		entry, err := fileEntry(temp, name)
		if err != nil {
			return BackupReceipt{}, err
		}
		manifest.Entries = append(manifest.Entries, entry)
	}
	latest, _, err := readBackupConfig(base)
	if err != nil || sha256.Sum256(latest) != configHash {
		return BackupReceipt{}, errors.New("configuration changed during backup")
	}
	manifestBytes, _ := json.Marshal(manifest)
	mh := sha256.Sum256(manifestBytes)
	archive, err := os.CreateTemp(temp, "archive-")
	if err != nil {
		return BackupReceipt{}, err
	}
	defer archive.Close()
	tw := tar.NewWriter(&sizeWriter{archive, backupArchiveLimit})
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(manifestBytes)), Mode: 0600, Format: tar.FormatUSTAR}); err != nil {
		return BackupReceipt{}, err
	}
	if _, err := tw.Write(manifestBytes); err != nil {
		return BackupReceipt{}, err
	}
	for _, entry := range manifest.Entries {
		if err := tw.WriteHeader(&tar.Header{Name: entry.Name, Size: entry.Size, Mode: 0600, Format: tar.FormatUSTAR}); err != nil {
			return BackupReceipt{}, err
		}
		f, err := os.Open(filepath.Join(temp, entry.Name))
		if err != nil {
			return BackupReceipt{}, err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		if err != nil {
			return BackupReceipt{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return BackupReceipt{}, err
	}
	if _, err := archive.Seek(0, 0); err != nil {
		return BackupReceipt{}, err
	}
	// Build ciphertext beside its final path, then publish without replacing any
	// existing destination. A partial ciphertext is never a successful backup.
	ciphertext, err := os.CreateTemp(filepath.Dir(destination), ".backup-encrypted-")
	if err != nil {
		return BackupReceipt{}, err
	}
	defer os.Remove(ciphertext.Name())
	defer ciphertext.Close()
	h := sha256.New()
	bounded := &sizeWriter{io.MultiWriter(ciphertext, h), backupArchiveLimit + 16<<20}
	if err := runCrypto(ctx, crypto, archive, bounded, "--recipient", recipient, "encrypt"); err != nil {
		return BackupReceipt{}, err
	}
	if err := ciphertext.Sync(); err != nil {
		return BackupReceipt{}, err
	}
	info, err := ciphertext.Stat()
	if err != nil {
		return BackupReceipt{}, err
	}
	if err := os.Link(ciphertext.Name(), destination); err != nil {
		return BackupReceipt{}, errors.New("backup destination appeared or cannot be published atomically")
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return BackupReceipt{}, err
	}
	return BackupReceipt{ManifestSHA256: hex.EncodeToString(mh[:]), CiphertextSHA256: hex.EncodeToString(h.Sum(nil)), Bytes: info.Size(), CreatedAt: manifest.CreatedAt, State: "encrypted-backup-created", EthereumCheckpoint: metadata.LastEthereumBlockParsed, KoinosCheckpoint: metadata.LastKoinosBlockParsed}, nil
}
func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func extractBackup(archive io.Reader, temp string) (BackupManifest, string, error) {
	tr := tar.NewReader(archive)
	header, err := tr.Next()
	if err != nil || header.Name != "manifest.json" || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > 65536 {
		return BackupManifest{}, "", errors.New("invalid backup manifest entry")
	}
	raw, err := io.ReadAll(tr)
	if err != nil {
		return BackupManifest{}, "", err
	}
	mh := sha256.Sum256(raw)
	var manifest BackupManifest
	if strictJSON(raw, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Format != "badger-v3-logical-v1" || len(manifest.Entries) != 5 || !hexHash.MatchString(manifest.SourceConfigSHA256) {
		return manifest, "", errors.New("unsupported backup manifest")
	}
	allowed := map[string]bool{"config.yml": true, "operator-public.json": true, "databases/metadata.backup": true, "databases/ethereum_transactions.backup": true, "databases/koinos_transactions.backup": true}
	for _, entry := range manifest.Entries {
		if !allowed[entry.Name] || entry.Size < 0 || entry.Size > backupFileLimit || !hexHash.MatchString(entry.SHA256) {
			return manifest, "", errors.New("invalid or duplicate backup entry")
		}
		delete(allowed, entry.Name)
		header, err := tr.Next()
		if err != nil || header.Name != entry.Name || header.Typeflag != tar.TypeReg || header.Size != entry.Size || header.Linkname != "" {
			return manifest, "", errors.New("backup archive entry differs from manifest")
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(temp, entry.Name)), 0700); err != nil {
			return manifest, "", err
		}
		out, err := os.OpenFile(filepath.Join(temp, entry.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return manifest, "", err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, h), tr)
		closeErr := out.Close()
		if err != nil || closeErr != nil || n != entry.Size || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return manifest, "", errors.New("backup entry checksum mismatch")
		}
	}
	if _, err := tr.Next(); err != io.EOF {
		return manifest, "", errors.New("unexpected trailing backup entries")
	}
	var extra [1]byte
	if n, err := archive.Read(extra[:]); n != 0 || err != io.EOF {
		return manifest, "", errors.New("unexpected data after backup archive")
	}
	return manifest, hex.EncodeToString(mh[:]), nil
}
func RestoreBackup(ctx context.Context, source, destination, identityFile string, provider CryptoProvider) (BackupReceipt, error) {
	if !filepath.IsAbs(source) || !filepath.IsAbs(destination) || !filepath.IsAbs(identityFile) {
		return BackupReceipt{}, errors.New("restore paths must be absolute")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return BackupReceipt{}, errors.New("restore destination must be new; live state is never replaced")
	}
	temp, err := os.MkdirTemp(filepath.Dir(destination), ".restore-")
	if err != nil {
		return BackupReceipt{}, err
	}
	defer os.RemoveAll(temp)
	crypto, err := provider.prepare(temp)
	if err != nil {
		return BackupReceipt{}, err
	}
	ciphertext, err := OpenBoundedArtifact(source, backupArchiveLimit+16<<20)
	if err != nil {
		return BackupReceipt{}, err
	}
	defer ciphertext.Close()
	h := sha256.New()
	plain, err := os.CreateTemp(temp, "authenticated-")
	if err != nil {
		return BackupReceipt{}, err
	}
	defer plain.Close()
	// Consume and authenticate the entire age stream before parsing or loading a
	// database. A failed tag/truncated stream only leaves disposable private data.
	if err := runCrypto(ctx, crypto, io.TeeReader(ciphertext, h), &sizeWriter{plain, backupArchiveLimit}, "--identity-file", identityFile, "decrypt"); err != nil {
		return BackupReceipt{}, err
	}
	if _, err := plain.Seek(0, 0); err != nil {
		return BackupReceipt{}, err
	}
	extracted := filepath.Join(temp, "extracted")
	if err := os.Mkdir(extracted, 0700); err != nil {
		return BackupReceipt{}, err
	}
	manifest, digest, err := extractBackup(plain, extracted)
	if err != nil {
		return BackupReceipt{}, err
	}
	_, cfg, err := readBackupConfig(extracted)
	if err != nil {
		return BackupReceipt{}, err
	}
	sanitized, _ := yaml.Marshal(publicBackupConfig(cfg))
	actual, _ := yaml.Marshal(cfg)
	if string(sanitized) != string(actual) {
		return BackupReceipt{}, errors.New("backup configuration contains private or activation fields")
	}
	for _, name := range backupDatabases {
		if err := validateDatabaseExport(filepath.Join(extracted, "databases", name+".backup")); err != nil {
			return BackupReceipt{}, err
		}
	}
	base := filepath.Join(temp, "validator")
	if err := os.Mkdir(base, 0700); err != nil {
		return BackupReceipt{}, err
	}
	seed := make([]byte, 8)
	if _, err := rand.Read(seed); err != nil {
		return BackupReceipt{}, err
	}
	cfg.Bridge.InstanceID = "restore-" + hex.EncodeToString(seed)
	config, _ := yaml.Marshal(cfg)
	if err := atomicFile(base, "config.yml", config); err != nil {
		return BackupReceipt{}, err
	}
	if err := worker.EnsureNetworkBinding(filepath.Join(base, "bridge", ".operator"), networkBinding(cfg), false); err != nil {
		return BackupReceipt{}, err
	}
	for _, name := range backupDatabases {
		db, err := badger.Open(badger.DefaultOptions(filepath.Join(base, "bridge", name)).WithSyncWrites(true).WithLogger(nil))
		if err != nil {
			return BackupReceipt{}, errors.New("cannot create restored database")
		}
		input, err := os.Open(filepath.Join(extracted, "databases", name+".backup"))
		if err != nil {
			db.Close()
			return BackupReceipt{}, err
		}
		err = db.Load(input, 1)
		input.Close()
		closeErr := db.Close()
		if err != nil || closeErr != nil {
			return BackupReceipt{}, errors.New("database restore failed")
		}
	}
	// Validate the metadata schema using the same runtime reader before publishing.
	dbs, err := openSnapshotDatabases(base)
	if err != nil {
		return BackupReceipt{}, err
	}
	metadata, err := store.NewMetadataStore(&store.BadgerBackend{DB: dbs[0]}).Get()
	for _, db := range dbs {
		db.Close()
	}
	if err != nil {
		return BackupReceipt{}, errors.New("restored checkpoint metadata is invalid")
	}
	control := filepath.Join(base, "bridge", ".operator")
	if err := worker.PrivateDir(control); err != nil {
		return BackupReceipt{}, err
	}
	if err := worker.EnsureMode(control, true, false); err != nil {
		return BackupReceipt{}, err
	}
	configHash := sha256.Sum256(config)
	fence := worker.RestoreFence{SchemaVersion: 1, State: "review-required", BackupSHA256: digest, PublicConfigSHA256: hex.EncodeToString(configHash[:]), SourceInstanceID: manifest.SourceInstanceID, SourceMode: manifest.SourceMode, RestoredAt: time.Now().UTC()}
	encoded, _ := json.Marshal(fence)
	if err := atomicFile(control, "restore.json", encoded); err != nil {
		return BackupReceipt{}, err
	}
	public, err := os.ReadFile(filepath.Join(extracted, "operator-public.json"))
	if err != nil {
		return BackupReceipt{}, err
	}
	if err := atomicFile(base, "operator-public.json", public); err != nil {
		return BackupReceipt{}, err
	}
	if err := syncDirectory(filepath.Join(base, "bridge")); err != nil {
		return BackupReceipt{}, err
	}
	if err := syncDirectory(base); err != nil {
		return BackupReceipt{}, err
	}
	// Reserve the absent target exclusively. Rename then replaces only our empty
	// directory; competing clients fail mkdir and cannot replace live state.
	if err := os.Mkdir(destination, 0700); err != nil {
		return BackupReceipt{}, errors.New("restore destination appeared or cannot be reserved")
	}
	// Go's os.Rename refuses an existing directory before reaching rename(2).
	// POSIX rename permits replacing our exclusively reserved empty directory.
	if err := syscall.Rename(base, destination); err != nil {
		os.Remove(destination)
		return BackupReceipt{}, err
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return BackupReceipt{}, err
	}
	info, _ := ciphertext.Stat()
	return BackupReceipt{ManifestSHA256: digest, CiphertextSHA256: hex.EncodeToString(h.Sum(nil)), Bytes: info.Size(), CreatedAt: manifest.CreatedAt, State: "restored-observation-review-required", EthereumCheckpoint: metadata.LastEthereumBlockParsed, KoinosCheckpoint: metadata.LastKoinosBlockParsed}, nil
}

// ReviewRestoreObservation records a local review of the recovered checkpoints
// and unchanged public configuration. It does not establish chain finality,
// reconcile signing authority, or permit signing from a recovered database.
func ReviewRestoreObservation(base, digest, note string, ethereumHeight, koinosHeight uint64) (*worker.RestoreFence, error) {
	if !filepath.IsAbs(base) || !hexHash.MatchString(digest) || len(strings.TrimSpace(note)) < 8 || len(note) > 2048 {
		return nil, errors.New("restore review requires absolute base, exact backup digest and a non-secret review note (8–2048 bytes)")
	}
	control := filepath.Join(base, "bridge", ".operator")
	lease, err := worker.Acquire(control, "process.lock")
	if err != nil {
		return nil, errors.New("stop the restored observer before review")
	}
	defer lease.Close()
	fence, err := worker.ReadRestoreFence(control)
	if err != nil || fence == nil {
		return nil, errors.New("restore review marker unavailable")
	}
	if fence.BackupSHA256 != digest {
		return nil, errors.New("restore review digest differs from recovered backup")
	}
	raw, cfg, err := readBackupConfig(base)
	if err != nil {
		return nil, err
	}
	b := cfg.Bridge
	if !b.ObservationOnly || b.Reset || b.EthereumPK != "" || b.KoinosPK != "" || b.EthereumPKFile != "" || b.KoinosPKFile != "" || len(cfg.Global) != 0 {
		return nil, errors.New("restored observer must remain keyless, observation-only, without reset or global overrides")
	}
	public, _ := yaml.Marshal(publicBackupConfig(cfg))
	publicHash := sha256.Sum256(public)
	if hex.EncodeToString(publicHash[:]) != fence.PublicConfigSHA256 {
		return nil, errors.New("restored public configuration differs from the backup; contract, instance, token, validator and checkpoint policies must be preserved")
	}
	if b.EthereumBlockStart != 0 || b.KoinosBlockStart != 0 {
		return nil, errors.New("restore must resume saved checkpoints without start-height overrides")
	}
	if ValidateEndpoint(b.EthereumRpc) != nil || ValidateEndpoint(b.KoinosRpc) != nil {
		return nil, errors.New("configure explicit local or HTTPS RPC endpoints before observation review")
	}
	host, port, err := net.SplitHostPort(b.ApiUrl)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || portErr != nil || portNumber == 0 {
		return nil, errors.New("restored observer API must use a literal loopback address")
	}
	dbs, err := openSnapshotDatabases(base)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, db := range dbs {
			db.Close()
		}
	}()
	metadata, err := store.NewMetadataStore(&store.BadgerBackend{DB: dbs[0]}).Get()
	if err != nil || metadata.LastEthereumBlockParsed != ethereumHeight || metadata.LastKoinosBlockParsed != koinosHeight {
		return nil, errors.New("checkpoint values differ from local restore review")
	}
	fence.State = "observation-enabled"
	fence.ReviewNote = note
	h := sha256.Sum256(raw)
	fence.ReviewedConfigSHA256 = hex.EncodeToString(h[:])
	encoded, _ := json.Marshal(fence)
	if err := atomicFile(control, "restore.json", encoded); err != nil {
		return nil, err
	}
	return fence, nil
}
