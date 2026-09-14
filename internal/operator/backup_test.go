package operator

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"gopkg.in/yaml.v2"
)

func mustBackupWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func backupTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	path := os.Getenv("VORTEX_BACKUP_CRYPTO_TEST_BINARY")
	if path == "" {
		path = filepath.Join(t.TempDir(), "backup-crypto")
		cmd := exec.Command("go", "-C", "../../tools/backup-crypto", "build", "-trimpath", "-o", path, ".")
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "GOTOOLCHAIN=") && !strings.HasPrefix(v, "GOSUMDB=") {
				cmd.Env = append(cmd.Env, v)
			}
		}
		cmd.Env = append(cmd.Env, "GOTOOLCHAIN=go1.27.0", "GOSUMDB=sum.golang.org")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build isolated age helper: %v %s", err, out)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return CryptoProvider{Path: path, SHA256: hex.EncodeToString(h[:])}
}
func backupTestIdentity(t *testing.T, provider CryptoProvider, path string) string {
	t.Helper()
	cmd := exec.Command(provider.Path, "--identity-file", path, "keygen")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	return strings.TrimSpace(string(out))
}
func backupTestSource(t *testing.T, root string) (string, *Store) {
	t.Helper()
	base := filepath.Join(root, "source")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := util.YamlConfig{Global: map[string]interface{}{"synthetic-secret": "DO-NOT-BACKUP-GLOBAL"}, Bridge: util.BridgeConfig{
		SigningVaultFile: "DO-NOT-BACKUP-VAULT",
		InstanceID:       "backup-test-source", EthereumPK: "DO-NOT-BACKUP-EVM-KEY", KoinosPK: "DO-NOT-BACKUP-KOINOS-KEY", EthereumPKFile: "/DO-NOT-BACKUP-KEY-PATH", KoinosPKFile: "/DO-NOT-BACKUP-KOINOS-PATH",
		EthereumRpc: "https://example.invalid/DO-NOT-BACKUP-RPC", KoinosRpc: "https://example.invalid/DO-NOT-BACKUP-KOINOS-RPC", ApiUrl: "DO-NOT-BACKUP-API", Reset: true, EthereumBlockStart: 123, KoinosBlockStart: 456,
		EthereumContract: "0x1111111111111111111111111111111111111111", KoinosContract: "1111111111111111111114oLvT2",
		EthereumNetworkID: "31337", KoinosNetworkID: "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		Validators: map[string]util.ValidatorConfig{"operator-a": {EthereumAddress: "0x2222222222222222222222222222222222222222", KoinosAddress: "1111111111111111111114oLvT2", ApiUrl: "DO-NOT-BACKUP-PEER"}},
	}}
	raw, _ := yaml.Marshal(cfg)
	mustBackupWrite(t, filepath.Join(base, "config.yml"), raw)
	if err := worker.EnsureNetworkBinding(filepath.Join(base, "bridge", ".operator"), networkBinding(cfg), false); err != nil {
		t.Fatal(err)
	}
	for i, name := range backupDatabases {
		db, err := badger.Open(badger.DefaultOptions(filepath.Join(base, "bridge", name)).WithSyncWrites(true).WithLogger(nil))
		if err != nil {
			t.Fatal(err)
		}
		backend := &store.BadgerBackend{DB: db}
		if i == 0 {
			err = store.NewMetadataStore(backend).Put(&bridge_pb.Metadata{LastEthereumBlockParsed: 5, LastKoinosBlockParsed: 9})
		} else if i == 1 {
			err = store.NewTransactionsStore(backend).Put("pending-record", &bridge_pb.Transaction{Id: "synthetic-pending-transfer", BlockNumber: 5, Status: bridge_pb.TransactionStatus_gathering_signatures, Signatures: []string{"synthetic-public-signature"}})
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	control := filepath.Join(base, "bridge", ".operator")
	if err := worker.PrivateDir(control); err != nil {
		t.Fatal(err)
	}
	if err := worker.EnsureMode(control, false, false); err != nil {
		t.Fatal(err)
	}
	mustBackupWrite(t, filepath.Join(control, "access-token"), []byte("DO-NOT-BACKUP-TOKEN"))
	s, err := OpenStore(filepath.Join(root, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return base, s
}
func TestEncryptedBackupRecovery(t *testing.T) {
	root, err := os.MkdirTemp("", "vbr-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	provider := backupTestCrypto(t)
	identity := filepath.Join(root, "identity")
	recipient := backupTestIdentity(t, provider, identity)
	otherKey := filepath.Join(root, "other-identity")
	backupTestIdentity(t, provider, otherKey)
	base, s := backupTestSource(t, root)
	archive := filepath.Join(root, "validator.age")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	t.Run("active worker rejected", func(t *testing.T) {
		lease, err := worker.Acquire(filepath.Join(base, "bridge", ".operator"), "process.lock")
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		if _, err := s.CreateBackup(ctx, base, archive, recipient, provider); err == nil {
			t.Fatal("active worker backed up")
		}
	})
	t.Run("legacy database writer rejected", func(t *testing.T) {
		db, err := badger.Open(badger.DefaultOptions(filepath.Join(base, "bridge", "ethereum_transactions")).WithLogger(nil))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := s.CreateBackup(ctx, base, archive, recipient, provider); err == nil {
			t.Fatal("legacy writer backed up")
		}
	})
	t.Run("unreviewed crypto rejected", func(t *testing.T) {
		bad := provider
		bad.SHA256 = strings.Repeat("0", 64)
		if _, err := s.CreateBackup(ctx, base, archive, recipient, bad); err == nil {
			t.Fatal("wrong provider hash accepted")
		}
	})
	receipt, err := s.CreateBackup(ctx, base, archive, recipient, provider)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(cipher, []byte("age-encryption.org/v1\n")) {
		t.Fatal("not standard age format")
	}
	ch := sha256.Sum256(cipher)
	if receipt.CiphertextSHA256 != hex.EncodeToString(ch[:]) || receipt.Bytes != int64(len(cipher)) {
		t.Fatal("cipher receipt mismatch")
	}
	if _, err := s.CreateBackup(ctx, base, archive, recipient, provider); err == nil {
		t.Fatal("backup overwrote destination")
	}
	plain := new(bytes.Buffer)
	if err := runCrypto(ctx, provider.Path, bytes.NewReader(cipher), plain, "--identity-file", identity, "decrypt"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain.Bytes(), []byte("DO-NOT-BACKUP")) {
		t.Fatal("private configuration or token was exported")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"tampered":  func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(root, name+".age")
			mustBackupWrite(t, file, mutate(append([]byte(nil), cipher...)))
			dest := filepath.Join(root, name)
			if _, err := RestoreBackup(ctx, file, dest, identity, provider); err == nil {
				t.Fatal("invalid ciphertext restored")
			}
			if _, err := os.Lstat(dest); !os.IsNotExist(err) {
				t.Fatal("failed authentication published state")
			}
		})
	}
	t.Run("wrong key", func(t *testing.T) {
		dest := filepath.Join(root, "wrong-key")
		if _, err := RestoreBackup(ctx, archive, dest, otherKey, provider); err == nil {
			t.Fatal("wrong identity accepted")
		}
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			t.Fatal("wrong identity published state")
		}
	})
	t.Run("identity permissions and symlink", func(t *testing.T) {
		if err := os.Chmod(identity, 0644); err != nil {
			t.Fatal(err)
		}
		if err := runCrypto(ctx, provider.Path, bytes.NewReader(cipher), io.Discard, "--identity-file", identity, "decrypt"); err == nil {
			t.Fatal("public-readable identity accepted")
		}
		os.Chmod(identity, 0600)
		link := filepath.Join(root, "key-link")
		if err := os.Symlink(identity, link); err != nil {
			t.Fatal(err)
		}
		if err := runCrypto(ctx, provider.Path, bytes.NewReader(cipher), io.Discard, "--identity-file", link, "decrypt"); err == nil {
			t.Fatal("symlink identity accepted")
		}
	})
	dest := filepath.Join(root, "restored")
	restored, err := RestoreBackup(ctx, archive, dest, identity, provider)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ManifestSHA256 != receipt.ManifestSHA256 || restored.CiphertextSHA256 != receipt.CiphertextSHA256 {
		t.Fatal("restore receipt differs")
	}
	if receipt.EthereumCheckpoint != 5 || receipt.KoinosCheckpoint != 9 || restored.EthereumCheckpoint != 5 || restored.KoinosCheckpoint != 9 {
		t.Fatal("checkpoint receipt differs from recovered state")
	}
	t.Run("concurrent restore publishes once", func(t *testing.T) {
		target := filepath.Join(root, "concurrent-restore")
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() { _, err := RestoreBackup(ctx, archive, target, identity, provider); results <- err }()
		}
		first, second := <-results, <-results
		if (first == nil) == (second == nil) {
			t.Fatalf("expected one successful restore: %v / %v", first, second)
		}
		if _, _, err := readBackupConfig(target); err != nil {
			t.Fatal("concurrent restore lost published configuration")
		}
	})
	if _, err := RestoreBackup(ctx, archive, dest, identity, provider); err == nil {
		t.Fatal("existing restored data replaced")
	}
	control := filepath.Join(dest, "bridge", ".operator")
	if worker.CheckRestoreFence(control, true) == nil || worker.CheckRestoreFence(control, false) == nil {
		t.Fatal("unreviewed restore can start")
	}
	binary := os.Getenv("VORTEX_BACKUP_TEST_VALIDATOR")
	if binary == "" {
		binary = filepath.Join(root, "validator")
		build := exec.Command("go", "build", "-o", binary, "../../cmd/koinos-bridge-validator")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build runtime: %v %s", err, out)
		}
	}
	blockedCtx, blockedCancel := context.WithTimeout(context.Background(), 3*time.Second)
	blocked := exec.CommandContext(blockedCtx, binary, "--basedir", dest, "--observe-only")
	blockedOutput, blockedErr := blocked.CombinedOutput()
	blockedCancel()
	if blockedErr == nil || !bytes.Contains(blockedOutput, []byte("requires local configuration and checkpoint review")) {
		t.Fatalf("actual runtime did not refuse unreviewed restore: %v %s", blockedErr, blockedOutput)
	}
	_, cfg, err := readBackupConfig(dest)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Bridge.InstanceID == "backup-test-source" || !cfg.Bridge.ObservationOnly || cfg.Bridge.Reset {
		t.Fatal("restored mode/identity unsafe")
	}
	if cfg.Bridge.EthereumNetworkID != "31337" || cfg.Bridge.KoinosNetworkID != "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" || worker.CheckNetworkBinding(control, networkBinding(cfg), true) != nil {
		t.Fatal("restored network binding lost")
	}
	dbs, err := openSnapshotDatabases(dest)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.NewMetadataStore(&store.BadgerBackend{DB: dbs[0]}).Get()
	if err != nil || metadata.LastEthereumBlockParsed != 5 || metadata.LastKoinosBlockParsed != 9 {
		t.Fatal("checkpoint lost")
	}
	pending, err := store.NewTransactionsStore(&store.BadgerBackend{DB: dbs[1]}).Get("pending-record")
	if err != nil || pending == nil || pending.Id != "synthetic-pending-transfer" || pending.BlockNumber != 5 || pending.Status != bridge_pb.TransactionStatus_gathering_signatures || len(pending.Signatures) != 1 || pending.Signatures[0] != "synthetic-public-signature" {
		t.Fatal("pending record lost")
	}
	for _, db := range dbs {
		db.Close()
	}
	if _, err := ReviewRestoreObservation(dest, receipt.ManifestSHA256, "reviewed synthetic checkpoints", 5, 9); err == nil {
		t.Fatal("missing endpoints accepted")
	}
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("invalid synthetic RPC request")
			return
		}
		var result interface{}
		switch req.Method {
		case "eth_chainId":
			result = "0x7a69"
		case "chain.get_chain_id":
			result = map[string]string{"chain_id": "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
		case "eth_blockNumber":
			result = "0x0"
		case "chain.get_head_info":
			result = map[string]interface{}{"last_irreversible_block": "0", "head_topology": map[string]interface{}{"height": "0", "id": "0x1220" + strings.Repeat("00", 32)}}
		default:
			t.Errorf("restored observer attempted unexpected RPC %s", req.Method)
			http.Error(w, "disallowed", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer rpc.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiAddress := listener.Addr().String()
	listener.Close()
	cfg.Bridge.EthereumRpc = rpc.URL
	cfg.Bridge.KoinosRpc = rpc.URL
	cfg.Bridge.ApiUrl = apiAddress
	reviewedRaw, _ := yaml.Marshal(cfg)
	cfg.Bridge.SigningVaultFile = "/deliberately-missing-restored-vault"
	vaultConfig, _ := yaml.Marshal(cfg)
	mustBackupWrite(t, filepath.Join(dest, "config.yml"), vaultConfig)
	if _, err := ReviewRestoreObservation(dest, receipt.ManifestSHA256, "reviewed synthetic checkpoints", 5, 9); err == nil || !strings.Contains(err.Error(), "remain keyless") {
		t.Fatal("restore review accepted a vault reference")
	}
	cfg.Bridge.SigningVaultFile = ""
	mustBackupWrite(t, filepath.Join(dest, "config.yml"), reviewedRaw)
	if _, err := ReviewRestoreObservation(dest, strings.Repeat("0", 64), "reviewed synthetic checkpoints", 5, 9); err == nil {
		t.Fatal("wrong backup review accepted")
	}
	if _, err := ReviewRestoreObservation(dest, receipt.ManifestSHA256, "reviewed synthetic checkpoints", 6, 9); err == nil {
		t.Fatal("wrong checkpoint review accepted")
	}
	cfg.Bridge.EthereumContract = "0x3333333333333333333333333333333333333333"
	changed, _ := yaml.Marshal(cfg)
	mustBackupWrite(t, filepath.Join(dest, "config.yml"), changed)
	if _, err := ReviewRestoreObservation(dest, receipt.ManifestSHA256, "reviewed synthetic checkpoints", 5, 9); err == nil {
		t.Fatal("contract drift accepted")
	}
	mustBackupWrite(t, filepath.Join(dest, "config.yml"), reviewedRaw)
	if _, err := ReviewRestoreObservation(dest, receipt.ManifestSHA256, "reviewed synthetic checkpoints", 5, 9); err != nil {
		t.Fatal(err)
	}
	if err := worker.CheckRestoreFence(control, true); err != nil {
		t.Fatal(err)
	}
	if worker.CheckRestoreFence(control, false) == nil {
		t.Fatal("restore review permitted signing")
	}
	t.Run("actual restored observer starts and stops", func(t *testing.T) {
		log, err := os.OpenFile(filepath.Join(root, "restored-test.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		cmd := exec.Command(binary, "--basedir", dest, "--observe-only")
		cmd.Stdout = log
		cmd.Stderr = log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if cmd.ProcessState == nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
		}()
		deadline := time.Now().Add(5 * time.Second)
		var health worker.Health
		for time.Now().Before(deadline) {
			if worker.Call(context.Background(), control, "GET", "/health", &health) == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if health.PID != cmd.Process.Pid || health.Mode != "observation-only" {
			b, _ := os.ReadFile(filepath.Join(root, "restored-test.log"))
			t.Fatalf("restored worker unavailable: %s", b)
		}
		client := &http.Client{Timeout: time.Second}
		response, err := client.Post("http://"+apiAddress+"/SubmitSignature", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("restored observer accepted signatures")
		}
		if _, err := ReviewRestoreObservation(dest, receipt.ManifestSHA256, "active review must fail", 5, 9); err == nil {
			t.Fatal("active restore reviewed")
		}
		var stopped map[string]bool
		if err := worker.Call(context.Background(), control, "POST", "/stop", &stopped, health); err != nil {
			t.Fatal(err)
		}
		exit := make(chan error, 1)
		go func() { exit <- cmd.Wait() }()
		select {
		case err := <-exit:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-exit
			t.Fatal("restored observer failed graceful stop")
		}
		dbs, err := openSnapshotDatabases(dest)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			for _, db := range dbs {
				db.Close()
			}
		}()
		metadata, err := store.NewMetadataStore(&store.BadgerBackend{DB: dbs[0]}).Get()
		if err != nil || metadata.LastEthereumBlockParsed != 5 || metadata.LastKoinosBlockParsed != 9 {
			t.Fatal("runtime changed recovered checkpoints")
		}
		pending, err := store.NewTransactionsStore(&store.BadgerBackend{DB: dbs[1]}).Get("pending-record")
		if err != nil || pending == nil || len(pending.Signatures) != 1 {
			t.Fatal("runtime lost recovered pending signature")
		}
	})
	mustBackupWrite(t, filepath.Join(dest, "config.yml"), append(reviewedRaw, []byte("\n# changed after review\n")...))
	if worker.CheckRestoreFence(control, true) == nil {
		t.Fatal("post-review configuration drift accepted")
	}
	t.Run("documented CLI create restore review", func(t *testing.T) {
		cli := os.Getenv("VORTEX_BACKUP_TEST_OPERATOR")
		if cli == "" {
			cli = filepath.Join(root, "vortex-operator")
			build := exec.Command("go", "build", "-o", cli, "../../cmd/vortex-operator")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build CLI: %v %s", err, out)
			}
		}
		invoke := func(args ...string) []byte {
			t.Helper()
			cmd := exec.Command(cli, append([]string{"--data", filepath.Join(root, "cli-operator")}, args...)...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("CLI failed: %v %s", err, out)
			}
			return out
		}
		cliArchive := filepath.Join(root, "cli.age")
		common := []string{"--backup-crypto", provider.Path, "--backup-crypto-sha256", provider.SHA256, "--backup-file", cliArchive}
		out := invoke(append(append([]string{}, common...), "--worker-base", base, "--recovery-recipient", recipient, "backup-create")...)
		var created BackupReceipt
		if err := json.Unmarshal(out, &created); err != nil || created.State != "encrypted-backup-created" {
			t.Fatalf("invalid CLI backup receipt %s", out)
		}
		cliDest := filepath.Join(root, "cli-restored")
		out = invoke(append(append([]string{}, common...), "--restore-base", cliDest, "--recovery-identity-file", identity, "backup-restore")...)
		var restored BackupReceipt
		if err := json.Unmarshal(out, &restored); err != nil || restored.ManifestSHA256 != created.ManifestSHA256 || restored.State != "restored-observation-review-required" {
			t.Fatalf("invalid CLI restore receipt %s", out)
		}
		_, cfg, err := readBackupConfig(cliDest)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Bridge.EthereumRpc = rpc.URL
		cfg.Bridge.KoinosRpc = rpc.URL
		cfg.Bridge.ApiUrl = "127.0.0.1:13001"
		raw, _ := yaml.Marshal(cfg)
		mustBackupWrite(t, filepath.Join(cliDest, "config.yml"), raw)
		out = invoke("--worker-base", cliDest, "--backup-digest", restored.ManifestSHA256, "--review-ethereum-height", "5", "--review-koinos-height", "9", "--review-note", "Reviewed synthetic fixture checkpoints and configuration.", "restore-review")
		var fence worker.RestoreFence
		if err := json.Unmarshal(out, &fence); err != nil || fence.State != "observation-enabled" {
			t.Fatalf("invalid CLI review receipt %s", out)
		}
	})
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".restore-") || strings.HasPrefix(e.Name(), ".backup-encrypted-") {
			t.Fatal("private temporary data not cleaned")
		}
	}
}

func TestBackupArchiveRejectsMalformedEntries(t *testing.T) {
	names := []string{"config.yml", "operator-public.json", "databases/metadata.backup", "databases/ethereum_transactions.backup", "databases/koinos_transactions.backup"}
	h := sha256.Sum256([]byte("x"))
	digest := hex.EncodeToString(h[:])
	for _, test := range []string{"valid", "traversal", "duplicate", "symlink", "checksum", "extra-entry", "trailing-data", "oversize"} {
		t.Run(test, func(t *testing.T) {
			manifest := BackupManifest{SchemaVersion: 1, Format: "badger-v3-logical-v1", SourceConfigSHA256: strings.Repeat("0", 64), Entries: []BackupEntry{}}
			for _, name := range names {
				manifest.Entries = append(manifest.Entries, BackupEntry{Name: name, Size: 1, SHA256: digest})
			}
			switch test {
			case "traversal":
				manifest.Entries[0].Name = "../escape"
			case "duplicate":
				manifest.Entries[1].Name = names[0]
			case "checksum":
				manifest.Entries[0].SHA256 = strings.Repeat("0", 64)
			case "oversize":
				manifest.Entries[0].Size = backupFileLimit + 1
			}
			raw, _ := json.Marshal(manifest)
			buf := new(bytes.Buffer)
			tw := tar.NewWriter(buf)
			if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(raw)), Mode: 0600}); err != nil {
				t.Fatal(err)
			}
			tw.Write(raw)
			for i, entry := range manifest.Entries {
				header := &tar.Header{Name: entry.Name, Size: 1, Mode: 0600}
				if test == "symlink" && i == 0 {
					header.Typeflag = tar.TypeSymlink
					header.Size = 0
					header.Linkname = "/tmp/escape"
				}
				if err := tw.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if header.Size > 0 {
					tw.Write([]byte("x"))
				}
			}
			if test == "extra-entry" {
				tw.WriteHeader(&tar.Header{Name: "extra", Size: 0})
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if test == "trailing-data" {
				buf.WriteString("unexpected")
			}
			_, _, err := extractBackup(bytes.NewReader(buf.Bytes()), t.TempDir())
			if test == "valid" && err != nil {
				t.Fatal(err)
			}
			if test != "valid" && err == nil {
				t.Fatal("malformed archive accepted")
			}
		})
	}
}
