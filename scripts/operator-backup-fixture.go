//go:build ignore
// +build ignore

// Build a disposable stopped-validator backup fixture. It creates only synthetic
// local data and, unless given a public recipient, a fresh test recovery
// identity. It starts no worker or RPC.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dgraph-io/badger/v3"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	bridge "github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"gopkg.in/yaml.v2"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(path string) string {
	raw, err := os.ReadFile(path)
	must(err)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func main() {
	validator := flag.String("validator", "", "locally built validator binary")
	crypto := flag.String("crypto", "", "locally built backup crypto helper")
	command := flag.String("operator", "", "locally built operator binary")
	externalRecipient := flag.String("recipient", "", "public age X25519 recipient whose private identity stays off this host")
	flag.Parse()
	for _, p := range []string{*validator, *crypto, *command} {
		if !filepath.IsAbs(p) {
			panic("absolute locally built binary paths required")
		}
	}
	root, err := os.MkdirTemp("", "vortex-backup-dev.")
	must(err)
	base := filepath.Join(root, "worker")
	must(os.Mkdir(base, 0700))
	cfg := util.YamlConfig{Bridge: util.BridgeConfig{InstanceID: "synthetic-backup-worker", ObservationOnly: true, LogLevel: "info", SignaturesExpiration: 60000, ApiUrl: "http://127.0.0.1:18551", EthereumRpc: "http://127.0.0.1:18550", KoinosRpc: "http://127.0.0.1:18550", EthereumNetworkID: "31337", KoinosNetworkID: "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", EthereumContract: "0x1111111111111111111111111111111111111111", KoinosContract: "1111111111111111111114oLvT2", Validators: map[string]util.ValidatorConfig{}, Tokens: map[string]util.TokenConfig{}}}
	raw, err := yaml.Marshal(cfg)
	must(err)
	must(os.WriteFile(filepath.Join(base, "config.yml"), raw, 0600))
	control := filepath.Join(base, "bridge", ".operator")
	must(worker.EnsureNetworkBinding(control, worker.NetworkBinding{SchemaVersion: 1, EVMNetworkID: cfg.Bridge.EthereumNetworkID, KoinosNetworkID: cfg.Bridge.KoinosNetworkID, EVMContract: cfg.Bridge.EthereumContract, KoinosContract: cfg.Bridge.KoinosContract}, false))
	must(worker.EnsureMode(control, true, false))
	for i, name := range []string{"metadata", "ethereum_transactions", "koinos_transactions"} {
		db, err := badger.Open(badger.DefaultOptions(filepath.Join(base, "bridge", name)).WithLogger(nil))
		must(err)
		backend := &store.BadgerBackend{DB: db}
		if i == 0 {
			must(store.NewMetadataStore(backend).Put(&bridge.Metadata{LastEthereumBlockParsed: 5, LastKoinosBlockParsed: 9}))
		} else {
			must(store.NewTransactionsStore(backend).Put("synthetic-transfer", &bridge.Transaction{Id: "synthetic-transfer", Type: bridge.TransactionType(i - 1), Status: bridge.TransactionStatus_gathering_signatures}))
		}
		must(db.Close())
	}
	dir := filepath.Join(root, "operator")
	s, err := operator.OpenStore(dir)
	must(err)
	registration, err := s.RegisterWorker(base, *validator, digest(*validator))
	must(err)
	must(s.Close())
	identity := ""
	recipient := strings.TrimSpace(*externalRecipient)
	if recipient == "" {
		identity = filepath.Join(root, "test-recovery-identity")
		output, err := exec.Command(*crypto, "--identity-file", identity, "keygen").Output()
		must(err)
		recipient = strings.TrimSpace(string(output))
	}
	output, err := exec.Command(*command, "--data", dir, "--backup-crypto", *crypto, "--backup-crypto-sha256", digest(*crypto), "--recovery-recipient", recipient, "backup-configure").Output()
	must(err)
	var inventory operator.BackupInventory
	must(json.Unmarshal(output, &inventory))
	summary := map[string]interface{}{"root": root, "operatorDir": dir, "workerDir": base, "registration": registration, "backupPolicyDigest": inventory.PolicyDigest, "recipient": recipient, "validatorSha256": digest(*validator), "operatorSha256": digest(*command), "cryptoSha256": digest(*crypto)}
	if identity != "" {
		summary["testIdentityFile"] = identity
	}
	raw, err = json.MarshalIndent(summary, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(root, "fixture.json"), raw, 0600))
	fmt.Println(string(raw))
}
