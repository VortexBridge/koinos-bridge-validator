// Command governance-fixture prepares and inspects the disposable Prompt 05
// acceptance environment. It refuses non-local chain identities and is not
// installed with validator release artifacts.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/managed"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	kutil "github.com/koinos/koinos-util-golang"
)

const isolatedKoinosNetwork = "EiDdmebKeAcWOVxSQFyWCB8vcgEaDGDz75mWO9EhW3FnFA=="

type deployment struct {
	NetworkID     string   `json:"networkId"`
	BridgeChainID uint32   `json:"bridgeChainId"`
	Contract      string   `json:"contract"`
	CodeHash      string   `json:"codeHash"`
	Validators    []string `json:"validators"`
}

type fixtureConfig struct {
	SchemaVersion int        `json:"schemaVersion"`
	EVM           deployment `json:"evm"`
	Koinos        deployment `json:"koinos"`
	EVMRPC        string     `json:"evmRpc"`
	KoinosRPC     string     `json:"koinosRpc"`
	ReplicaRPC    string     `json:"replicaRpc"`
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "governance-fixture:", err)
	os.Exit(1)
}

func readJSON(path string, out interface{}) error {
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, out) != nil {
		return errors.New("fixture JSON is unavailable or invalid")
	}
	return nil
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func writeJSON(path string, value interface{}) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fixture-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if tmp.Chmod(0600) != nil || func() error { _, err := tmp.Write(raw); return err }() != nil || tmp.Sync() != nil || tmp.Close() != nil || os.Rename(name, path) != nil {
		_ = tmp.Close()
		return errors.New("cannot persist private fixture data")
	}
	return nil
}

func loadConfig(work string) (fixtureConfig, error) {
	var config fixtureConfig
	if err := readJSON(filepath.Join(work, "fixture.json"), &config); err != nil || config.SchemaVersion != 1 {
		return config, errors.New("fixture configuration is unavailable")
	}
	return config, nil
}

func observer(config fixtureConfig) operator.ObservationProvider {
	return managed.GovernanceObservationProvider(config.ReplicaRPC, config.Koinos.Validators[0])
}

func openStore(work string) (*operator.Store, error) {
	return operator.OpenStore(filepath.Join(work, "operator"))
}

func createProposal(work string, config fixtureConfig, id string, pause bool) (operator.GovernanceProposal, error) {
	store, err := openStore(work)
	if err != nil {
		return operator.GovernanceProposal{}, err
	}
	defer store.Close()
	now := time.Now().UTC()
	proposal, err := store.CreateGovernance(context.Background(), operator.CreateGovernanceProposal{
		ID: id, ProfileIDs: []string{"p05-evm", "p05-koinos"}, Pause: pause,
		Expiration: fmt.Sprint(now.Add(45 * time.Minute).UnixMilli()),
	}, observer(config), now)
	if err != nil {
		return proposal, err
	}
	if err := writeJSON(filepath.Join(work, id+".json"), proposal); err != nil {
		return operator.GovernanceProposal{}, err
	}
	return proposal, nil
}

func setup(work, evmPath, koinosPath, evmPayerPath, koinosSource, evmRPC, koinosRPC, replicaRPC string) error {
	if work != "/work" {
		return errors.New("acceptance fixture requires the dedicated /work tmpfs")
	}
	if _, err := os.Stat(filepath.Join(work, "fixture.json")); err == nil {
		return errors.New("acceptance fixture already exists")
	}
	config := fixtureConfig{SchemaVersion: 1, EVMRPC: evmRPC, KoinosRPC: koinosRPC, ReplicaRPC: replicaRPC}
	if err := readJSON(evmPath, &config.EVM); err != nil {
		return err
	}
	if err := readJSON(koinosPath, &config.Koinos); err != nil {
		return err
	}
	if config.EVM.NetworkID != "31337" || config.EVM.BridgeChainID != 1 || len(config.EVM.Validators) != 3 || config.Koinos.NetworkID != isolatedKoinosNetwork || config.Koinos.BridgeChainID != 31337 || len(config.Koinos.Validators) != 3 {
		return errors.New("fixture refuses a deployment outside the two reviewed disposable networks")
	}
	for _, path := range []string{work, filepath.Join(work, "operator"), filepath.Join(work, "validator-one"), filepath.Join(work, "validator-two"), filepath.Join(work, "payer"), filepath.Join(work, "executor")} {
		if err := privateDir(path); err != nil {
			return err
		}
	}
	passphrase, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
	if err != nil || len(passphrase) < 20 || len(passphrase) > 1024 {
		return errors.New("bounded runtime passphrase required on stdin")
	}
	defer keyvault.Clear(passphrase)
	password := func() ([]byte, error) { return append([]byte{}, passphrase...), nil }
	validators := make([]keyvault.Public, 0, 2)
	for index, name := range []string{"validator-one", "validator-two"} {
		seed := sha256.Sum256([]byte(fmt.Sprintf("Vortex Prompt 05 synthetic validator %d", index+1)))
		public, err := keyvault.Create(filepath.Join(work, name, "keys.vault"), seed[:], seed[:], password)
		if err != nil {
			return err
		}
		if !strings.EqualFold(public.EVMAddress, config.EVM.Validators[index]) || public.KoinosAddress != config.Koinos.Validators[index] {
			return errors.New("synthetic validator keys differ from the reviewed isolated deployments")
		}
		validators = append(validators, public)
	}
	payerEVMText, err := os.ReadFile(evmPayerPath)
	if err != nil {
		return errors.New("isolated EVM payer fixture unavailable")
	}
	payerEVM, err := hex.DecodeString(strings.TrimSpace(string(payerEVMText)))
	keyvault.Clear(payerEVMText)
	if err != nil || len(payerEVM) != 32 {
		return errors.New("isolated EVM payer fixture invalid")
	}
	defer keyvault.Clear(payerEVM)
	localKoinos, err := os.ReadFile(koinosSource)
	if err != nil {
		return errors.New("isolated Koinos payer fixture unavailable")
	}
	match := regexp.MustCompile(`const GENESIS_WIF = '([^']+)'`).FindSubmatch(localKoinos)
	if len(match) != 2 {
		keyvault.Clear(localKoinos)
		return errors.New("isolated Koinos payer fixture invalid")
	}
	payerKoinos, err := kutil.DecodeWIF(string(match[1]))
	keyvault.Clear(localKoinos)
	for index := range match[1] {
		match[1][index] = 0
	}
	if err != nil {
		return errors.New("isolated Koinos payer fixture invalid")
	}
	defer keyvault.Clear(payerKoinos)
	payer, err := keyvault.Create(filepath.Join(work, "payer", "keys.vault"), payerEVM, payerKoinos, password)
	if err != nil {
		return err
	}
	store, err := openStore(work)
	if err != nil {
		return err
	}
	bindings := []operator.Binding{
		{Profile: operator.Profile{SchemaVersion: 1, ID: "p05-evm", Name: "Prompt 05 isolated EVM", Family: "evm", Environment: "local", NetworkID: config.EVM.NetworkID, BridgeChainID: config.EVM.BridgeChainID, Contract: config.EVM.Contract, Codec: operator.EVMCodec, SourceCommit: operator.EVMSource, CodeHash: config.EVM.CodeHash, ReviewEvidence: "Prompt 05 disposable isolated-chain deployment", Reviewed: true}, RPC: config.EVMRPC},
		{Profile: operator.Profile{SchemaVersion: 1, ID: "p05-koinos", Name: "Prompt 05 isolated Koinos", Family: "koinos", Environment: "local", NetworkID: config.Koinos.NetworkID, BridgeChainID: config.Koinos.BridgeChainID, Contract: config.Koinos.Contract, Codec: operator.KoinosCodec, SourceCommit: operator.KoinosSource, CodeHash: config.Koinos.CodeHash, ReviewEvidence: "Prompt 05 disposable isolated-chain deployment", Reviewed: true}, RPC: config.KoinosRPC},
	}
	for index, binding := range bindings {
		if _, err := store.Apply(operator.ApplyConfig{ExpectedRevision: uint64(index), IdempotencyKey: "p05-profile-" + binding.Profile.Family, Binding: binding}); err != nil {
			store.Close()
			return err
		}
	}
	store.Close()
	if err := writeJSON(filepath.Join(work, "fixture.json"), config); err != nil {
		return err
	}
	proposal, err := createProposal(work, config, "pause-both", true)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
		"schemaVersion": 1, "validatorOne": validators[0], "validatorTwo": validators[1], "payer": payer,
		"proposalId": proposal.ID, "proposalDigest": proposal.Digest,
	})
}

func merge(work string) error {
	config, err := loadConfig(work)
	if err != nil {
		return err
	}
	var envelope operator.GovernanceSignatureEnvelope
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 256*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(interface{})) != io.EOF {
		return errors.New("one signature envelope is required on stdin")
	}
	store, err := openStore(work)
	if err != nil {
		return err
	}
	defer store.Close()
	proposal, err := store.AddGovernanceSignature(context.Background(), envelope, observer(config), time.Now().UTC())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(proposal)
}

func inventory(work string) error {
	store, err := openStore(work)
	if err != nil {
		return err
	}
	defer store.Close()
	return json.NewEncoder(os.Stdout).Encode(store.GovernanceInventory(true, time.Now().UTC()))
}

func observe(work string) error {
	config, err := loadConfig(work)
	if err != nil {
		return err
	}
	store, err := openStore(work)
	if err != nil {
		return err
	}
	defer store.Close()
	provider := observer(config)
	result := map[string]operator.Observation{}
	for _, id := range []string{"p05-evm", "p05-koinos"} {
		binding, ok := store.Binding(id)
		if !ok {
			return errors.New("fixture binding missing")
		}
		result[id] = provider(context.Background(), binding)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	work := flag.String("work", "/work", "dedicated tmpfs acceptance state")
	evmDeployment := flag.String("evm-deployment", "", "reviewed disposable EVM deployment JSON")
	koinosDeployment := flag.String("koinos-deployment", "", "reviewed disposable Koinos deployment JSON")
	evmPayer := flag.String("evm-payer", "", "runtime file containing the disposable EVM payer key")
	koinosSource := flag.String("koinos-source", "", "published local-koinos development source")
	evmRPC := flag.String("evm-rpc", "http://127.0.0.1:18083", "isolated EVM RPC")
	koinosRPC := flag.String("koinos-rpc", "http://127.0.0.1:18081", "isolated live Koinos RPC")
	replicaRPC := flag.String("replica-rpc", "http://127.0.0.1:18082", "isolated Koinos finality replica RPC")
	id := flag.String("id", "", "proposal id")
	pause := flag.Bool("pause", false, "proposal pause value")
	flag.Parse()
	command := "hold"
	if flag.NArg() == 1 {
		command = flag.Arg(0)
	} else if flag.NArg() > 1 {
		fail(errors.New("provide one fixture command"))
	}
	var err error
	switch command {
	case "hold":
		select {}
	case "setup":
		err = setup(*work, *evmDeployment, *koinosDeployment, *evmPayer, *koinosSource, *evmRPC, *koinosRPC, *replicaRPC)
	case "merge":
		err = merge(*work)
	case "proposal":
		if *id == "" {
			err = errors.New("proposal id required")
		} else {
			var config fixtureConfig
			if config, err = loadConfig(*work); err == nil {
				var proposal operator.GovernanceProposal
				proposal, err = createProposal(*work, config, *id, *pause)
				if err == nil {
					err = json.NewEncoder(os.Stdout).Encode(proposal)
				}
			}
		}
	case "inventory":
		err = inventory(*work)
	case "observe":
		err = observe(*work)
	default:
		err = errors.New("commands: hold, setup, merge, proposal, inventory, observe")
	}
	if err != nil {
		fail(err)
	}
}
