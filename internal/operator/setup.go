package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"gopkg.in/yaml.v2"
)

type WorkerPreparation struct {
	SchemaVersion int    `json:"schemaVersion"`
	WorkerID      string `json:"workerId"`
	BinarySHA256  string `json:"binarySha256"`
}
type SetupToken struct {
	ID     string `json:"id"`
	EVM    string `json:"evm"`
	Koinos string `json:"koinos"`
}
type SetupPeer struct {
	ID       string `json:"id"`
	EVM      string `json:"evm"`
	Koinos   string `json:"koinos"`
	Endpoint string `json:"endpoint,omitempty"`
}
type SetupInput struct {
	ExpectedRevision uint64       `json:"expectedRevision"`
	EVMProfileID     string       `json:"evmProfileId"`
	KoinosProfileID  string       `json:"koinosProfileId"`
	EVMStartBlock    string       `json:"evmStartBlock"`
	KoinosStartBlock string       `json:"koinosStartBlock"`
	EVMConfirmations string       `json:"evmConfirmations"`
	APIPort          int          `json:"apiPort"`
	Tokens           []SetupToken `json:"tokens"`
	Peers            []SetupPeer  `json:"peers"`
}
type SetupPreview struct {
	Digest           string       `json:"digest"`
	Revision         uint64       `json:"revision"`
	WorkerID         string       `json:"workerId"`
	BinarySHA256     string       `json:"binarySha256"`
	ConfigSHA256     string       `json:"configSha256"`
	EVM              Profile      `json:"evm"`
	Koinos           Profile      `json:"koinos"`
	EVMStartBlock    string       `json:"evmStartBlock"`
	KoinosStartBlock string       `json:"koinosStartBlock"`
	EVMConfirmations string       `json:"evmConfirmations"`
	APIPort          int          `json:"apiPort"`
	Tokens           []SetupToken `json:"tokens"`
	Peers            []SetupPeer  `json:"peers"`
	Notice           string       `json:"notice"`
}
type CreateWorker struct {
	Input          SetupInput `json:"input"`
	PreviewDigest  string     `json:"previewDigest"`
	IdempotencyKey string     `json:"idempotencyKey"`
}
type SetupReceipt struct {
	SchemaVersion      int          `json:"schemaVersion"`
	RequestDigest      string       `json:"requestDigest"`
	IdempotencyKey     string       `json:"idempotencyKey"`
	Preview            SetupPreview `json:"preview"`
	RegistrationDigest string       `json:"registrationDigest"`
	CreatedAt          time.Time    `json:"createdAt"`
	Revision           uint64       `json:"revision"`
	State              string       `json:"state"`
}

// PrepareWorker is CLI-only. Web setup never chooses or replaces executables.
func (s *Store) PrepareWorker(binary, expectedHash string) (WorkerPreparation, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if s.workerExists() {
		return WorkerPreparation{}, errors.New("worker already exists; setup cannot replace it")
	}
	path := filepath.Join(s.dir, "worker-preparation.json")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return WorkerPreparation{}, errors.New("preparation already exists or is unreadable; inspect it locally")
	}
	if !workerHashPattern.MatchString(expectedHash) {
		return WorkerPreparation{}, errors.New("provide the locally reviewed worker SHA-256")
	}
	if err := s.pinWorkerBinary(binary, expectedHash); err != nil {
		return WorkerPreparation{}, err
	}
	p := WorkerPreparation{1, "worker-" + strings.TrimPrefix(s.InstanceID(), "operator-"), expectedHash}
	raw, _ := json.Marshal(p)
	return p, atomicFile(s.dir, "worker-preparation.json", raw)
}
func (s *Store) preparation() (WorkerPreparation, error) {
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, "worker-preparation.json"), 4096)
	var p WorkerPreparation
	if err != nil || strictJSON(raw, &p) != nil || p.SchemaVersion != 1 || !slug.MatchString(p.WorkerID) || !workerHashPattern.MatchString(p.BinarySHA256) {
		return p, errors.New("prepare a reviewed binary locally with worker-prepare before using setup")
	}
	return p, nil
}
func (s *Store) SetupState() map[string]interface{} {
	p, err := s.preparation()
	revision, profiles, _ := s.Summary()
	result := map[string]interface{}{"prepared": err == nil, "revision": revision, "profiles": profiles, "workerExists": s.workerExists()}
	if err == nil {
		result["preparation"] = p
	}
	if receipt, err := s.setupReceipt(); err == nil {
		result["receipt"] = receipt
	}
	return result
}
func setupNumber(value string, maximum uint64) (uint64, error) {
	if !decimal.MatchString(value) {
		return 0, errors.New("scan settings must be canonical positive decimal integers")
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 || n > maximum {
		return 0, errors.New("scan setting outside supported range")
	}
	return n, nil
}

// Caller holds s.mu so preview and publication cannot race profile changes.
func (s *Store) buildSetupLocked(input SetupInput, p WorkerPreparation) (SetupPreview, []byte, error) {
	var empty SetupPreview
	if input.ExpectedRevision != s.data.Revision {
		return empty, nil, errors.New("configuration revision changed; refresh the setup preview")
	}
	var evm, koinos Binding
	for _, b := range s.data.Bindings {
		if b.Profile.ID == input.EVMProfileID {
			evm = b
		}
		if b.Profile.ID == input.KoinosProfileID {
			koinos = b
		}
	}
	if evm.Profile.Family != "evm" || koinos.Profile.Family != "koinos" || evm.Validate() != nil || koinos.Validate() != nil {
		return empty, nil, errors.New("select one valid saved deployment for each chain family")
	}
	if evm.Profile.Environment != koinos.Profile.Environment || evm.Profile.BridgeChainID == koinos.Profile.BridgeChainID {
		return empty, nil, errors.New("route deployments must share an environment and have distinct protocol chain IDs")
	}
	// The UI and health transport use exact JSON integers for checkpoint display.
	evmStart, err := setupNumber(input.EVMStartBlock, 1<<53-1)
	if err != nil {
		return empty, nil, err
	}
	koinosStart, err := setupNumber(input.KoinosStartBlock, 1<<53-1)
	if err != nil {
		return empty, nil, err
	}
	confirmations, err := setupNumber(input.EVMConfirmations, 100000)
	if err != nil {
		return empty, nil, err
	}
	if input.APIPort < 1024 || input.APIPort > 65535 {
		return empty, nil, errors.New("choose a loopback API port from 1024 to 65535")
	}
	if len(input.Tokens) > 256 || len(input.Peers) > 256 {
		return empty, nil, errors.New("setup allows at most 256 tokens and 256 peers")
	}
	bridge := util.BridgeConfig{ObservationOnly: true, InstanceID: p.WorkerID, LogLevel: "info", ApiUrl: fmt.Sprintf("127.0.0.1:%d", input.APIPort), EthereumRpc: evm.RPC, KoinosRpc: koinos.RPC, EthereumContract: evm.Profile.Contract, KoinosContract: koinos.Profile.Contract, EthereumNetworkID: evm.Profile.NetworkID, KoinosNetworkID: koinos.Profile.NetworkID, EthereumBlockStart: evmStart, KoinosBlockStart: koinosStart, EthereumConfirmations: confirmations, EthereumMaxBlocksStream: 100, KoinosMaxBlocksStream: 100, EthereumPollingTime: 3000, KoinosPollingTime: 3000, SignaturesExpiration: 3600000, Tokens: map[string]util.TokenConfig{}, Validators: map[string]util.ValidatorConfig{}}
	validatePairs := func(id, evm, koinos string, seen map[string]bool) error {
		if !slug.MatchString(id) {
			return errors.New("mapping IDs must be lowercase slugs")
		}
		if _, err := addressBytes("evm", evm); err != nil {
			return err
		}
		if _, err := addressBytes("koinos", koinos); err != nil {
			return err
		}
		for _, key := range []string{"id:" + id, "evm:" + strings.ToLower(evm), "koinos:" + koinos} {
			if seen[key] {
				return errors.New("duplicate mapping ID or address")
			}
			seen[key] = true
		}
		return nil
	}
	seen := map[string]bool{}
	publicTokens := []SetupToken{}
	for _, t := range input.Tokens {
		if err := validatePairs(t.ID, t.EVM, t.Koinos, seen); err != nil {
			return empty, nil, err
		}
		t.EVM = common.HexToAddress(t.EVM).Hex()
		bridge.Tokens[t.ID] = util.TokenConfig{EthereumAddress: t.EVM, KoinosAddress: t.Koinos}
		publicTokens = append(publicTokens, t)
	}
	seen = map[string]bool{}
	publicPeers := []SetupPeer{}
	for _, peer := range input.Peers {
		if err := validatePairs(peer.ID, peer.EVM, peer.Koinos, seen); err != nil {
			return empty, nil, err
		}
		if ValidateEndpoint(peer.Endpoint) != nil {
			return empty, nil, errors.New("peer endpoint must be HTTPS or literal loopback HTTP")
		}
		peer.EVM = common.HexToAddress(peer.EVM).Hex()
		bridge.Validators[peer.ID] = util.ValidatorConfig{EthereumAddress: peer.EVM, KoinosAddress: peer.Koinos, ApiUrl: peer.Endpoint}
		peer.Endpoint = ""
		publicPeers = append(publicPeers, peer)
	}
	cfg := util.YamlConfig{Bridge: bridge}
	if err := networkBinding(cfg).Validate(); err != nil {
		return empty, nil, err
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return empty, nil, err
	}
	if len(raw) > 128<<10 {
		return empty, nil, errors.New("generated configuration exceeds worker size limit")
	}
	hash := sha256.Sum256(raw)
	preview := SetupPreview{Revision: s.data.Revision, WorkerID: p.WorkerID, BinarySHA256: p.BinarySHA256, ConfigSHA256: hex.EncodeToString(hash[:]), EVM: evm.Profile, Koinos: koinos.Profile, EVMStartBlock: input.EVMStartBlock, KoinosStartBlock: input.KoinosStartBlock, EVMConfirmations: input.EVMConfirmations, APIPort: input.APIPort, Tokens: publicTokens, Peers: publicPeers, Notice: "Creates a new observation-only worker. RPC and peer URLs remain private. Key provisioning, on-chain membership, token/peer reconciliation and signing are separate steps. No worker is started by setup."}
	encoded, _ := json.Marshal(preview)
	hash = sha256.Sum256(encoded)
	preview.Digest = hex.EncodeToString(hash[:])
	return preview, raw, nil
}
func (s *Store) PreviewWorkerSetup(input SetupInput) (SetupPreview, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if s.workerExists() {
		return SetupPreview{}, errors.New("worker already exists; setup only creates a new worker")
	}
	p, err := s.preparation()
	if err != nil {
		return SetupPreview{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	preview, _, err := s.buildSetupLocked(input, p)
	return preview, err
}
func (s *Store) setupReceipt() (SetupReceipt, error) {
	info, statErr := os.Lstat(filepath.Join(s.dir, "managed-worker"))
	if statErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return SetupReceipt{}, errors.New("managed setup directory unavailable or not private")
	}
	raw, err := worker.ReadPrivateFile(filepath.Join(s.dir, "managed-worker", "setup-receipt.json"), 256<<10)
	var receipt SetupReceipt
	if err != nil || strictJSON(raw, &receipt) != nil || receipt.SchemaVersion != 1 || !workerHashPattern.MatchString(receipt.RequestDigest) || receipt.State != "created-observation-only" {
		return receipt, errors.New("setup receipt unavailable or invalid")
	}
	return receipt, nil
}
func (s *Store) CreateObservationWorker(req CreateWorker) (SetupReceipt, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	var empty SetupReceipt
	if !slug.MatchString(req.IdempotencyKey) {
		return empty, errors.New("idempotency key must be a lowercase slug")
	}
	encoded, _ := json.Marshal(req)
	hash := sha256.Sum256(encoded)
	requestDigest := hex.EncodeToString(hash[:])
	if s.workerExists() {
		old, err := s.setupReceipt()
		if err == nil && old.RequestDigest == requestDigest && old.IdempotencyKey == req.IdempotencyKey {
			return old, nil
		}
		return empty, errors.New("worker already exists or setup state is uncertain; no data was replaced")
	}
	p, err := s.preparation()
	if err != nil {
		return empty, err
	}
	base := filepath.Join(s.dir, "managed-worker")
	release, err := s.lockWorkerOwnership(base, p.WorkerID)
	if err != nil {
		return empty, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	preview, config, err := s.buildSetupLocked(req.Input, p)
	if err != nil {
		return empty, err
	}
	if preview.Digest != req.PreviewDigest {
		return empty, errors.New("setup preview differs; review the current preview before creating")
	}
	binary, err := worker.ReadPrivateFile(filepath.Join(s.dir, "worker-bin", p.BinarySHA256), 256<<20)
	hash = sha256.Sum256(binary)
	if err != nil || hex.EncodeToString(hash[:]) != p.BinarySHA256 {
		return empty, errors.New("prepared worker binary changed or is unavailable")
	}
	temp, err := os.MkdirTemp(s.dir, ".worker-setup-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(temp)
	if err := atomicFile(temp, "config.yml", config); err != nil {
		return empty, err
	}
	var cfg util.YamlConfig
	if yaml.UnmarshalStrict(config, &cfg) != nil {
		return empty, errors.New("generated configuration is invalid")
	}
	control := filepath.Join(temp, "bridge", ".operator")
	if err := worker.EnsureNetworkBinding(control, networkBinding(cfg), false); err != nil {
		return empty, err
	}
	if err := worker.EnsureMode(control, true, false); err != nil {
		return empty, err
	}
	r := WorkerRegistration{1, p.WorkerID, base, p.BinarySHA256, preview.ConfigSHA256, "observation-only"}
	encoded, _ = json.Marshal(r)
	if err := atomicFile(temp, "registration.json", encoded); err != nil {
		return empty, err
	}
	receipt := SetupReceipt{1, requestDigest, req.IdempotencyKey, preview, registrationDigest(r), time.Now().UTC(), s.data.Revision + 1, "created-observation-only"}
	encoded, _ = json.Marshal(receipt)
	if len(encoded) > 256<<10 {
		return empty, errors.New("setup receipt exceeds size limit")
	}
	if err := atomicFile(temp, "setup-receipt.json", encoded); err != nil {
		return empty, err
	}
	if err := syncDirectory(filepath.Join(temp, "bridge")); err != nil {
		return empty, err
	}
	if err := syncDirectory(temp); err != nil {
		return empty, err
	}
	// Intent is durable before publication. A pre-publication failure requires a
	// fresh preview; a published bundle carries its own retry receipt atomically.
	if err := s.recordLifecycleLocked("worker setup requested", p.WorkerID); err != nil {
		return empty, err
	}
	if err := os.Mkdir(base, 0700); err != nil {
		return empty, errors.New("worker destination appeared; no directory was replaced")
	}
	// Use rename(2) to replace only our reserved empty directory; os.Rename
	// rejects directory destinations before reaching the syscall on macOS.
	if err := syscall.Rename(temp, base); err != nil {
		os.Remove(base) // Remove only our still-empty reservation, never worker data.
		return empty, errors.New("worker setup publication failed; refresh and inspect local state")
	}
	if err := syncDirectory(s.dir); err != nil {
		return empty, errors.New("worker published but durability is uncertain; retry the same request to inspect its receipt")
	}
	return receipt, nil
}
