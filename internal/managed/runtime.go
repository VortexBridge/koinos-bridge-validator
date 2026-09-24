package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// RuntimeConfig contains public identities and private local paths, never keys,
// passwords or caller-supplied readiness booleans. Block hints are untrusted:
// the Koinos reader verifies the referenced transaction and irreversible branch.
type RuntimeConfig struct {
	Schema         int               `json:"schemaVersion"`
	Instance       string            `json:"instance"`
	EVM            operator.Binding  `json:"evm"`
	Koinos         operator.Binding  `json:"koinos"`
	Replica        string            `json:"koinosReplica"`
	EVMAddress     string            `json:"evmAddress"`
	KoinosAddress  string            `json:"koinosAddress"`
	PreviousEVM    string            `json:"previousEvm,omitempty"`
	PreviousKoinos string            `json:"previousKoinos,omitempty"`
	Tokens         map[string]string `json:"tokens"` // EVM -> Koinos, one-to-one
	Lifetime       uint64            `json:"signatureLifetimeMs"`
	BlockHints     map[string]uint64 `json:"koinosBlockHints"`
	Vault          string            `json:"vault"`
	HostReview     string            `json:"hostReview"`
	Reviewer       string            `json:"reviewer"`
	HostEvidence   string            `json:"hostEvidence"`
}

// PrepareRuntime wires every mandatory gate. It does not unlock or start a
// process. The host supervisor must hold host.lock throughout session lifetime.
// Configuration changes require a new signed host review and recovery review.
func PrepareRuntime(root, configPath, trustPath string) (*Session, string, error) {
	return prepareRuntime(root, configPath, trustPath, nil)
}

type artifactTransition struct {
	ctx      context.Context
	previous Policy
	review   SignedHostReview
}

// PrepareArtifactUpgrade opens only an existing stopped journal. The host
// supervisor must hold host.lock, just as for normal managed activation.
func PrepareArtifactUpgrade(ctx context.Context, root, configPath, trustPath string, previous Policy, review SignedHostReview) (*Session, string, error) {
	return prepareRuntime(root, configPath, trustPath, &artifactTransition{ctx, previous, review})
}
func prepareRuntime(root, configPath, trustPath string, upgrade *artifactTransition) (*Session, string, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(configPath) || !filepath.IsAbs(trustPath) {
		return nil, "", errors.New("absolute runtime paths required")
	}
	raw, e := worker.ReadPrivateFile(configPath, 128<<10)
	if e != nil {
		return nil, "", e
	}
	var cfg RuntimeConfig
	if host.JSON(raw, &cfg) != nil || cfg.Schema != 1 || cfg.Instance == "" || len(cfg.BlockHints) > 4096 || !filepath.IsAbs(cfg.Vault) {
		return nil, "", errors.New("invalid managed runtime configuration")
	}
	evm, e := NewEVMSnapshot(cfg.EVM)
	if e != nil {
		return nil, "", e
	}
	koinos, e := NewKoinosSnapshot(cfg.Koinos, cfg.Replica)
	if e != nil {
		return nil, "", e
	}
	chains, e := NewChainVerifier(evm, koinos)
	if e != nil {
		return nil, "", e
	}
	reverse := map[string]string{}
	for from, to := range cfg.Tokens {
		if _, exists := reverse[to]; exists {
			return nil, "", errors.New("ambiguous token mapping")
		}
		reverse[to] = from
	}
	toKoinos, e := NewEVMKoinosReader(cfg.EVM, koinos, cfg.KoinosAddress, cfg.Tokens, cfg.Lifetime)
	if e != nil {
		return nil, "", e
	}
	toEVM, e := NewKoinosEVMReader(cfg.Koinos, cfg.EVM, reverse, cfg.Lifetime, func(ctx context.Context, id string) (uint64, error) {
		return locateRuntimeOperation(ctx, root, cfg.BlockHints, id)
	})
	if e != nil {
		return nil, "", e
	}
	routes, e := NewBidirectionalVerifier(chains, cfg.EVM.Profile, cfg.Koinos.Profile, toKoinos, toEVM)
	if e != nil {
		return nil, "", e
	}
	installed, e := NewInstalledVerifier(root, trustPath, configPath, filepath.Join(root, "candidate.json"), routes)
	if e != nil {
		return nil, "", e
	}
	reviewed, e := NewHostVerifier(installed, cfg.HostReview, cfg.Reviewer, cfg.HostEvidence)
	if e != nil {
		return nil, "", e
	}
	executable, e := os.Executable()
	if e != nil {
		return nil, "", e
	}
	artifact, e := fileDigest(executable, host.MaxBundle)
	if e != nil {
		return nil, "", e
	}
	configHash := sha256.Sum256(raw)
	configuration := hex.EncodeToString(configHash[:])
	p := Policy{Instance: cfg.Instance, ArtifactSHA256: artifact, ConfigSHA256: configuration, EVMAddress: cfg.EVMAddress, KoinosAddress: cfg.KoinosAddress, PreviousEVM: cfg.PreviousEVM, PreviousKoinos: cfg.PreviousKoinos}
	if upgrade != nil {
		raw, err := worker.ReadPrivateFile(filepath.Join(root, "managed-session", "session.json"), 4<<20)
		var existing Journal
		if err != nil || host.JSON(raw, &existing) != nil || existing.State != "locked" {
			return nil, "", errors.New("existing stopped journal required before artifact upgrade")
		}
		if existing.PolicySHA256 == Digest(p) {
			if !artifactOnlyTransition(upgrade.previous, p) {
				return nil, "", errors.New("invalid artifact transition")
			}
			if err = reviewed.authorizeUpgrade(upgrade.ctx, upgrade.previous, upgrade.review); err != nil {
				return nil, "", err
			}
			session, err := Open(filepath.Join(root, "managed-session"), p, reviewed)
			if err != nil {
				return nil, "", err
			}
			if err = session.check(upgrade.ctx); err != nil {
				session.Close()
				return nil, "", err
			}
			return session, cfg.Vault, nil
		}
		session, err := Open(filepath.Join(root, "managed-session"), upgrade.previous, reviewed)
		if err != nil {
			return nil, "", err
		}
		if err = session.UpgradeArtifact(upgrade.ctx, p, upgrade.review); err != nil {
			session.Close()
			return nil, "", err
		}
		return session, cfg.Vault, nil
	}
	session, e := Open(filepath.Join(root, "managed-session"), p, reviewed)
	return session, cfg.Vault, e
}

// Hints only locate a receipt. The reader independently proves transaction,
// event, block hash, chain identity and irreversible ancestry. They grant no
// signing authority and can change without changing the approved policy.
func locateRuntimeOperation(ctx context.Context, root string, pinned map[string]uint64, id string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if height := pinned[id]; height != 0 {
		return height, nil
	}
	raw, err := worker.ReadPrivateFile(filepath.Join(root, "operation-hints.json"), 512<<10)
	if err != nil {
		return 0, errors.New("source block hint unavailable")
	}
	hints, err := decodeOperationHints(raw)
	if err != nil || hints[id] == 0 {
		return 0, errors.New("source block hint unavailable")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return hints[id], nil
}

// RecoveryHintPreflight identifies a missing, non-authoritative locator before
// attempting a retired-journal import. It grants no signing permission: the
// normal reader still verifies each receipt, digest and irreversible anchor.
// The diagnostic deliberately omits operation IDs and private host paths.
func RecoveryHintPreflight(root, configPath string, source Journal) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(configPath) {
		return errors.New("absolute private recovery paths required")
	}
	required := []string{}
	for id := range source.Operations {
		if strings.HasPrefix(id, "koinos-to-evm/") {
			required = append(required, strings.TrimPrefix(id, "koinos-to-evm/"))
		}
	}
	if len(required) == 0 {
		return nil
	}
	raw, err := worker.ReadPrivateFile(configPath, 128<<10)
	var cfg RuntimeConfig
	if err != nil || host.JSON(raw, &cfg) != nil || cfg.Schema != 1 || len(cfg.BlockHints) > 4096 {
		return errors.New("invalid managed runtime configuration")
	}
	missing := false
	for _, id := range required {
		if cfg.BlockHints[id] == 0 {
			missing = true
			break
		}
	}
	if !missing {
		return nil
	}
	raw, err = worker.ReadPrivateFile(filepath.Join(root, "operation-hints.json"), 512<<10)
	if err != nil {
		return errors.New("source receipt locator unavailable; restore owner-only operation-hints.json and retry")
	}
	hints, err := decodeOperationHints(raw)
	if err != nil {
		return errors.New("source receipt locator unavailable; restore owner-only operation-hints.json and retry")
	}
	for _, id := range required {
		if cfg.BlockHints[id] == 0 && hints[id] == 0 {
			return errors.New("source receipt locator unavailable; restore owner-only operation-hints.json and retry")
		}
	}
	return nil
}

func decodeOperationHints(raw []byte) (map[string]uint64, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid hints")
	}
	hints := map[string]uint64{}
	for d.More() {
		token, err = d.Token()
		id, ok := token.(string)
		if err != nil || !ok || id == "" || len(hints) >= 4096 {
			return nil, errors.New("invalid hint identity")
		}
		if _, exists := hints[id]; exists {
			return nil, errors.New("duplicate hint")
		}
		var height uint64
		if d.Decode(&height) != nil || height == 0 {
			return nil, errors.New("invalid hint height")
		}
		hints[id] = height
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid hints")
	}
	var trailing interface{}
	if d.Decode(&trailing) != io.EOF {
		return nil, errors.New("trailing hints")
	}
	return hints, nil
}
