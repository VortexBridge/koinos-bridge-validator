package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

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
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		height, ok := cfg.BlockHints[id]
		if !ok || height == 0 {
			return 0, errors.New("source block hint unavailable")
		}
		return height, nil
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
	session, e := Open(filepath.Join(root, "managed-session"), p, reviewed)
	return session, cfg.Vault, e
}
