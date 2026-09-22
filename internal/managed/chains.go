package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// ChainVerifier joins finalized state from both chains. It deliberately leaves
// release and host readiness false: independent local gates must establish them.
// Its base Operation method cannot sign; use a typed OperationVerifier wrapper.
type ChainVerifier struct {
	evm        *EVMSnapshot
	koinos     *KoinosSnapshot
	evmRead    func(context.Context, []string) (FinalEVMState, error)
	koinosRead func(context.Context, string, []string) (FinalKoinosState, error)
}

func NewChainVerifier(evm *EVMSnapshot, koinos *KoinosSnapshot) (*ChainVerifier, error) {
	if evm == nil || koinos == nil {
		return nil, errors.New("both finalized state readers required")
	}
	// The activation path supports the isolated EVM development chain only.
	// Relabeling a public Koinos profile as local must not authorize public signing.
	if evm.binding.Profile.Environment != "local" || evm.binding.Profile.NetworkID != "31337" || koinos.live.Profile.Environment != "local" || koinos.live.Profile.NetworkID == "EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==" || koinos.live.Profile.NetworkID == "EiBncD4pKRIQWco_WRqo5Q-xnXR7JuO3PtZv983mKdKHSQ==" {
		return nil, errors.New("isolated development identities required; public managed signing blocked")
	}
	return &ChainVerifier{evm, koinos, evm.Read, koinos.Read}, nil
}
func (v *ChainVerifier) Inspect(ctx context.Context, p Policy) (Evidence, error) {
	var out Evidence
	if _, e := transferAddress(v.evm.binding.Profile, p.EVMAddress, false); e != nil {
		return out, e
	}
	if _, e := transferAddress(v.koinos.live.Profile, p.KoinosAddress, false); e != nil {
		return out, e
	}
	probes := []string{p.EVMAddress}
	replacing := p.PreviousEVM != "" || p.PreviousKoinos != ""
	if replacing {
		if p.PreviousEVM == "" || p.PreviousKoinos == "" || strings.EqualFold(p.PreviousEVM, p.EVMAddress) || p.PreviousKoinos == p.KoinosAddress {
			return out, errors.New("replacement must rotate both identities")
		}
		if _, e := transferAddress(v.evm.binding.Profile, p.PreviousEVM, false); e != nil {
			return out, e
		}
		if _, e := transferAddress(v.koinos.live.Profile, p.PreviousKoinos, false); e != nil {
			return out, e
		}
		probes = append(probes, p.PreviousEVM)
	}
	// Independent RPC reads share cancellation but never share authority decisions.
	evm, e := v.evmRead(ctx, probes)
	if e != nil {
		return out, e
	}
	koinos, e := v.koinosRead(ctx, p.KoinosAddress, nil)
	if e != nil {
		return out, e
	}
	now := time.Now()
	fresh := func(t time.Time) bool { return !t.After(now) && now.Sub(t) <= 15*time.Second }
	if ctx.Err() != nil || !fresh(evm.ObservedAt) || !fresh(koinos.ObservedAt) || evm.ProfileDigest != v.evm.binding.Profile.Digest() || koinos.ProfileDigest != v.koinos.live.Profile.Digest() || evm.CodeHash != v.evm.binding.Profile.CodeHash || koinos.CodeHash != v.koinos.live.Profile.CodeHash || !validHash(evm.BlockHash) || !validHash(koinos.BlockHash) || evm.Height == 0 || koinos.Height == 0 {
		return out, errors.New("finalized chain evidence is stale or mismatched")
	}
	if evm.Paused || koinos.Paused {
		return out, errors.New("bridge paused on at least one chain")
	}
	contains := func(members []string, member string) bool {
		for _, m := range members {
			if m == member {
				return true
			}
		}
		return false
	}
	evmAddress := common.HexToAddress(p.EVMAddress).Hex()
	if !contains(evm.Validators, evmAddress) || !evm.Membership[evmAddress] || !contains(koinos.Validators, p.KoinosAddress) {
		return out, errors.New("new signing identities are not finalized members on both chains")
	}
	if replacing {
		previous := common.HexToAddress(p.PreviousEVM).Hex()
		active, checked := evm.Membership[previous]
		if !checked || active || contains(evm.Validators, previous) || contains(koinos.Validators, p.PreviousKoinos) {
			return out, errors.New("previous identities are not retired on both chains")
		}
		out.RemovedEVM = p.PreviousEVM
		out.RemovedKoinos = p.PreviousKoinos
		out.RotationFinal = true
	}
	checked := evm.ObservedAt
	if koinos.ObservedAt.Before(checked) {
		checked = koinos.ObservedAt
	}
	out.CheckedAt = checked
	out.ExpiresAt = checked.Add(15 * time.Second)
	out.PolicySHA256 = Digest(p)
	out.ArtifactSHA256 = p.ArtifactSHA256
	out.ConfigSHA256 = p.ConfigSHA256
	out.LocalDevelopment = true
	out.NetworksMatch = true
	out.ProvenanceVerified = true
	out.MembershipFinal = true
	out.EVMMember = p.EVMAddress
	out.KoinosMember = p.KoinosAddress
	// Block identities bind membership/code state. Nonces and profile digests keep
	// governance changes and route changes explicit in the reconciliation anchor.
	raw, _ := jsonBytes(struct {
		Policy, EVMBlock, KoinosBlock, EVMProfile, KoinosProfile, EVMNonce, KoinosRoot string
		KoinosNonce                                                                    uint64
	}{out.PolicySHA256, evm.BlockHash, koinos.BlockHash, evm.ProfileDigest, koinos.ProfileDigest, evm.Nonce, koinos.StateRoot, koinos.Nonce})
	hash := sha256.Sum256(raw)
	out.Checkpoint = hex.EncodeToString(hash[:])
	return out, nil
}
func (v *ChainVerifier) Reconcile(ctx context.Context, p Policy, j Journal) (string, error) {
	// A caller with retained operations must use OperationVerifier, which rechecks
	// every receipt. This base refuses to certify an unexamined nonempty journal.
	if len(j.Operations) > 0 {
		return "", errors.New("typed operation reconciliation required")
	}
	e, err := v.Inspect(ctx, p)
	return e.Checkpoint, err
}
func (v *ChainVerifier) Operation(context.Context, Policy, string) (Operation, error) {
	return Operation{}, errors.New("typed transfer reader required")
}
