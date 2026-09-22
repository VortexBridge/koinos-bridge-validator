package managed

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

// EVMSnapshot pins all state calls to one finalized block hash. RPC providers
// remain trusted. This does not authorize activation or submit transactions.
type EVMSnapshot struct{ binding operator.Binding }
type FinalEVMState struct {
	ProfileDigest string
	Height        uint64
	BlockHash     string
	CodeHash      string
	Nonce         string
	Validators    []string
	Membership    map[string]bool // includes explicit requested old/new identities
	Paused        bool
	ObservedAt    time.Time
}

func NewEVMSnapshot(binding operator.Binding) (*EVMSnapshot, error) {
	if binding.Validate() != nil || binding.Profile.Family != "evm" || binding.Profile.Environment != "local" || !binding.Profile.Reviewed {
		return nil, errors.New("reviewed local EVM binding required")
	}
	return &EVMSnapshot{binding}, nil
}
func (s *EVMSnapshot) identity(ctx context.Context) error {
	var id string
	if rpcRead(ctx, s.binding.RPC, "eth_chainId", []interface{}{}, &id) != nil {
		return errors.New("EVM identity unavailable")
	}
	n, e := hexutil.DecodeBig(id)
	if e != nil || n.String() != s.binding.Profile.NetworkID {
		return errors.New("EVM network mismatch")
	}
	return nil
}
func (s *EVMSnapshot) Read(ctx context.Context, probes []string) (FinalEVMState, error) {
	var out FinalEVMState
	if len(probes) > 32 {
		return out, errors.New("too many identity probes")
	}
	requested := map[string]bool{}
	for _, p := range probes {
		if _, e := transferAddress(s.binding.Profile, p, false); e != nil {
			return out, e
		}
		requested[common.HexToAddress(p).Hex()] = true
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if e := s.identity(ctx); e != nil {
		return out, e
	}
	var block evmReadBlock
	if rpcRead(ctx, s.binding.RPC, "eth_getBlockByNumber", []interface{}{"finalized", false}, &block) != nil || !evmHash(block.Hash) {
		return out, errors.New("finalized EVM state unavailable")
	}
	height, e := hexutil.DecodeUint64(block.Number)
	if e != nil || height == 0 {
		return out, errors.New("invalid finalized height")
	}
	selector := map[string]interface{}{"blockHash": block.Hash, "requireCanonical": true}
	var code string
	if rpcRead(ctx, s.binding.RPC, "eth_getCode", []interface{}{s.binding.Profile.Contract, selector}, &code) != nil {
		return out, errors.New("finalized EVM code unavailable")
	}
	raw, e := hexutil.Decode(code)
	if e != nil || len(raw) == 0 || hex.EncodeToString(crypto.Keccak256(raw)) != s.binding.Profile.CodeHash {
		return out, errors.New("finalized EVM code mismatch")
	}
	call := func(signature string, arg []byte) ([]byte, error) {
		data := append(append([]byte{}, crypto.Keccak256([]byte(signature))[:4]...), arg...)
		var result string
		if rpcRead(ctx, s.binding.RPC, "eth_call", []interface{}{map[string]string{"to": s.binding.Profile.Contract, "data": hexutil.Encode(data)}, selector}, &result) != nil {
			return nil, errors.New("finalized EVM state call failed")
		}
		b, e := hexutil.Decode(result)
		if e != nil || len(b) != 32 {
			return nil, errors.New("invalid EVM return word")
		}
		return b, nil
	}
	number := func(signature string) (*big.Int, error) {
		b, e := call(signature, nil)
		if e != nil {
			return nil, e
		}
		return new(big.Int).SetBytes(b), nil
	}
	chain, e := number("chainId()")
	if e != nil || !chain.IsUint64() || chain.Uint64() != uint64(s.binding.Profile.BridgeChainID) {
		return out, errors.New("bridge chain identity mismatch")
	}
	nonce, e := number("nonce()")
	if e != nil {
		return out, e
	}
	paused, e := number("paused()")
	if e != nil || paused.Cmp(big.NewInt(1)) > 0 {
		return out, errors.New("invalid EVM pause state")
	}
	count, e := number("getValidatorsLength()")
	if e != nil || !count.IsUint64() || count.Uint64() == 0 || count.Uint64() > 256 {
		return out, errors.New("invalid EVM validator count")
	}
	members := map[string]bool{}
	for i := uint64(0); i < count.Uint64(); i++ {
		arg := new(big.Int).SetUint64(i).FillBytes(make([]byte, 32))
		b, e := call("validators(uint256)", arg)
		if e != nil {
			return out, e
		}
		if new(big.Int).SetBytes(b[:12]).Sign() != 0 {
			return out, errors.New("noncanonical EVM address word")
		}
		address := common.BytesToAddress(b[12:]).Hex()
		if _, e = transferAddress(s.binding.Profile, address, false); e != nil || members[address] {
			return out, errors.New("invalid or duplicate EVM validator")
		}
		members[address] = true
		requested[address] = true
		out.Validators = append(out.Validators, address)
	}
	out.Membership = map[string]bool{}
	for address := range requested {
		arg := common.LeftPadBytes(common.HexToAddress(address).Bytes(), 32)
		b, e := call("isValidator(address)", arg)
		if e != nil {
			return out, e
		}
		n := new(big.Int).SetBytes(b)
		if n.Cmp(big.NewInt(1)) > 0 {
			return out, errors.New("invalid EVM membership flag")
		}
		active := n.Sign() == 1
		// A flag/list inconsistency cannot establish current quorum or retirement.
		if active != members[address] {
			return out, errors.New("EVM validator list and authority mapping disagree")
		}
		out.Membership[address] = active
	}
	var canonical, final evmReadBlock
	if rpcRead(ctx, s.binding.RPC, "eth_getBlockByNumber", []interface{}{block.Number, false}, &canonical) != nil || canonical.Number != block.Number || canonical.Hash != block.Hash {
		return out, errors.New("finalized EVM block changed")
	}
	if rpcRead(ctx, s.binding.RPC, "eth_getBlockByNumber", []interface{}{"finalized", false}, &final) != nil || !evmHash(final.Hash) {
		return out, errors.New("EVM finality unavailable after read")
	}
	last, e := hexutil.DecodeUint64(final.Number)
	if e != nil || last < height || (last == height && final.Hash != block.Hash) {
		return out, errors.New("EVM finality regressed or changed")
	}
	if e = s.identity(ctx); e != nil {
		return out, e
	}
	out.ProfileDigest = s.binding.Profile.Digest()
	out.Height = height
	out.BlockHash = strings.TrimPrefix(block.Hash, "0x")
	out.CodeHash = s.binding.Profile.CodeHash
	out.Nonce = nonce.String()
	out.Paused = paused.Sign() == 1
	out.ObservedAt = time.Now()
	return out, nil
}
