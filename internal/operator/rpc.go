package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/encoding/protowire"
)

type Binding struct {
	Profile Profile `json:"profile"`
	RPC     string  `json:"rpc"` // private; never returned in status or diagnostics
}

func (b Binding) Validate() error {
	if err := b.Profile.Validate(); err != nil {
		return err
	}
	return ValidateEndpoint(b.RPC)
}

type Observation struct {
	Complete              bool      `json:"complete"`
	ConfigurationRevision uint64    `json:"configurationRevision"`
	ProfileID             string    `json:"profileId"`
	ObservedAt            time.Time `json:"observedAt"`
	Status                string    `json:"status"`
	Message               string    `json:"message"`
	NetworkID             string    `json:"networkId,omitempty"`
	Block                 string    `json:"block,omitempty"`
	BlockHash             string    `json:"blockHash,omitempty"`
	Finality              string    `json:"finality"`
	CodeHash              string    `json:"codeHash,omitempty"`
	Nonce                 string    `json:"nonce,omitempty"`
	BridgeChainID         uint32    `json:"bridgeChainId,omitempty"`
	Paused                *bool     `json:"paused"`
	Validators            []string  `json:"validators"`
	Quorum                int       `json:"quorum"`
	GovernanceReady       bool      `json:"governanceReady"`
}

// rpcClient can only issue read methods. It rejects redirects so a configured
// endpoint cannot forward credentials to another host. Errors are sanitized.
type rpcClient struct {
	endpoint string
	client   *http.Client
}

var readMethods = map[string]bool{"eth_chainId": true, "eth_getBlockByNumber": true, "eth_getCode": true, "eth_call": true, "chain.get_chain_id": true, "chain.get_head_info": true, "chain.read_contract": true}

func (r rpcClient) call(ctx context.Context, method string, params interface{}, result interface{}) error {
	if !readMethods[method] {
		return errors.New("RPC method is not read-only allowlisted")
	}
	b, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return errors.New("invalid RPC request")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(b))
	if err != nil {
		return errors.New("invalid RPC endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := r.client.Do(req)
	if err != nil {
		return errors.New("RPC unavailable or timed out")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("RPC HTTP status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 {
		return errors.New("RPC response too large or unreadable")
	}
	var envelope struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.ID != 1 || len(envelope.Result) == 0 || string(envelope.Result) == "null" || (len(envelope.Error) > 0 && string(envelope.Error) != "null") {
		return errors.New("RPC returned an invalid response or an error")
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return errors.New("RPC result has an unexpected format")
	}
	return nil
}

func Observe(ctx context.Context, b Binding) Observation {
	o := Observation{ProfileID: b.Profile.ID, ObservedAt: time.Now().UTC(), Status: "unavailable", Finality: "unknown", Validators: []string{}}
	if err := b.Validate(); err != nil {
		o.Message = err.Error()
		return o
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	rpc := rpcClient{b.RPC, &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects disabled") }}}
	var err error
	if b.Profile.Family == "evm" {
		err = observeEVM(ctx, rpc, b.Profile, &o)
	} else {
		err = observeKoinos(ctx, rpc, b.Profile, &o)
	}
	if err != nil {
		o.Message = err.Error()
		o.GovernanceReady = false
		return o
	}
	o.Status = "observed"
	o.Complete = true
	o.Message = "Observation only. No validator signer is running in the operator service."
	if o.CodeHash != "" && b.Profile.CodeHash != "" && o.CodeHash != b.Profile.CodeHash {
		o.Status = "mismatch"
		o.Message = "Contract code differs from the locally approved profile."
		return o
	}
	// Production authority remains gated pending deployed-version and safety
	// review. A profile flag alone never enables a production signing path.
	o.GovernanceReady = b.Profile.Environment == "local" && b.Profile.Reviewed && o.CodeHash == b.Profile.CodeHash && o.Finality == "finalized" && len(o.Validators) > 0
	return o
}

func readHexNumber(s string) (*big.Int, error) {
	if !strings.HasPrefix(s, "0x") || len(s) <= 2 || len(s) > 66 {
		return nil, errors.New("invalid RPC hex integer")
	}
	n, ok := new(big.Int).SetString(s[2:], 16)
	if !ok {
		return nil, errors.New("invalid RPC hex integer")
	}
	return n, nil
}
func observeEVM(ctx context.Context, r rpcClient, p Profile, o *Observation) error {
	var identity string
	if err := r.call(ctx, "eth_chainId", []interface{}{}, &identity); err != nil {
		return err
	}
	n, err := readHexNumber(identity)
	if err != nil {
		return err
	}
	o.NetworkID = n.String()
	if o.NetworkID != p.NetworkID {
		o.Status = "mismatch"
		return errors.New("RPC network identity differs from the profile")
	}
	var block struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if err := r.call(ctx, "eth_getBlockByNumber", []interface{}{"finalized", false}, &block); err != nil {
		return errors.New("finalized EVM block unavailable; observation cannot assume latest is final")
	}
	if _, err := readHexNumber(block.Number); err != nil {
		return err
	}
	if len(block.Hash) != 66 {
		return errors.New("invalid finalized block hash")
	}
	o.Block = block.Number
	o.BlockHash = block.Hash
	o.Finality = "finalized"
	var code string
	if err := r.call(ctx, "eth_getCode", []interface{}{p.Contract, block.Number}, &code); err != nil {
		return err
	}
	if !strings.HasPrefix(code, "0x") {
		return errors.New("invalid EVM bytecode")
	}
	codeBytes, err := hex.DecodeString(code[2:])
	if err != nil || len(codeBytes) == 0 {
		return errors.New("no valid contract bytecode at selected address")
	}
	o.CodeHash = hex.EncodeToString(crypto.Keccak256(codeBytes))
	call := func(method string, args ...*big.Int) (*big.Int, error) {
		data := crypto.Keccak256([]byte(method))[:4]
		for _, arg := range args {
			data = append(data, word(arg)...)
		}
		var value string
		if err := r.call(ctx, "eth_call", []interface{}{map[string]string{"to": p.Contract, "data": "0x" + hex.EncodeToString(data)}, block.Number}, &value); err != nil {
			return nil, err
		}
		if len(value) != 66 {
			return nil, errors.New("invalid contract return size")
		}
		return readHexNumber(value)
	}
	chain, err := call("chainId()")
	if err != nil {
		return err
	}
	if chain.BitLen() > 32 || uint32(chain.Uint64()) != p.BridgeChainID {
		o.Status = "mismatch"
		return errors.New("contract bridgeChainId differs from profile")
	}
	o.BridgeChainID = uint32(chain.Uint64())
	nonce, err := call("nonce()")
	if err != nil {
		return err
	}
	o.Nonce = nonce.String()
	paused, err := call("paused()")
	if err != nil {
		return err
	}
	if paused.Cmp(big.NewInt(1)) > 0 {
		return errors.New("invalid paused value")
	}
	v := paused.Sign() != 0
	o.Paused = &v
	count, err := call("getValidatorsLength()")
	if err != nil {
		return err
	}
	if !count.IsInt64() || count.Int64() > 256 {
		return errors.New("validator count exceeds operator read limit")
	}
	seen := map[string]bool{}
	for i := int64(0); i < count.Int64(); i++ {
		member, err := call("validators(uint256)", big.NewInt(i))
		if err != nil {
			return err
		}
		if member.BitLen() > 160 {
			return errors.New("invalid validator address word")
		}
		b := make([]byte, 20)
		member.FillBytes(b)
		addr := "0x" + hex.EncodeToString(b)
		if _, err := addressBytes("evm", addr); err != nil {
			return err
		}
		if seen[addr] {
			return errors.New("duplicate on-chain validator")
		}
		seen[addr] = true
		o.Validators = append(o.Validators, addr)
	}
	o.Quorum = Quorum(len(o.Validators))
	// Check the numbered block still resolves to the same canonical block after
	// all reads. No latest-state/numbered-state mixing is permitted.
	var after struct {
		Hash string `json:"hash"`
	}
	if err := r.call(ctx, "eth_getBlockByNumber", []interface{}{block.Number, false}, &after); err != nil {
		return err
	}
	if after.Hash != block.Hash {
		return errors.New("block identity changed during observation")
	}
	return nil
}

func observeKoinos(ctx context.Context, r rpcClient, p Profile, o *Observation) error {
	var identity struct {
		ChainID string `json:"chain_id"`
	}
	if err := r.call(ctx, "chain.get_chain_id", map[string]interface{}{}, &identity); err != nil {
		return err
	}
	o.NetworkID = identity.ChainID
	if identity.ChainID != p.NetworkID {
		o.Status = "mismatch"
		return errors.New("RPC network identity differs from profile")
	}
	var head struct {
		HeadTopology struct {
			ID     string `json:"id"`
			Height string `json:"height"`
		} `json:"head_topology"`
		LastIrreversibleBlock string `json:"last_irreversible_block"`
	}
	if err := r.call(ctx, "chain.get_head_info", map[string]interface{}{}, &head); err != nil {
		return err
	}
	o.Block = head.HeadTopology.Height
	o.BlockHash = head.HeadTopology.ID
	o.Finality = "head snapshot; not pinned to irreversible state"
	read := func(name string, args []byte) ([]byte, error) {
		h := sha256.Sum256([]byte(name))
		ep := uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
		var res struct {
			Result string `json:"result"`
		}
		if err := r.call(ctx, "chain.read_contract", map[string]interface{}{"contract_id": p.Contract, "entry_point": ep, "args": base64.URLEncoding.EncodeToString(args)}, &res); err != nil {
			return nil, err
		}
		data, err := base64.URLEncoding.DecodeString(res.Result)
		if err != nil {
			return nil, errors.New("invalid Koinos result encoding")
		}
		return data, nil
	}
	meta, err := read("get_metadata", nil)
	if err != nil {
		return err
	}
	fields, err := wireFields(meta)
	if err != nil {
		return err
	}
	if fields.ints[1] != 1 {
		return errors.New("Koinos contract not initialized")
	}
	o.Nonce = fmt.Sprint(fields.ints[2])
	chain := fields.ints[3]
	if chain > 1<<32-1 || uint32(chain) != p.BridgeChainID {
		o.Status = "mismatch"
		return errors.New("contract bridgeChainId differs from profile")
	}
	o.BridgeChainID = uint32(chain)
	count := fields.ints[4]
	if count > 256 {
		return errors.New("validator count exceeds operator read limit")
	}
	// Current getter supports pagination; request one extra to detect a mismatch.
	validators, err := read("get_validators", fieldUint(nil, 2, count+1))
	if err != nil {
		return err
	}
	vf, err := wireFields(validators)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, addr := range vf.bytes[1] {
		s := base58.Encode(addr)
		if _, err := addressBytes("koinos", s); err != nil {
			return err
		}
		if seen[s] {
			return errors.New("duplicate on-chain validator")
		}
		seen[s] = true
		o.Validators = append(o.Validators, s)
	}
	if uint64(len(o.Validators)) != count {
		return errors.New("Koinos membership changed or pagination incomplete")
	}
	o.Quorum = Quorum(len(o.Validators))
	var after struct {
		HeadTopology struct {
			ID string `json:"id"`
		} `json:"head_topology"`
	}
	if err := r.call(ctx, "chain.get_head_info", map[string]interface{}{}, &after); err != nil {
		return err
	}
	if after.HeadTopology.ID != head.HeadTopology.ID {
		return errors.New("Koinos head changed during observation; retry")
	}
	// This source has no pause getter. Unknown remains null. ABI/code attestation
	// and irreversible-state reads are required before Koinos signing enablement.
	return nil
}

type wireMessage struct {
	ints  map[protowire.Number]uint64
	bytes map[protowire.Number][][]byte
}

func wireFields(raw []byte) (wireMessage, error) {
	m := wireMessage{map[protowire.Number]uint64{}, map[protowire.Number][][]byte{}}
	for len(raw) > 0 {
		n, typ, k := protowire.ConsumeTag(raw)
		if k < 0 {
			return m, errors.New("invalid protobuf tag")
		}
		raw = raw[k:]
		switch typ {
		case protowire.VarintType:
			v, k := protowire.ConsumeVarint(raw)
			if k < 0 {
				return m, errors.New("invalid protobuf integer")
			}
			m.ints[n] = v
			raw = raw[k:]
		case protowire.BytesType:
			v, k := protowire.ConsumeBytes(raw)
			if k < 0 {
				return m, errors.New("invalid protobuf bytes")
			}
			m.bytes[n] = append(m.bytes[n], v)
			raw = raw[k:]
		default:
			return m, errors.New("unexpected protobuf field type")
		}
	}
	return m, nil
}
