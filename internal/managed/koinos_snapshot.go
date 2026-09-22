package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	krpc "github.com/koinos-bridge/koinos-bridge-validator/internal/rpc"
	"github.com/koinos/koinos-proto-golang/koinos/canonical"
	sys "github.com/koinos/koinos-proto-golang/koinos/chain"
	chainrpc "github.com/koinos/koinos-proto-golang/koinos/rpc/chain"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multihash"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// KoinosSnapshot requires a separate read replica stopped/replayed at the live
// node's current LIB. Ordinary head reads are NOT upgraded to finality: replica
// height, block ID and state root must match the irreversible block receipt,
// and both live LIB and replica head/root must remain unchanged through the read.
// Providers are trusted; this is not a merkle-proof or consensus light client.
type KoinosSnapshot struct {
	live    operator.Binding
	replica string
}
type FinalKoinosState struct {
	ProfileDigest string
	Height        uint64
	BlockHash     string
	StateRoot     string
	CodeHash      string
	Nonce         uint64
	Validators    []string
	Paused        bool
	Completed     map[string]bool
	ObservedAt    time.Time
}

func NewKoinosSnapshot(live operator.Binding, replica string) (*KoinosSnapshot, error) {
	if live.Validate() != nil || live.Profile.Family != "koinos" || live.Profile.Environment != "local" || !live.Profile.Reviewed || operator.ValidateEndpoint(replica) != nil {
		return nil, errors.New("reviewed local Koinos route and private read-replica endpoint required")
	}
	return &KoinosSnapshot{live, replica}, nil
}
func snapshotCall(ctx context.Context, endpoint, method string, params interface{}, out interface{}) error {
	if method != "chain.read_contract" && method != "chain.invoke_system_call" {
		return errors.New("snapshot method forbidden")
	}
	if method == "chain.invoke_system_call" {
		p, ok := params.(map[string]interface{})
		if !ok || (p["name"] != "get_contract_metadata" && p["name"] != "get_object") {
			return errors.New("snapshot system call forbidden")
		}
	}
	raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if e != nil {
		return errors.New("invalid snapshot endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("snapshot redirect refused") }}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("snapshot RPC unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("snapshot RPC HTTP error")
	}
	raw, e = io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if e != nil || len(raw) > 2<<20 {
		return errors.New("snapshot RPC response oversized")
	}
	var envelope struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.ID != 1 || len(envelope.Result) == 0 || string(envelope.Result) == "null" || (len(envelope.Error) > 0 && string(envelope.Error) != "null") || json.Unmarshal(envelope.Result, out) != nil {
		return errors.New("invalid snapshot RPC response")
	}
	return nil
}
func wireUInt(b []byte, n protowire.Number, v uint64) []byte {
	if v == 0 {
		return b
	}
	return protowire.AppendVarint(protowire.AppendTag(b, n, protowire.VarintType), v)
}
func wireBytes(b []byte, n protowire.Number, v []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(b, n, protowire.BytesType), v)
}

type snapshotFields struct {
	ints map[protowire.Number]uint64
	data map[protowire.Number][][]byte
}

// Reject unexpected fields or wire types instead of interpreting missing fields
// as safe protobuf defaults after an incompatible or malformed RPC response.
func (f snapshotFields) only(ints, data []protowire.Number) bool {
	contains := func(ns []protowire.Number, n protowire.Number) bool {
		for _, v := range ns {
			if v == n {
				return true
			}
		}
		return false
	}
	for n := range f.ints {
		if !contains(ints, n) {
			return false
		}
	}
	for n := range f.data {
		if !contains(data, n) {
			return false
		}
	}
	return true
}

func snapshotWire(b []byte) (snapshotFields, error) {
	f := snapshotFields{map[protowire.Number]uint64{}, map[protowire.Number][][]byte{}}
	for len(b) > 0 {
		n, t, k := protowire.ConsumeTag(b)
		if k < 0 || n <= 0 {
			return f, errors.New("invalid snapshot protobuf tag")
		}
		b = b[k:]
		switch t {
		case protowire.VarintType:
			v, k := protowire.ConsumeVarint(b)
			if k < 0 {
				return f, errors.New("invalid snapshot integer")
			}
			if _, ok := f.ints[n]; ok || len(f.data[n]) > 0 {
				return f, errors.New("duplicate or mixed snapshot field")
			}
			f.ints[n] = v
			b = b[k:]
		case protowire.BytesType:
			v, k := protowire.ConsumeBytes(b)
			if k < 0 {
				return f, errors.New("invalid snapshot bytes")
			}
			if _, ok := f.ints[n]; ok {
				return f, errors.New("mixed snapshot field")
			}
			f.data[n] = append(f.data[n], append([]byte{}, v...))
			b = b[k:]
		default:
			return f, errors.New("unsupported snapshot field")
		}
	}
	return f, nil
}
func (s *KoinosSnapshot) read(ctx context.Context, name string, args []byte) ([]byte, error) {
	hash := sha256.Sum256([]byte(name))
	entry := uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3])
	var result struct {
		Result string `json:"result"`
	}
	if e := snapshotCall(ctx, s.replica, "chain.read_contract", map[string]interface{}{"contract_id": s.live.Profile.Contract, "entry_point": entry, "args": base64.URLEncoding.EncodeToString(args)}, &result); e != nil {
		return nil, e
	}
	b, e := base64.URLEncoding.DecodeString(result.Result)
	if e != nil {
		return nil, errors.New("snapshot contract result encoding invalid")
	}
	return b, nil
}
func (s *KoinosSnapshot) system(ctx context.Context, name string, args []byte) ([]byte, error) {
	var result struct {
		Value string `json:"value"`
	}
	if e := snapshotCall(ctx, s.replica, "chain.invoke_system_call", map[string]interface{}{"name": name, "args": base64.URLEncoding.EncodeToString(args)}, &result); e != nil {
		return nil, e
	}
	b, e := base64.URLEncoding.DecodeString(result.Value)
	if e != nil {
		return nil, errors.New("snapshot system result encoding invalid")
	}
	return b, nil
}
func sameSnapshot(a, b *chainrpc.GetHeadInfoResponse) bool {
	return a != nil && b != nil && a.HeadTopology != nil && b.HeadTopology != nil && a.HeadTopology.Height == b.HeadTopology.Height && bytes.Equal(a.HeadTopology.Id, b.HeadTopology.Id) && bytes.Equal(a.HeadStateMerkleRoot, b.HeadStateMerkleRoot)
}
func (s *KoinosSnapshot) Read(ctx context.Context, member string, transactions []string) (FinalKoinosState, error) {
	var out FinalKoinosState
	seed, e := transferAddress(s.live.Profile, member, false)
	if e != nil || len(transactions) > 256 {
		return out, errors.New("current membership seed and bounded transaction set required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	live := krpc.NewBoundedJsonRPC(s.live.RPC)
	replica := krpc.NewBoundedJsonRPC(s.replica)
	for _, node := range []*krpc.JsonRPC{live, replica} {
		id, e := node.GetChainID(ctx)
		if e != nil || base64.URLEncoding.EncodeToString(id) != s.live.Profile.NetworkID {
			return out, errors.New("snapshot network mismatch")
		}
	}
	liveHead, e := live.GetHeadInfo(ctx)
	if e != nil || liveHead.HeadTopology == nil || !hashPayload(liveHead.HeadTopology.Id) || liveHead.LastIrreversibleBlock == 0 || liveHead.LastIrreversibleBlock > liveHead.HeadTopology.Height {
		return out, errors.New("live irreversible anchor unavailable")
	}
	before, e := replica.GetHeadInfo(ctx)
	if e != nil || before.HeadTopology == nil || before.HeadTopology.Height != liveHead.LastIrreversibleBlock {
		return out, errors.New("read replica must be pinned exactly at current irreversible height")
	}
	batch, e := live.GetBlocksByHeight(ctx, multihash.Multihash(liveHead.HeadTopology.Id), liveHead.LastIrreversibleBlock, 1)
	if e != nil || len(batch.BlockItems) != 1 {
		return out, errors.New("irreversible block receipt unavailable")
	}
	block := batch.BlockItems[0]
	if block == nil || block.Block == nil || block.Block.Header == nil || block.Receipt == nil || block.BlockHeight != liveHead.LastIrreversibleBlock || block.Block.Header.Height != block.BlockHeight || block.Receipt.Height != block.BlockHeight || !hashPayload(block.BlockId) || !bytes.Equal(block.Block.Id, block.BlockId) || !bytes.Equal(block.Receipt.Id, block.BlockId) || !bytes.Equal(before.HeadTopology.Id, block.BlockId) || !hashPayload(block.Receipt.StateMerkleRoot) || !bytes.Equal(before.HeadStateMerkleRoot, block.Receipt.StateMerkleRoot) {
		return out, errors.New("replica does not match irreversible block and state root")
	}
	raw, e := canonical.Marshal(block.Block.Header)
	h := sha256.Sum256(raw)
	if e != nil || !bytes.Equal(h[:], block.BlockId[2:]) {
		return out, errors.New("irreversible header hash mismatch")
	}
	contract, _ := base58.Decode(s.live.Profile.Contract)
	raw, e = s.system(ctx, "get_contract_metadata", wireBytes(nil, 1, contract))
	if e != nil {
		return out, e
	}
	outer, e := snapshotWire(raw)
	if e != nil || len(outer.data[1]) != 1 || !outer.only(nil, []protowire.Number{1}) {
		return out, errors.New("code metadata missing")
	}
	meta, e := snapshotWire(outer.data[1][0])
	if e != nil || !meta.only([]protowire.Number{2, 3, 4, 5}, []protowire.Number{1}) || len(meta.data[1]) != 1 || !hashPayload(meta.data[1][0]) || hex.EncodeToString(meta.data[1][0][2:]) != s.live.Profile.CodeHash {
		return out, errors.New("irreversible code hash differs from reviewed build")
	}
	for _, n := range []protowire.Number{2, 3, 4, 5} {
		if meta.ints[n] != 0 {
			return out, errors.New("unsupported contract authority override")
		}
	}
	raw, e = s.read(ctx, "get_metadata", nil)
	if e != nil {
		return out, e
	}
	state, e := snapshotWire(raw)
	if e != nil || !state.only([]protowire.Number{1, 2, 3, 4}, nil) || state.ints[1] != 1 || state.ints[3] != uint64(s.live.Profile.BridgeChainID) || state.ints[4] == 0 || state.ints[4] > 256 {
		return out, errors.New("invalid initialized bridge metadata")
	}
	members := map[string]bool{}
	for _, descending := range []bool{false, true} {
		args := wireUInt(wireBytes(nil, 1, seed), 2, state.ints[4])
		if descending {
			args = wireUInt(args, 3, 1)
		}
		raw, e = s.read(ctx, "get_validators", args)
		if e != nil {
			return out, e
		}
		list, e := snapshotWire(raw)
		if e != nil || !list.only(nil, []protowire.Number{1}) || len(list.data[1]) == 0 || uint64(len(list.data[1])) > state.ints[4] || !bytes.Equal(list.data[1][0], seed) {
			return out, errors.New("membership seed missing or pagination invalid")
		}
		for i, address := range list.data[1] {
			name := base58.Encode(address)
			if _, e = transferAddress(s.live.Profile, name, false); e != nil {
				return out, e
			}
			if i > 0 {
				order := bytes.Compare(list.data[1][i-1], address)
				if (!descending && order >= 0) || (descending && order <= 0) {
					return out, errors.New("membership order or uniqueness invalid")
				}
			}
			members[name] = true
		}
	}
	if uint64(len(members)) != state.ints[4] {
		return out, errors.New("irreversible membership enumeration incomplete")
	}
	pauseArgs, _ := proto.Marshal(&sys.GetObjectArguments{Space: &sys.ObjectSpace{Zone: contract, Id: 100002}})
	raw, e = s.system(ctx, "get_object", pauseArgs)
	if e != nil {
		return out, e
	}
	var pause sys.GetObjectResult
	if proto.Unmarshal(raw, &pause) != nil || pause.Value == nil {
		return out, errors.New("pause state unavailable")
	}
	out.Completed = map[string]bool{}
	for _, tx := range transactions {
		b, e := hex.DecodeString(tx)
		if e != nil || len(b) != 32 || hex.EncodeToString(b) != tx {
			return out, errors.New("invalid completion transaction hash")
		}
		raw, e = s.read(ctx, "get_transfer_status", wireBytes(nil, 1, b))
		if e != nil {
			return out, e
		}
		done, e := snapshotWire(raw)
		if e != nil || done.ints[1] > 1 || !done.only([]protowire.Number{1}, nil) {
			return out, errors.New("invalid completion status")
		}
		out.Completed[tx] = done.ints[1] == 1
	}
	after, e := replica.GetHeadInfo(ctx)
	if e != nil || !sameSnapshot(before, after) {
		return out, errors.New("read replica changed during snapshot")
	}
	liveAfter, e := live.GetHeadInfo(ctx)
	if e != nil || liveAfter.HeadTopology == nil || !hashPayload(liveAfter.HeadTopology.Id) || liveAfter.HeadTopology.Height < liveAfter.LastIrreversibleBlock || liveAfter.LastIrreversibleBlock != liveHead.LastIrreversibleBlock {
		return out, errors.New("live irreversible anchor advanced; refresh replica")
	}
	again, e := live.GetBlocksByHeight(ctx, multihash.Multihash(liveAfter.HeadTopology.Id), liveAfter.LastIrreversibleBlock, 1)
	if e != nil || len(again.BlockItems) != 1 || again.BlockItems[0] == nil || again.BlockItems[0].Receipt == nil || !bytes.Equal(again.BlockItems[0].BlockId, block.BlockId) || !bytes.Equal(again.BlockItems[0].Receipt.StateMerkleRoot, block.Receipt.StateMerkleRoot) {
		return out, errors.New("irreversible anchor branch changed during snapshot")
	}
	for _, node := range []*krpc.JsonRPC{live, replica} {
		id, e := node.GetChainID(ctx)
		if e != nil || base64.URLEncoding.EncodeToString(id) != s.live.Profile.NetworkID {
			return out, errors.New("snapshot network changed")
		}
	}
	out.ProfileDigest = s.live.Profile.Digest()
	out.Height = block.BlockHeight
	out.BlockHash = hex.EncodeToString(block.BlockId[2:])
	out.StateRoot = hex.EncodeToString(block.Receipt.StateMerkleRoot)
	out.CodeHash = s.live.Profile.CodeHash
	out.Nonce = state.ints[2]
	out.Paused = pause.Value.Exists
	out.ObservedAt = time.Now()
	// Stable ordering makes checkpoint encodings reproducible.
	for name := range members {
		out.Validators = append(out.Validators, name)
	}
	sort.Strings(out.Validators)
	return out, nil
}
