package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/koinos/koinos-proto-golang/koinos/canonical"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	krpc "github.com/koinos-bridge/koinos-bridge-validator/internal/rpc"
	bridge "github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multihash"
	"google.golang.org/protobuf/proto"
)

// KoinosEVMReader reconstructs a transfer from the irreversible Koinos block
// receipt and an EIP-1898-pinned EVM completion read. It trusts the configured
// read RPCs; it is not a light-client proof and does not prove Koinos membership.
// Local profiles only: public activation remains blocked by Prompt 02.
type KoinosEVMReader struct {
	source      operator.Binding
	destination operator.Binding
	tokens      map[string]string
	lifetime    uint64
	locate      func(context.Context, string) (uint64, error)
}

func NewKoinosEVMReader(source, destination operator.Binding, tokens map[string]string, lifetime uint64, locate func(context.Context, string) (uint64, error)) (*KoinosEVMReader, error) {
	if source.Validate() != nil || destination.Validate() != nil || source.Profile.Family != "koinos" || destination.Profile.Family != "evm" || source.Profile.Environment != "local" || destination.Profile.Environment != "local" || !source.Profile.Reviewed || !destination.Profile.Reviewed || lifetime == 0 || lifetime > 86400000 || locate == nil || len(tokens) == 0 || len(tokens) > 128 {
		return nil, errors.New("reviewed local Koinos/EVM route, token map, bounded lifetime and locator required")
	}
	copied := map[string]string{}
	for from, to := range tokens {
		if _, e := transferAddress(source.Profile, from, false); e != nil {
			return nil, e
		}
		if _, e := transferAddress(destination.Profile, to, false); e != nil {
			return nil, e
		}
		copied[from] = to
	}
	return &KoinosEVMReader{source, destination, copied, lifetime, locate}, nil
}
func rpcRead(ctx context.Context, endpoint, method string, params interface{}, out interface{}) error {
	switch method {
	case "eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call":
	default:
		return errors.New("method is not read-only allowlisted")
	}
	raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if e != nil {
		return errors.New("invalid read endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	response, e := client.Do(req)
	if e != nil {
		return errors.New("read RPC unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("read RPC HTTP failure")
	}
	raw, e = io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if e != nil || len(raw) > 2<<20 {
		return errors.New("read RPC response oversized")
	}
	var envelope struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.ID != 1 || len(envelope.Result) == 0 || string(envelope.Result) == "null" || (len(envelope.Error) > 0 && string(envelope.Error) != "null") || json.Unmarshal(envelope.Result, out) != nil {
		return errors.New("invalid read RPC response")
	}
	return nil
}
func (r *KoinosEVMReader) identities(ctx context.Context, k *krpc.JsonRPC) error {
	id, e := k.GetChainID(ctx)
	if e != nil || base64.URLEncoding.EncodeToString(id) != r.source.Profile.NetworkID {
		return errors.New("Koinos network identity mismatch")
	}
	var evm string
	if rpcRead(ctx, r.destination.RPC, "eth_chainId", []interface{}{}, &evm) != nil {
		return errors.New("EVM network identity unavailable")
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(evm, "0x"), 16)
	if !strings.HasPrefix(evm, "0x") || !ok || n.String() != r.destination.Profile.NetworkID {
		return errors.New("EVM network identity mismatch")
	}
	return nil
}
func hashPayload(b []byte) bool { return len(b) == 34 && b[0] == 0x12 && b[1] == 0x20 }
func (r *KoinosEVMReader) ReadTransfer(ctx context.Context, id string) (TransferObservation, error) {
	var out TransferObservation
	parts := strings.Split(id, ":")
	if len(parts) != 2 {
		return out, errors.New("canonical transaction and operation ID required")
	}
	tx, e := hex.DecodeString(parts[0])
	sequence, seqErr := strconv.ParseUint(parts[1], 10, 32)
	if e != nil || (len(tx) != 32 && !hashPayload(tx)) || hex.EncodeToString(tx) != parts[0] || seqErr != nil || strconv.FormatUint(sequence, 10) != parts[1] {
		return out, errors.New("invalid transfer identity")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	height, e := r.locate(ctx, id)
	if e != nil || height == 0 {
		return out, errors.New("source block locator unavailable")
	}
	k := krpc.NewBoundedJsonRPC(r.source.RPC)
	if e = r.identities(ctx, k); e != nil {
		return out, e
	}
	head, e := k.GetHeadInfo(ctx)
	if e != nil || head.HeadTopology == nil || !hashPayload(head.HeadTopology.Id) || height > head.LastIrreversibleBlock || head.LastIrreversibleBlock > head.HeadTopology.Height {
		return out, errors.New("source block is not irreversibly anchored")
	}
	blocks, e := k.GetBlocksByHeight(ctx, multihash.Multihash(head.HeadTopology.Id), height, 1)
	if e != nil || len(blocks.BlockItems) != 1 {
		return out, errors.New("source block receipt unavailable")
	}
	block := blocks.BlockItems[0]
	if block == nil || block.BlockHeight != height || block.Block == nil || block.Block.Header == nil || block.Block.Header.Height != height || block.Receipt == nil || !hashPayload(block.BlockId) || !bytes.Equal(block.BlockId, block.Block.Id) {
		return out, errors.New("source block or receipt binding invalid")
	}
	if block.Receipt.Height != height || !bytes.Equal(block.Receipt.Id, block.BlockId) {
		return out, errors.New("receipt block identity mismatch")
	}
	headerBytes, headerErr := canonical.Marshal(block.Block.Header)
	headerDigest := sha256.Sum256(headerBytes)
	if headerErr != nil || !bytes.Equal(headerDigest[:], block.BlockId[2:]) {
		return out, errors.New("source block header hash mismatch")
	}
	contract, _ := base58.Decode(r.source.Profile.Contract)
	matches := 0
	bridgeEvents := uint32(0)
	txMatches := 0
	receiptMatches := 0
	var transfer Transfer
	for _, transaction := range block.Block.Transactions {
		if transaction != nil && bytes.Equal(transaction.Id, tx) {
			txMatches++
		}
	}
	for _, receipt := range block.Receipt.TransactionReceipts {
		if receipt == nil || !bytes.Equal(receipt.Id, tx) {
			continue
		}
		receiptMatches++
		if receipt.Reverted {
			return out, errors.New("source transaction reverted")
		}
		for _, event := range receipt.Events {
			if event != nil && bytes.Equal(event.Source, contract) && event.Name == "bridge.tokens_locked_event" {
				bridgeEvents++
			}
			if event == nil || uint64(event.Sequence) != sequence {
				continue
			}
			// An event index must resolve uniquely, even when an unexpected emitter is returned.
			matches++
			if !bytes.Equal(event.Source, contract) || event.Name != "bridge.tokens_locked_event" {
				return out, errors.New("source event is not a bridge token lock")
			}
			var locked bridge.TokensLockedEvent
			if proto.Unmarshal(event.Data, &locked) != nil || len(locked.ProtoReflect().GetUnknown()) != 0 || locked.ChainId != r.destination.Profile.BridgeChainID {
				return out, errors.New("source event decoding or destination mismatch")
			}
			token, known := r.tokens[base58.Encode(locked.Token)]
			if !known {
				return out, errors.New("source token has no reviewed mapping")
			}
			timestamp := block.Block.Header.Timestamp
			if timestamp == 0 || timestamp > math.MaxUint64-r.lifetime {
				return out, errors.New("source time or expiration overflow")
			}
			transfer = Transfer{TransactionID: parts[0], OperationID: parts[1], Token: token, Recipient: locked.Recipient, Relayer: locked.Relayer, Amount: locked.Amount, Payment: locked.Payment, Metadata: locked.Metadata, Expiration: strconv.FormatUint(timestamp+r.lifetime, 10)}
		}
	}
	if txMatches != 1 || receiptMatches != 1 || matches != 1 {
		return out, errors.New("source operation is missing or ambiguous")
	}
	if _, e = TransferDigest(r.destination.Profile, transfer); e != nil {
		return out, e
	}
	var finalized struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if rpcRead(ctx, r.destination.RPC, "eth_getBlockByNumber", []interface{}{"finalized", false}, &finalized) != nil || !strings.HasPrefix(finalized.Hash, "0x") || !validHash(strings.TrimPrefix(finalized.Hash, "0x")) {
		return out, errors.New("EVM finalized block unavailable")
	}
	selector := map[string]interface{}{"blockHash": finalized.Hash, "requireCanonical": true}
	var code string
	if rpcRead(ctx, r.destination.RPC, "eth_getCode", []interface{}{r.destination.Profile.Contract, selector}, &code) != nil || !strings.HasPrefix(code, "0x") {
		return out, errors.New("EVM code unavailable")
	}
	codeBytes, e := hex.DecodeString(code[2:])
	if e != nil || len(codeBytes) == 0 || hex.EncodeToString(crypto.Keccak256(codeBytes)) != r.destination.Profile.CodeHash {
		return out, errors.New("EVM code differs from reviewed profile")
	}
	rawHash := crypto.Keccak256(tx, common.LeftPadBytes(new(big.Int).SetUint64(sequence).Bytes(), 32))
	statusKey := crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), rawHash)
	calldata := append(crypto.Keccak256([]byte("isTransferCompleted(bytes32)"))[:4], statusKey...)
	var result string
	if rpcRead(ctx, r.destination.RPC, "eth_call", []interface{}{map[string]string{"to": r.destination.Profile.Contract, "data": "0x" + hex.EncodeToString(calldata)}, selector}, &result) != nil {
		return out, errors.New("destination completion unavailable")
	}
	if result != "0x"+strings.Repeat("0", 64) && result != "0x"+strings.Repeat("0", 63)+"1" {
		return out, errors.New("invalid destination completion result")
	}
	if e = r.identities(ctx, k); e != nil {
		return out, e
	}
	out = TransferObservation{ID: id, SourceProfileDigest: r.source.Profile.Digest(), DestinationProfileDigest: r.destination.Profile.Digest(), ObservedAt: time.Now(), SourceBlockHash: hex.EncodeToString(block.BlockId[2:]), DestinationBlockHash: finalized.Hash[2:], SourceFinality: "finalized", DestinationFinality: "finalized", BridgeEventsInTransaction: bridgeEvents, Completed: strings.HasSuffix(result, "1"), Transfer: transfer}
	return out, nil
}
