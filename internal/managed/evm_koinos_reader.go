package managed

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

const lockedEventABI = `[{"type":"event","name":"TokensLockedEvent","inputs":[{"name":"from","type":"address"},{"name":"token","type":"address"},{"name":"amount","type":"uint256"},{"name":"payment","type":"uint256"},{"name":"relayer","type":"string"},{"name":"recipient","type":"string"},{"name":"metadata","type":"string"},{"name":"blocktime","type":"uint256"},{"name":"chain","type":"uint32"}]}]`

type EVMKoinosReader struct {
	source   operator.Binding
	snapshot *KoinosSnapshot
	seed     string
	tokens   map[string]string
	lifetime uint64
	// Test seam is private; production construction always uses snapshot.Read.
	readState func(context.Context, string, []string) (FinalKoinosState, error)
}

func NewEVMKoinosReader(source operator.Binding, snapshot *KoinosSnapshot, seed string, tokens map[string]string, lifetime uint64) (*EVMKoinosReader, error) {
	if source.Validate() != nil || source.Profile.Family != "evm" || source.Profile.Environment != "local" || !source.Profile.Reviewed || snapshot == nil || lifetime == 0 || lifetime > 86400000 || len(tokens) == 0 || len(tokens) > 128 {
		return nil, errors.New("reviewed local EVM route, Koinos snapshot and bounded transfer policy required")
	}
	if _, e := transferAddress(snapshot.live.Profile, seed, false); e != nil {
		return nil, e
	}
	copied := map[string]string{}
	for from, to := range tokens {
		if _, e := transferAddress(source.Profile, from, false); e != nil {
			return nil, e
		}
		if _, e := transferAddress(snapshot.live.Profile, to, false); e != nil {
			return nil, e
		}
		key := strings.ToLower(from)
		if _, exists := copied[key]; exists {
			return nil, errors.New("duplicate source token")
		}
		copied[key] = to
	}
	return &EVMKoinosReader{source, snapshot, seed, copied, lifetime, snapshot.Read}, nil
}

type evmReadBlock struct {
	Hash         string   `json:"hash"`
	Number       string   `json:"number"`
	Timestamp    string   `json:"timestamp"`
	Transactions []string `json:"transactions"`
}
type evmReadLog struct {
	Address          string   `json:"address"`
	Topics           []string `json:"topics"`
	Data             string   `json:"data"`
	BlockHash        string   `json:"blockHash"`
	BlockNumber      string   `json:"blockNumber"`
	TransactionHash  string   `json:"transactionHash"`
	TransactionIndex string   `json:"transactionIndex"`
	LogIndex         string   `json:"logIndex"`
	Removed          bool     `json:"removed"`
}
type evmReadReceipt struct {
	TransactionHash  string       `json:"transactionHash"`
	TransactionIndex string       `json:"transactionIndex"`
	BlockHash        string       `json:"blockHash"`
	BlockNumber      string       `json:"blockNumber"`
	Status           string       `json:"status"`
	Logs             []evmReadLog `json:"logs"`
}

func evmHash(s string) bool { return len(s) == 66 && strings.HasPrefix(s, "0x") && validHash(s[2:]) }
func (r *EVMKoinosReader) identity(ctx context.Context) error {
	var id string
	if rpcRead(ctx, r.source.RPC, "eth_chainId", []interface{}{}, &id) != nil {
		return errors.New("EVM identity unavailable")
	}
	n, e := hexutil.DecodeBig(id)
	if e != nil || n.String() != r.source.Profile.NetworkID {
		return errors.New("EVM network mismatch")
	}
	return nil
}
func (r *EVMKoinosReader) ReadTransfer(ctx context.Context, id string) (TransferObservation, error) {
	var out TransferObservation
	parts := strings.Split(id, ":")
	if len(parts) != 2 || parts[1] != "0" || !validHash(parts[0]) {
		return out, errors.New("Koinos destination requires transaction hash and operation zero")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if e := r.identity(ctx); e != nil {
		return out, e
	}
	tx := "0x" + parts[0]
	var receipt evmReadReceipt
	if rpcRead(ctx, r.source.RPC, "eth_getTransactionReceipt", []interface{}{tx}, &receipt) != nil || receipt.TransactionHash != tx || receipt.Status != "0x1" || !evmHash(receipt.BlockHash) {
		return out, errors.New("successful source receipt unavailable")
	}
	height, e := hexutil.DecodeUint64(receipt.BlockNumber)
	index, ie := hexutil.DecodeUint64(receipt.TransactionIndex)
	if e != nil || ie != nil || height == 0 {
		return out, errors.New("invalid source receipt position")
	}
	var final, block evmReadBlock
	if rpcRead(ctx, r.source.RPC, "eth_getBlockByNumber", []interface{}{"finalized", false}, &final) != nil || !evmHash(final.Hash) {
		return out, errors.New("EVM finality unavailable")
	}
	finalHeight, e := hexutil.DecodeUint64(final.Number)
	if e != nil || height > finalHeight {
		return out, errors.New("source receipt is not finalized")
	}
	if rpcRead(ctx, r.source.RPC, "eth_getBlockByNumber", []interface{}{receipt.BlockNumber, false}, &block) != nil || block.Hash != receipt.BlockHash || block.Number != receipt.BlockNumber || (height == finalHeight && block.Hash != final.Hash) || index >= uint64(len(block.Transactions)) || block.Transactions[index] != tx {
		return out, errors.New("receipt does not match canonical source block")
	}
	matches := 0
	for _, candidate := range block.Transactions {
		if candidate == tx {
			matches++
		}
	}
	if matches != 1 {
		return out, errors.New("ambiguous source transaction inclusion")
	}
	seconds, e := hexutil.DecodeUint64(block.Timestamp)
	if e != nil || seconds == 0 || seconds > (math.MaxUint64-r.lifetime)/1000 {
		return out, errors.New("invalid source block time")
	}
	var code string
	selector := map[string]interface{}{"blockHash": block.Hash, "requireCanonical": true}
	if rpcRead(ctx, r.source.RPC, "eth_getCode", []interface{}{r.source.Profile.Contract, selector}, &code) != nil {
		return out, errors.New("source code unavailable")
	}
	codeBytes, e := hexutil.Decode(code)
	if e != nil || len(codeBytes) == 0 || hex.EncodeToString(crypto.Keccak256(codeBytes)) != r.source.Profile.CodeHash {
		return out, errors.New("source code differs from reviewed build")
	}
	eventABI, _ := abi.JSON(strings.NewReader(lockedEventABI))
	event := eventABI.Events["TokensLockedEvent"]
	var selected *evmReadLog
	seen := map[uint64]bool{}
	for i := range receipt.Logs {
		log := &receipt.Logs[i]
		li, le := hexutil.DecodeUint64(log.LogIndex)
		if le != nil || seen[li] || log.Removed || log.BlockHash != block.Hash || log.BlockNumber != receipt.BlockNumber || log.TransactionHash != tx || log.TransactionIndex != receipt.TransactionIndex {
			return out, errors.New("receipt log binding invalid")
		}
		seen[li] = true
		if !strings.EqualFold(log.Address, r.source.Profile.Contract) || len(log.Topics) == 0 || log.Topics[0] != event.ID.Hex() {
			continue
		}
		if selected != nil || len(log.Topics) != 1 {
			return out, errors.New("ambiguous bridge events in transaction")
		}
		selected = log
	}
	if selected == nil {
		return out, errors.New("bridge event missing")
	}
	data, e := hexutil.Decode(selected.Data)
	if e != nil {
		return out, errors.New("invalid event encoding")
	}
	values, e := event.Inputs.Unpack(data)
	if e != nil {
		return out, errors.New("invalid event ABI")
	}
	canonical, e := event.Inputs.Pack(values...)
	if e != nil || !bytes.Equal(canonical, data) {
		return out, errors.New("noncanonical event ABI")
	}
	amount, payment, blocktime := values[2].(*big.Int), values[3].(*big.Int), values[7].(*big.Int)
	if !amount.IsUint64() || !payment.IsUint64() || !blocktime.IsUint64() || blocktime.Uint64() != seconds*1000 || values[8].(uint32) != r.snapshot.live.Profile.BridgeChainID {
		return out, errors.New("event range, time or destination mismatch")
	}
	token, ok := r.tokens[strings.ToLower(values[1].(common.Address).Hex())]
	if !ok {
		return out, errors.New("source token not reviewed")
	}
	transfer := Transfer{TransactionID: parts[0], OperationID: "0", Token: token, Recipient: values[5].(string), Relayer: values[4].(string), Amount: amount.String(), Payment: payment.String(), Metadata: values[6].(string), Expiration: strconv.FormatUint(seconds*1000+r.lifetime, 10)}
	if _, e = TransferDigest(r.snapshot.live.Profile, transfer); e != nil {
		return out, e
	}
	state, e := r.readState(ctx, r.seed, []string{parts[0]})
	done, present := state.Completed[parts[0]]
	if e != nil || !present || state.ProfileDigest != r.snapshot.live.Profile.Digest() || !validHash(state.BlockHash) || state.ObservedAt.After(time.Now()) || time.Since(state.ObservedAt) > 15*time.Second {
		return out, errors.New("irreversible destination status unavailable")
	}
	// Recheck canonical inclusion after the potentially slower replica read.
	var again evmReadBlock
	if rpcRead(ctx, r.source.RPC, "eth_getBlockByNumber", []interface{}{receipt.BlockNumber, false}, &again) != nil || again.Hash != block.Hash || again.Number != block.Number {
		return out, errors.New("source canonical block changed")
	}
	var finalAfter evmReadBlock
	if rpcRead(ctx, r.source.RPC, "eth_getBlockByNumber", []interface{}{"finalized", false}, &finalAfter) != nil || !evmHash(finalAfter.Hash) {
		return out, errors.New("source finality unavailable after read")
	}
	afterHeight, err := hexutil.DecodeUint64(finalAfter.Number)
	if err != nil || afterHeight < finalHeight || (afterHeight == finalHeight && finalAfter.Hash != final.Hash) {
		return out, errors.New("source finality regressed or changed")
	}
	if e = r.identity(ctx); e != nil {
		return out, e
	}
	return TransferObservation{ID: id, SourceProfileDigest: r.source.Profile.Digest(), DestinationProfileDigest: r.snapshot.live.Profile.Digest(), ObservedAt: time.Now(), SourceBlockHash: block.Hash[2:], DestinationBlockHash: state.BlockHash, SourceFinality: "finalized", DestinationFinality: "finalized", BridgeEventsInTransaction: 1, Completed: done, Transfer: transfer}, nil
}
