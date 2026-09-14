package streamer

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/koinos/koinos-proto-golang/koinos/protocol"
	"github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

func TestObservationStoresTransfersWithoutSigningOrBroadcast(t *testing.T) {
	var peerCalls int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&peerCalls, 1)
		http.Error(w, "must not contact peer", 500)
	}))
	defer peer.Close()
	evmAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	koinosAddr := base58.Encode([]byte{1, 2, 3, 4})
	validators := map[string]util.ValidatorConfig{"peer": {ApiUrl: peer.URL}}
	tokens := map[string]util.TokenConfig{evmAddr.Hex(): {KoinosAddress: koinosAddr}, koinosAddr: {EthereumAddress: evmAddr.Hex()}}
	transactions := store.NewTransactionsStore(store.NewMapBackend())
	transactions.EnableActivity("")
	eventABI, err := abi.JSON(strings.NewReader(`[{"type":"event","name":"TokensLockedEvent","inputs":[{"name":"from","type":"address"},{"name":"token","type":"address"},{"name":"amount","type":"uint256"},{"name":"payment","type":"uint256"},{"name":"relayer","type":"string"},{"name":"recipient","type":"string"},{"name":"metadata","type":"string"},{"name":"blocktime","type":"uint256"},{"name":"chain","type":"uint32"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	data, err := eventABI.Events["TokensLockedEvent"].Inputs.Pack(evmAddr, evmAddr, big.NewInt(50), big.NewInt(1), koinosAddr, koinosAddr, "", big.NewInt(1000), uint32(1))
	if err != nil {
		t.Fatal(err)
	}
	eventLog := types.Log{Data: data, TxHash: common.HexToHash("0x01"), BlockNumber: 9}
	for i := 0; i < 2; i++ {
		processEthereumTokensLockedEvent(nil, "", []byte{1}, tokens, transactions, 60000, validators, eventLog, eventABI)
	}
	tx, err := transactions.Get(eventLog.TxHash.Hex())
	if err != nil || tx == nil {
		t.Fatalf("missing observed EVM transfer: %v", err)
	}
	if len(tx.Signatures) != 0 || len(tx.Validators) != 0 || tx.Status != bridge_pb.TransactionStatus_gathering_signatures {
		t.Fatal("observation produced a signature")
	}
	payload, err := proto.Marshal(&bridge_pb.TokensLockedEvent{From: []byte{1}, Token: []byte{1, 2, 3, 4}, Amount: "50", Payment: "1", Recipient: evmAddr.Hex(), Relayer: evmAddr.Hex(), ChainId: 1})
	if err != nil {
		t.Fatal(err)
	}
	block := &block_store.BlockItem{BlockHeight: 9, Block: &protocol.Block{Header: &protocol.BlockHeader{Timestamp: 1000, Height: 9}}}
	receipt := &protocol.TransactionReceipt{Id: []byte{2}}
	event := &protocol.EventData{Data: payload, Sequence: 1}
	for i := 0; i < 2; i++ {
		processKoinosTokensLockedEvent(nil, "", nil, "", evmAddr, tokens, transactions, 60000, validators, block, receipt, event)
	}
	tx, err = transactions.Get("0x02-1")
	if err != nil || tx == nil {
		t.Fatalf("missing observed Koinos transfer: %v", err)
	}
	if len(tx.Signatures) != 0 || len(tx.Validators) != 0 {
		t.Fatal("observation produced a signature")
	}
	activity := transactions.Activity()
	if !activity.Complete || activity.NewRecords != 2 || activity.LocalSignatureChanges != 0 || activity.OtherSignatureChanges != 0 {
		t.Fatalf("replay inflated recorded activity or observation counted signatures: %+v", activity)
	}
	// Missing keys also stop direct renewal calls before event parsing or networking.
	processEthereumRequestNewSignaturesEvent(nil, "", nil, nil, nil, 0, nil, types.Log{}, abi.ABI{})
	processRequestNewSignaturesEvent(nil, nil, nil, nil, 0, nil, "", nil, "", common.Address{}, nil)
	if atomic.LoadInt32(&peerCalls) != 0 {
		t.Fatal("observation contacted a signature peer")
	}
}
func TestEthereumCheckpointsBeforeShutdownAndResumes(t *testing.T) {
	var mu sync.Mutex
	var ranges [][2]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		var result interface{}
		switch req.Method {
		case "eth_blockNumber":
			result = "0xc"
		case "eth_getLogs":
			var q map[string]string
			json.Unmarshal(req.Params[0], &q)
			mu.Lock()
			ranges = append(ranges, [2]string{q["fromBlock"], q["toBlock"]})
			mu.Unlock()
			result = []interface{}{}
		default:
			t.Errorf("unexpected RPC method %s", req.Method)
			http.Error(w, "disallowed", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer server.Close()
	metadata := store.NewMetadataStore(store.NewMapBackend())
	metadata.Put(&bridge_pb.Metadata{LastEthereumBlockParsed: 7, LastKoinosBlockParsed: 4})
	tx := store.NewTransactionsStore(store.NewMapBackend())
	run := func(start uint64) {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go StreamEthereumBlocks(&wg, ctx, metadata, start, server.URL, "0x1111111111111111111111111111111111111111", 2, nil, "", base58.Encode([]byte{1}), nil, tx, tx, 60000, nil, 0, 1, Options{ObserveOnly: true})
		deadline := time.Now().Add(3 * time.Second)
		for {
			m, err := metadata.Get()
			if err != nil {
				t.Fatal(err)
			}
			if m.LastEthereumBlockParsed == 12 {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				wg.Wait()
				t.Fatal("checkpoint never persisted while running")
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		wg.Wait()
	}
	run(7)
	m, _ := metadata.Get()
	if m.LastKoinosBlockParsed != 4 {
		t.Fatal("overwrote other chain checkpoint")
	}
	mu.Lock()
	before := len(ranges)
	mu.Unlock()
	run(12)
	mu.Lock()
	defer mu.Unlock()
	if len(ranges) != before {
		t.Fatal("replayed completed range after restart")
	}
	if len(ranges) == 0 || ranges[0][0] != "0x8" {
		t.Fatalf("wrong resumed range: %v", ranges)
	}
}
func TestRejectIncompleteOrDisorderedKoinosBatch(t *testing.T) {
	block := func(h uint64) *block_store.BlockItem {
		return &block_store.BlockItem{BlockHeight: h, Block: &protocol.Block{Header: &protocol.BlockHeader{Height: h}}, Receipt: &protocol.BlockReceipt{}}
	}
	valid := &block_store.GetBlocksByHeightResponse{BlockItems: []*block_store.BlockItem{block(8), block(9)}}
	if err := validateBlockBatch(valid, 8, 2); err != nil {
		t.Fatal(err)
	}
	for i, b := range []*block_store.GetBlocksByHeightResponse{nil, {}, {BlockItems: []*block_store.BlockItem{block(8)}}, {BlockItems: []*block_store.BlockItem{block(9), block(8)}}, {BlockItems: []*block_store.BlockItem{nil, block(9)}}} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if validateBlockBatch(b, 8, 2) == nil {
				t.Fatal("invalid batch accepted")
			}
		})
	}
}

func TestRejectUnsafeConfirmedLogBatch(t *testing.T) {
	address := common.HexToAddress("0x1111111111111111111111111111111111111111")
	valid := types.Log{Address: address, BlockNumber: 8, Index: 1, Topics: []common.Hash{common.HexToHash("0x01")}}
	if err := validateEthereumLogs([]types.Log{valid}, 8, 9, address); err != nil {
		t.Fatal(err)
	}
	cases := []types.Log{valid, valid, valid, valid, valid}
	cases[0].Removed = true
	cases[1].Topics = nil
	cases[2].Address = common.Address{}
	cases[3].BlockNumber = 7
	cases[4].BlockNumber = 10
	for _, entry := range cases {
		if validateEthereumLogs([]types.Log{entry}, 8, 9, address) == nil {
			t.Fatal("unsafe log accepted")
		}
	}
	if validateEthereumLogs([]types.Log{valid, valid}, 8, 9, address) == nil {
		t.Fatal("duplicate log accepted")
	}
}
