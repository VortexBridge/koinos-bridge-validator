package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	bridge "github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	kjson "github.com/koinos/koinos-proto-golang/encoding/json"
	"github.com/koinos/koinos-proto-golang/koinos"
	"github.com/koinos/koinos-proto-golang/koinos/canonical"
	"github.com/koinos/koinos-proto-golang/koinos/protocol"
	"github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
	chain "github.com/koinos/koinos-proto-golang/koinos/rpc/chain"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

func TestKoinosEVMReaderUsesIrreversibleReceiptsAndPinnedDestination(t *testing.T) {
	for _, kind := range []string{"good", "completed", "source-network", "not-irreversible", "reverted", "wrong-destination", "wrong-emitter", "unknown-token", "duplicate-event", "missing-transaction", "receipt-identity", "header-hash", "wrong-code", "bad-status", "missing-finality"} {
		t.Run(kind, func(t *testing.T) {
			vectors := transferVectors(t)
			source, destination := vectors[3].Profile, vectors[0].Profile
			for _, p := range []*operator.Profile{&source, &destination} {
				p.Reviewed = true
				p.CodeHash = strings.Repeat("a", 64)
				p.ReviewEvidence = "isolated synthetic HTTP fixture"
			}
			destination.CodeHash = hex.EncodeToString(crypto.Keccak256([]byte{0x60, 0x00}))
			network, _ := base64.URLEncoding.DecodeString(source.NetworkID)
			sourceAddress, _ := base58.Decode(source.Contract)
			tx := bytes.Repeat([]byte{0x12}, 32)
			id := hex.EncodeToString(tx) + ":1"
			locked := &bridge.TokensLockedEvent{Token: sourceAddress, Recipient: destination.Contract, Relayer: destination.Contract, Amount: "9223372036854775808", Payment: "0", Metadata: "RPC synthetic", ChainId: destination.BridgeChainID}
			if kind == "wrong-destination" {
				locked.ChainId++
			}
			if kind == "unknown-token" {
				locked.Token = bytes.Repeat([]byte{1}, 25)
			}
			eventBytes, _ := proto.Marshal(locked)
			event := &protocol.EventData{Sequence: 1, Source: sourceAddress, Name: "bridge.tokens_locked_event", Data: eventBytes}
			if kind == "wrong-emitter" {
				event.Source = []byte{1}
			}
			header := &protocol.BlockHeader{Height: 5, Timestamp: uint64(time.Now().UnixMilli())}
			headerBytes, _ := canonical.Marshal(header)
			headerHash := sha256.Sum256(headerBytes)
			blockID := append([]byte{0x12, 0x20}, headerHash[:]...)
			receipt := &protocol.TransactionReceipt{Id: tx, Events: []*protocol.EventData{event}}
			if kind == "reverted" {
				receipt.Reverted = true
			}
			if kind == "duplicate-event" {
				receipt.Events = append(receipt.Events, event)
			}
			block := &block_store.BlockItem{BlockId: blockID, BlockHeight: 5, Block: &protocol.Block{Id: blockID, Header: header, Transactions: []*protocol.Transaction{{Id: tx}}}, Receipt: &protocol.BlockReceipt{Id: blockID, Height: 5, TransactionReceipts: []*protocol.TransactionReceipt{receipt}}}
			if kind == "missing-transaction" {
				block.Block.Transactions = nil
			}
			if kind == "receipt-identity" {
				block.Receipt.Id = []byte{1}
			}
			if kind == "header-hash" {
				block.Block.Header.Timestamp++
			}
			kServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct {
					Method string          `json:"method"`
					Params json.RawMessage `json:"params"`
				}
				if json.NewDecoder(r.Body).Decode(&q) != nil {
					t.Error("request decode")
					return
				}
				var response proto.Message
				switch q.Method {
				case "chain.get_chain_id":
					n := append([]byte{}, network...)
					if kind == "source-network" {
						n[len(n)-1] ^= 1
					}
					response = &chain.GetChainIdResponse{ChainId: n}
				case "chain.get_head_info":
					lib := uint64(5)
					if kind == "not-irreversible" {
						lib = 4
					}
					response = &chain.GetHeadInfoResponse{HeadTopology: &koinos.BlockTopology{Id: blockID, Height: 5}, LastIrreversibleBlock: lib}
				case "block_store.get_blocks_by_height":
					var p block_store.GetBlocksByHeightRequest
					if kjson.Unmarshal(q.Params, &p) != nil || p.AncestorStartHeight != 5 || p.NumBlocks != 1 || !p.ReturnBlock || !p.ReturnReceipt || !bytes.Equal(p.HeadBlockId, blockID) {
						t.Error("unanchored block request")
					}
					response = &block_store.GetBlocksByHeightResponse{BlockItems: []*block_store.BlockItem{block}}
				default:
					t.Errorf("unexpected Koinos method %s", q.Method)
					w.WriteHeader(400)
					return
				}
				raw, e := kjson.Marshal(response)
				if e != nil {
					t.Error(e)
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": json.RawMessage(raw)})
			}))
			defer kServer.Close()
			pinnedHash := "0x" + strings.Repeat("f", 64)
			eServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct {
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if json.NewDecoder(r.Body).Decode(&q) != nil {
					t.Error("request decode")
					return
				}
				var result interface{}
				switch q.Method {
				case "eth_chainId":
					result = "0x7a69"
				case "eth_getBlockByNumber":
					if len(q.Params) != 2 || string(q.Params[0]) != `"finalized"` {
						t.Error("not finalized")
					}
					if kind == "missing-finality" {
						result = nil
					} else {
						result = map[string]string{"number": "0x10", "hash": pinnedHash}
					}
				case "eth_getCode", "eth_call":
					var selector struct {
						BlockHash        string `json:"blockHash"`
						RequireCanonical bool   `json:"requireCanonical"`
					}
					if len(q.Params) != 2 || json.Unmarshal(q.Params[1], &selector) != nil || selector.BlockHash != pinnedHash || !selector.RequireCanonical {
						t.Error("destination not hash-pinned")
					}
					if q.Method == "eth_getCode" {
						result = "0x6000"
						if kind == "wrong-code" {
							result = "0x6001"
						}
					} else {
						var call map[string]string
						_ = json.Unmarshal(q.Params[0], &call)
						// Independently computed using ethers packed(bytes,uint256) + personal hash.
						if call["to"] != destination.Contract || call["data"] != "0xaa4efa5bdc9b194573bc45936ffccb335a0235dc5a11223aaf853baffb4219df3fb88e19" {
							t.Error("wrong completion key")
						}
						result = "0x" + strings.Repeat("0", 64)
						if kind == "completed" {
							result = "0x" + strings.Repeat("0", 63) + "1"
						}
						if kind == "bad-status" {
							result = "0x01"
						}
					}
				default:
					t.Errorf("unexpected EVM method %s", q.Method)
					w.WriteHeader(400)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
			}))
			defer eServer.Close()
			reader, e := NewKoinosEVMReader(operator.Binding{Profile: source, RPC: kServer.URL}, operator.Binding{Profile: destination, RPC: eServer.URL}, map[string]string{source.Contract: destination.Contract}, 60000, func(context.Context, string) (uint64, error) { return 5, nil })
			if e != nil {
				t.Fatal(e)
			}
			observation, e := reader.ReadTransfer(context.Background(), id)
			if kind == "good" || kind == "completed" {
				if e != nil || observation.Completed != (kind == "completed") || observation.Transfer.Amount != "9223372036854775808" || observation.SourceFinality != "finalized" {
					t.Fatal("valid read failed", e)
				}
			} else if e == nil {
				t.Fatal("invalid source/destination evidence accepted")
			}
		})
	}
}
