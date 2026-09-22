package managed

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func TestEVMKoinosReaderFinalizedReceipt(t *testing.T) {
	for _, kind := range []string{"good", "completed", "network", "reverted", "unfinalized", "wrong-block", "missing-tx", "duplicate-tx", "wrong-code", "removed", "log-binding", "duplicate-log-index", "multiple-events", "indexed-event", "missing-event", "wrong-chain", "wrong-time", "overflow", "trailing-data", "unknown-token", "missing-completion", "stale-snapshot", "source-reorg", "finality-regresses", "nonzero-operation"} {
		t.Run(kind, func(t *testing.T) {
			vectors := transferVectors(t)
			source, destination := vectors[0].Profile, vectors[3].Profile
			for _, p := range []*operator.Profile{&source, &destination} {
				p.Reviewed = true
				p.CodeHash = strings.Repeat("a", 64)
				p.ReviewEvidence = "synthetic HTTP fixture"
			}
			source.CodeHash = hex.EncodeToString(crypto.Keccak256([]byte{0x60, 0}))
			snapshot, e := NewKoinosSnapshot(operator.Binding{Profile: destination, RPC: "http://127.0.0.1:1"}, "http://127.0.0.1:2")
			if e != nil {
				t.Fatal(e)
			}
			tx := "0x" + strings.Repeat("12", 32)
			hash := "0x" + strings.Repeat("f", 64)
			seconds := uint64(time.Now().Unix())
			eventABI, _ := abi.JSON(strings.NewReader(lockedEventABI))
			event := eventABI.Events["TokensLockedEvent"]
			amount := new(big.Int).SetUint64(1 << 63)
			if kind == "overflow" {
				amount.Lsh(big.NewInt(1), 64)
			}
			chain := destination.BridgeChainID
			if kind == "wrong-chain" {
				chain++
			}
			timestamp := seconds * 1000
			if kind == "wrong-time" {
				timestamp++
			}
			token := common.HexToAddress(source.Contract)
			if kind == "unknown-token" {
				token = common.HexToAddress("0x2222222222222222222222222222222222222222")
			}
			data, e := event.Inputs.Pack(token, token, amount, big.NewInt(0), destination.Contract, destination.Contract, "synthetic", new(big.Int).SetUint64(timestamp), chain)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "trailing-data" {
				data = append(data, 0)
			}
			log := evmReadLog{Address: source.Contract, Topics: []string{event.ID.Hex()}, Data: hexutil.Encode(data), BlockHash: hash, BlockNumber: "0x5", TransactionHash: tx, TransactionIndex: "0x0", LogIndex: "0x0"}
			if kind == "removed" {
				log.Removed = true
			}
			if kind == "log-binding" {
				log.TransactionHash = "0x" + strings.Repeat("a", 64)
			}
			if kind == "indexed-event" {
				log.Topics = append(log.Topics, hash)
			}
			receipt := evmReadReceipt{TransactionHash: tx, TransactionIndex: "0x0", BlockHash: hash, BlockNumber: "0x5", Status: "0x1", Logs: []evmReadLog{log}}
			if kind == "reverted" {
				receipt.Status = "0x0"
			}
			if kind == "missing-event" {
				receipt.Logs = nil
			}
			if kind == "multiple-events" || kind == "duplicate-log-index" {
				other := log
				if kind == "multiple-events" {
					other.LogIndex = "0x1"
				}
				receipt.Logs = append(receipt.Logs, other)
			}
			sourceReads, finalReads := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct {
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if json.NewDecoder(r.Body).Decode(&q) != nil {
					t.Error("request decoding")
					return
				}
				var result interface{}
				switch q.Method {
				case "eth_chainId":
					result = "0x7a69"
					if kind == "network" {
						result = "0x1"
					}
				case "eth_getTransactionReceipt":
					if len(q.Params) != 1 || string(q.Params[0]) != `"`+tx+`"` {
						t.Error("wrong transaction lookup")
					}
					result = receipt
				case "eth_getBlockByNumber":
					if len(q.Params) != 2 || string(q.Params[1]) != "false" {
						t.Error("invalid block request")
					}
					b := evmReadBlock{Hash: hash, Number: "0x5", Timestamp: hexutil.EncodeUint64(seconds), Transactions: []string{tx}}
					if string(q.Params[0]) == `"finalized"` {
						finalReads++
						b.Number = "0x6"
						if kind == "finality-regresses" && finalReads > 1 {
							b.Number = "0x4"
						}
						if kind == "unfinalized" {
							b.Number = "0x4"
						}
					} else {
						if string(q.Params[0]) != `"0x5"` {
							t.Error("wrong canonical height")
						}
						sourceReads++
						if kind == "wrong-block" || (kind == "source-reorg" && sourceReads > 1) {
							b.Hash = "0x" + strings.Repeat("a", 64)
						}
						if kind == "missing-tx" {
							b.Transactions = nil
						}
						if kind == "duplicate-tx" {
							b.Transactions = append(b.Transactions, tx)
						}
					}
					result = b
				case "eth_getCode":
					var selector struct {
						BlockHash        string `json:"blockHash"`
						RequireCanonical bool   `json:"requireCanonical"`
					}
					if len(q.Params) != 2 || json.Unmarshal(q.Params[1], &selector) != nil || selector.BlockHash != hash || !selector.RequireCanonical || string(q.Params[0]) != `"`+source.Contract+`"` {
						t.Error("unbound code read")
					}
					result = "0x6000"
					if kind == "wrong-code" {
						result = "0x6001"
					}
				default:
					t.Error("unexpected method", q.Method)
					w.WriteHeader(400)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
			}))
			defer server.Close()
			reader, e := NewEVMKoinosReader(operator.Binding{Profile: source, RPC: server.URL}, snapshot, destination.Contract, map[string]string{source.Contract: destination.Contract}, 60000)
			if e != nil {
				t.Fatal(e)
			}
			// Snapshot RPC semantics have their own two-server test suite. This seam tests
			// the receipt reader's consumption of typed snapshot evidence only.
			reader.readState = func(ctx context.Context, seed string, ids []string) (FinalKoinosState, error) {
				if seed != destination.Contract || len(ids) != 1 || ids[0] != tx[2:] {
					t.Error("wrong destination query")
				}
				state := FinalKoinosState{ProfileDigest: destination.Digest(), BlockHash: strings.Repeat("b", 64), ObservedAt: time.Now(), Completed: map[string]bool{tx[2:]: kind == "completed"}}
				if kind == "missing-completion" {
					state.Completed = nil
				}
				if kind == "stale-snapshot" {
					state.ObservedAt = time.Now().Add(-time.Minute)
				}
				return state, nil
			}
			id := tx[2:] + ":0"
			if kind == "nonzero-operation" {
				id = tx[2:] + ":1"
			}
			observation, e := reader.ReadTransfer(context.Background(), id)
			if kind == "good" || kind == "completed" {
				if e != nil {
					t.Fatal(e)
				}
				if observation.Completed != (kind == "completed") || observation.Transfer.Amount != "9223372036854775808" || observation.Transfer.Token != destination.Contract || observation.BridgeEventsInTransaction != 1 || observation.SourceBlockHash != hash[2:] || observation.SourceFinality != "finalized" || observation.DestinationFinality != "finalized" {
					t.Fatalf("wrong observation: %+v", observation)
				}
			} else if e == nil {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
}
