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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func TestEVMSnapshotPinnedMembershipAndRetirement(t *testing.T) {
	for _, kind := range []string{"good", "paused", "network", "network-changed", "missing-finality", "code", "chain", "bad-pause", "empty-members", "huge-count", "duplicate-member", "address-padding", "member-flag-missing", "retired-flag-active", "bad-boolean", "short-word", "reorg", "finality-regresses"} {
		t.Run(kind, func(t *testing.T) {
			p := transferVectors(t)[0].Profile
			p.Reviewed = true
			p.ReviewEvidence = "synthetic snapshot fixture"
			p.CodeHash = hex.EncodeToString(crypto.Keccak256([]byte{0x60, 0}))
			hash := "0x" + strings.Repeat("f", 64)
			addresses := []string{"0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"}
			retired := "0x4444444444444444444444444444444444444444"
			chains, finals := 0, 0
			probed := map[string]bool{}
			selector := func(signature string) string { return hexutil.Encode(crypto.Keccak256([]byte(signature))[:4]) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
					chains++
					result = "0x7a69"
					if kind == "network" || (kind == "network-changed" && chains > 1) {
						result = "0x1"
					}
				case "eth_getBlockByNumber":
					b := evmReadBlock{Number: "0x5", Hash: hash}
					if len(q.Params) != 2 || string(q.Params[1]) != "false" {
						t.Error("invalid block query")
					}
					if string(q.Params[0]) == `"finalized"` {
						finals++
						if kind == "finality-regresses" && finals > 1 {
							b.Number = "0x4"
						}
					} else {
						if string(q.Params[0]) != `"0x5"` {
							t.Error("wrong anchor")
						}
						if kind == "reorg" {
							b.Hash = "0x" + strings.Repeat("a", 64)
						}
					}
					result = b
					if kind == "missing-finality" {
						result = nil
					}
				case "eth_getCode", "eth_call":
					var anchor struct {
						BlockHash        string `json:"blockHash"`
						RequireCanonical bool   `json:"requireCanonical"`
					}
					if len(q.Params) != 2 || json.Unmarshal(q.Params[1], &anchor) != nil || anchor.BlockHash != hash || !anchor.RequireCanonical {
						t.Error("state not hash pinned")
					}
					if q.Method == "eth_getCode" {
						result = "0x6000"
						if kind == "code" {
							result = "0x6001"
						}
						break
					}
					var call map[string]string
					if json.Unmarshal(q.Params[0], &call) != nil || call["to"] != p.Contract {
						t.Error("wrong contract call")
					}
					data := call["data"]
					value := big.NewInt(0)
					switch {
					case data == selector("chainId()"):
						value.SetUint64(uint64(p.BridgeChainID))
						if kind == "chain" {
							value.Add(value, big.NewInt(1))
						}
					case data == selector("nonce()"):
						value.Lsh(big.NewInt(1), 200)
					case data == selector("paused()"):
						if kind == "paused" {
							value.SetInt64(1)
						}
						if kind == "bad-pause" {
							value.SetInt64(2)
						}
					case data == selector("getValidatorsLength()"):
						value.SetInt64(3)
						if kind == "empty-members" {
							value.SetInt64(0)
						}
						if kind == "huge-count" {
							value.SetInt64(257)
						}
					case strings.HasPrefix(data, selector("validators(uint256)")):
						arg, e := hexutil.Decode("0x" + data[10:])
						if e != nil || len(arg) != 32 {
							t.Error("bad index arg")
							return
						}
						index := new(big.Int).SetBytes(arg).Uint64()
						if index > 2 {
							t.Error("unexpected index")
							return
						}
						if kind == "duplicate-member" {
							index = 0
						}
						value.SetBytes(common.HexToAddress(addresses[index]).Bytes())
						if kind == "address-padding" {
							value.SetBit(value, 255, 1)
						}
					case strings.HasPrefix(data, selector("isValidator(address)")):
						arg, e := hexutil.Decode("0x" + data[10:])
						if e != nil || len(arg) != 32 {
							t.Error("bad identity arg")
							return
						}
						address := common.BytesToAddress(arg[12:]).Hex()
						probed[address] = true
						for _, member := range addresses {
							if address == member {
								value.SetInt64(1)
							}
						}
						if kind == "member-flag-missing" {
							value.SetInt64(0)
						}
						if kind == "retired-flag-active" && address == retired {
							value.SetInt64(1)
						}
						if kind == "bad-boolean" {
							value.SetInt64(2)
						}
					default:
						t.Error("unexpected getter", data)
						w.WriteHeader(400)
						return
					}
					result = hexutil.Encode(value.FillBytes(make([]byte, 32)))
					if kind == "short-word" {
						result = "0x01"
					}
				default:
					t.Error("unexpected method", q.Method)
					w.WriteHeader(400)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
			}))
			defer server.Close()
			snapshot, e := NewEVMSnapshot(operator.Binding{Profile: p, RPC: server.URL})
			if e != nil {
				t.Fatal(e)
			}
			state, e := snapshot.Read(context.Background(), []string{addresses[0], retired})
			if kind == "good" || kind == "paused" {
				if e != nil {
					t.Fatal(e)
				}
				expectedNonce := new(big.Int).Lsh(big.NewInt(1), 200).String()
				if state.Height != 5 || state.BlockHash != hash[2:] || state.ProfileDigest != p.Digest() || state.CodeHash != p.CodeHash || state.Nonce != expectedNonce || len(state.Validators) != 3 || len(state.Membership) != 4 || state.Membership[retired] || !probed[retired] || state.Paused != (kind == "paused") {
					t.Fatalf("bad snapshot %+v", state)
				}
				for _, member := range addresses {
					if !state.Membership[member] || !probed[member] {
						t.Fatal("member not verified")
					}
				}
			} else if e == nil {
				t.Fatal("unsafe state accepted")
			}
		})
	}
}
