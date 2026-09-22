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

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	kjson "github.com/koinos/koinos-proto-golang/encoding/json"
	"github.com/koinos/koinos-proto-golang/koinos"
	"github.com/koinos/koinos-proto-golang/koinos/canonical"
	sys "github.com/koinos/koinos-proto-golang/koinos/chain"
	"github.com/koinos/koinos-proto-golang/koinos/protocol"
	"github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
	chain "github.com/koinos/koinos-proto-golang/koinos/rpc/chain"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

func TestKoinosSnapshotRequiresStableIrreversibleReplica(t *testing.T) {
	cases := []string{"good", "pause-absent", "three-members", "membership-order", "membership-incomplete", "paused", "completed", "replica-ahead", "replica-behind", "replica-root", "replica-id", "header", "live-network", "replica-network", "network-changed", "code", "authority", "authority-wire", "uninitialized", "bridge-id", "member-count", "seed-missing", "duplicate-member", "status-wire", "status-value", "pause-wire", "replica-moves", "lib-advances", "anchor-changes"}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			p := transferVectors(t)[3].Profile
			p.Reviewed = true
			p.CodeHash = strings.Repeat("a", 64)
			p.ReviewEvidence = "synthetic replica fixture"
			network, _ := base64.URLEncoding.DecodeString(p.NetworkID)
			member, _ := base58.Decode(p.Contract)
			seed := member
			var three [][]byte
			if kind == "three-members" || kind == "membership-order" || kind == "membership-incomplete" {
				for i := byte(1); i <= 3; i++ {
					body := append([]byte{0}, bytes.Repeat([]byte{i}, 20)...)
					first := sha256.Sum256(body)
					check := sha256.Sum256(first[:])
					three = append(three, append(body, check[:4]...))
				}
				seed = three[1]
			}
			header := &protocol.BlockHeader{Height: 5, Timestamp: 1234}
			raw, _ := canonical.Marshal(header)
			hash := sha256.Sum256(raw)
			blockID := append([]byte{0x12, 0x20}, hash[:]...)
			root := append([]byte{0x12, 0x20}, bytes.Repeat([]byte{0x42}, 32)...)
			item := &block_store.BlockItem{BlockId: blockID, BlockHeight: 5, Block: &protocol.Block{Id: blockID, Header: header}, Receipt: &protocol.BlockReceipt{Id: blockID, Height: 5, StateMerkleRoot: root}}
			if kind == "header" {
				header.Timestamp++
			}
			makeServer := func(replica bool) *httptest.Server {
				heads, chains, blocks := 0, 0, 0
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var q struct {
						Method string          `json:"method"`
						Params json.RawMessage `json:"params"`
					}
					if json.NewDecoder(r.Body).Decode(&q) != nil {
						t.Error("request decoding")
						w.WriteHeader(400)
						return
					}
					var response proto.Message
					var result interface{}
					switch q.Method {
					case "chain.get_chain_id":
						chains++
						n := append([]byte{}, network...)
						if (kind == "live-network" && !replica) || (kind == "replica-network" && replica) || (kind == "network-changed" && chains > 1) {
							n[len(n)-1] ^= 1
						}
						response = &chain.GetChainIdResponse{ChainId: n}
					case "chain.get_head_info":
						heads++
						height := uint64(5)
						lib := uint64(5)
						id := append([]byte{}, blockID...)
						state := append([]byte{}, root...)
						if !replica {
							height = 8
						}
						if replica && kind == "replica-ahead" {
							height++
						}
						if replica && kind == "replica-behind" {
							height--
						}
						if replica && kind == "replica-root" {
							state[len(state)-1] ^= 1
						}
						if replica && kind == "replica-id" {
							id[len(id)-1] ^= 1
						}
						if replica && kind == "replica-moves" && heads > 1 {
							height++
						}
						if !replica && kind == "lib-advances" && heads > 1 {
							lib++
						}
						response = &chain.GetHeadInfoResponse{HeadTopology: &koinos.BlockTopology{Id: id, Height: height}, LastIrreversibleBlock: lib, HeadStateMerkleRoot: state}
					case "block_store.get_blocks_by_height":
						if replica {
							t.Error("anchor fetched from replica")
						}
						var args block_store.GetBlocksByHeightRequest
						if kjson.Unmarshal(q.Params, &args) != nil || args.AncestorStartHeight != 5 || args.NumBlocks != 1 || !args.ReturnReceipt || !args.ReturnBlock || !bytes.Equal(args.HeadBlockId, blockID) {
							t.Error("unanchored request")
						}
						blocks++
						b := proto.Clone(item).(*block_store.BlockItem)
						if kind == "anchor-changes" && blocks > 1 {
							b.BlockId[len(b.BlockId)-1] ^= 1
						}
						response = &block_store.GetBlocksByHeightResponse{BlockItems: []*block_store.BlockItem{b}}
					case "chain.read_contract", "chain.invoke_system_call":
						if !replica {
							t.Error("state read from live head")
						}
						var args struct {
							Name     string `json:"name"`
							Entry    uint32 `json:"entry_point"`
							Contract string `json:"contract_id"`
							Args     string `json:"args"`
							Caller   *struct {
								Address   string `json:"caller"`
								Privilege string `json:"caller_privilege"`
							} `json:"caller_data"`
						}
						if json.Unmarshal(q.Params, &args) != nil {
							t.Error("bad args")
						}
						data, e := base64.URLEncoding.DecodeString(args.Args)
						if e != nil {
							t.Error(e)
						}
						var output []byte
						if q.Method == "chain.invoke_system_call" {
							var lookup sys.GetObjectArguments
							if args.Name != "get_object" || proto.Unmarshal(data, &lookup) != nil || lookup.Space == nil {
								t.Fatal("invalid system lookup")
							}
							if lookup.Space.System {
								if args.Caller != nil {
									t.Error("kernel lookup must use default context")
								}
								expected, _ := proto.Marshal(&sys.GetObjectArguments{Space: &sys.ObjectSpace{System: true, Id: 3}, Key: member})
								if !bytes.Equal(data, expected) {
									t.Error("wrong contract metadata request")
								}
								code, _ := hex.DecodeString(p.CodeHash)
								if kind == "code" {
									code[0] ^= 1
								}
								meta := wireBytes(nil, 1, append([]byte{0x12, 0x20}, code...))
								if kind == "authority" {
									meta = wireUInt(meta, 3, 1)
								}
								if kind == "authority-wire" {
									meta = wireBytes(meta, 3, []byte{1})
								}
								output, _ = proto.Marshal(&sys.GetObjectResult{Value: &sys.DatabaseObject{Exists: true, Value: meta}})
							} else {
								var a sys.GetObjectArguments
								if proto.Unmarshal(data, &a) != nil || a.Space == nil || a.Space.System || a.Space.Id != 100002 || !bytes.Equal(a.Space.Zone, member) || len(a.Key) != 0 {
									t.Error("wrong pause storage lookup")
								}
								if args.Caller == nil || args.Caller.Address != p.Contract || args.Caller.Privilege != "user_mode" {
									t.Error("pause lookup requires contract user context")
								}
								object := &sys.GetObjectResult{Value: &sys.DatabaseObject{Exists: kind == "paused"}}
								if kind == "pause-wire" || kind == "pause-absent" {
									object.Value = nil
								}
								output, _ = proto.Marshal(object)
								if kind == "pause-wire" {
									output = []byte{0xff}
								}
							}
							result = map[string]string{"value": base64.URLEncoding.EncodeToString(output)}
						} else {
							if args.Contract != p.Contract {
								t.Error("wrong read contract")
							}
							entry := func(name string) uint32 {
								h := sha256.Sum256([]byte(name))
								return uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
							}
							switch args.Entry {
							case entry("get_metadata"):
								initialized := uint64(1)
								chainID := uint64(p.BridgeChainID)
								count := uint64(1)
								if len(three) > 0 {
									count = 3
								}
								if kind == "uninitialized" {
									initialized = 0
								}
								if kind == "bridge-id" {
									chainID++
								}
								if kind == "member-count" {
									count = 3
								}
								output = wireUInt(wireUInt(wireUInt(wireUInt(nil, 1, initialized), 2, 7), 3, chainID), 4, count)
							case entry("get_validators"):
								fields, e := snapshotWire(data)
								if e != nil || len(fields.data[1]) != 1 || !bytes.Equal(fields.data[1][0], seed) || fields.ints[2] == 0 {
									t.Error("missing membership seed/limit")
								}
								output = wireBytes(nil, 1, seed)
								if len(three) > 0 {
									next := three[2]
									if fields.ints[3] == 1 {
										next = three[0]
									}
									if kind == "membership-order" {
										next = seed
									}
									if kind != "membership-incomplete" {
										output = wireBytes(output, 1, next)
									}
								}
								if kind == "seed-missing" {
									output = nil
								}
								if kind == "duplicate-member" {
									output = wireBytes(output, 1, member)
								}
							case entry("get_transfer_status"):
								if !bytes.Equal(data, wireBytes(nil, 1, bytes.Repeat([]byte{0x12}, 32))) {
									t.Error("wrong transfer status key")
								}
								if kind == "completed" {
									output = wireUInt(nil, 1, 1)
								}
								if kind == "status-value" {
									output = wireUInt(nil, 1, 2)
								}
								if kind == "status-wire" {
									output = wireUInt(nil, 2, 1)
								}
							default:
								t.Error("unexpected read entry", args.Entry)
							}
							result = map[string]string{"result": base64.URLEncoding.EncodeToString(output)}
						}
					default:
						t.Error("unexpected method", q.Method)
						w.WriteHeader(400)
						return
					}
					if response != nil {
						b, e := kjson.Marshal(response)
						if e != nil {
							t.Error(e)
						}
						result = json.RawMessage(b)
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
				}))
			}
			live := makeServer(false)
			defer live.Close()
			replica := makeServer(true)
			defer replica.Close()
			snapshot, e := NewKoinosSnapshot(operator.Binding{Profile: p, RPC: live.URL}, replica.URL)
			if e != nil {
				t.Fatal(e)
			}
			tx := strings.Repeat("12", 32)
			state, e := snapshot.Read(context.Background(), base58.Encode(seed), []string{tx})
			if kind == "good" || kind == "pause-absent" || kind == "three-members" || kind == "paused" || kind == "completed" {
				if e != nil {
					t.Fatal(e)
				}
				if state.Height != 5 || state.Nonce != 7 || state.ProfileDigest != p.Digest() || state.BlockHash != hex.EncodeToString(blockID[2:]) || state.StateRoot != hex.EncodeToString(root) || (len(three) == 0 && (len(state.Validators) != 1 || state.Validators[0] != p.Contract)) || (len(three) > 0 && len(state.Validators) != 3) || state.Paused != (kind == "paused") || state.Completed[tx] != (kind == "completed") {
					t.Fatalf("bad snapshot: %+v", state)
				}
			} else if e == nil {
				t.Fatal("unsafe or malformed snapshot accepted")
			}
		})
	}
}
