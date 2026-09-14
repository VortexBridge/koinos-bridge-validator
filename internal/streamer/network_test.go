package streamer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/mr-tron/base58"
)

func TestBoundEVMRejectsRedirectedHead(t *testing.T) {
	var targetCalls int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&targetCalls, 1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "eth_chainId" {
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": "0x7a69"})
			return
		}
		if req.Method != "eth_blockNumber" {
			t.Error("unexpected method")
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	ctx, cancel := context.WithCancel(context.Background())
	metadata := store.NewMetadataStore(store.NewMapBackend())
	metadata.Put(&bridge_pb.Metadata{})
	tx := store.NewTransactionsStore(store.NewMapBackend())
	problem := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go StreamEthereumBlocks(&wg, ctx, metadata, 0, source.URL, "0x1111111111111111111111111111111111111111", 1, nil, "", base58.Encode([]byte{1}), nil, tx, tx, 60000, nil, 0, 1, Options{ObserveOnly: true, ExpectedNetworkID: "31337", OnProblem: func() {
		select {
		case problem <- struct{}{}:
		default:
		}
	}})
	defer func() { cancel(); wg.Wait() }()
	select {
	case <-problem:
	case <-time.After(3 * time.Second):
		t.Fatal("redirected head not rejected")
	}
	if atomic.LoadInt32(&targetCalls) != 0 {
		t.Fatal("redirect reached wrong RPC")
	}
	m, err := metadata.Get()
	if err != nil || m.LastEthereumBlockParsed != 0 {
		t.Fatal("redirected data checkpointed")
	}
}

func TestRuntimeNetworkSwitchDiscardsUntrustedBatches(t *testing.T) {
	for _, family := range []string{"evm", "koinos"} {
		for _, phase := range []string{"before-head", "after-head", "after-batch"} {
			t.Run(family+"/"+phase, func(t *testing.T) {
				var switched, recovered int32
				if phase == "before-head" {
					switched = 1
				}
				id := base64.URLEncoding.EncodeToString(append([]byte{0x12, 0x20}, make([]byte, 32)...))
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var req struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
					}
					if json.NewDecoder(r.Body).Decode(&req) != nil {
						t.Error("bad request")
						return
					}
					var result interface{}
					switch req.Method {
					case "eth_chainId":
						result = "0x7a69"
						if atomic.LoadInt32(&switched) == 1 {
							result = "0x1"
						}
					case "chain.get_chain_id":
						value := id
						if atomic.LoadInt32(&switched) == 1 {
							value = "EiABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=="
						}
						result = map[string]string{"chain_id": value}
					case "eth_blockNumber", "chain.get_head_info":
						if phase == "after-head" && atomic.LoadInt32(&recovered) == 0 {
							atomic.StoreInt32(&switched, 1)
						}
						if family == "evm" {
							result = "0x1"
						} else {
							result = map[string]interface{}{"head_topology": map[string]string{"id": "0x12200000000000000000000000000000000000000000000000000000000000000000", "height": "1"}, "last_irreversible_block": "1"}
						}
					case "eth_getLogs", "block_store.get_blocks_by_height":
						if phase == "after-batch" && atomic.LoadInt32(&recovered) == 0 {
							atomic.StoreInt32(&switched, 1)
						}
						if family == "evm" {
							result = []interface{}{}
						} else {
							result = json.RawMessage(`{"block_items":[{"block_height":"1","block":{"header":{"height":"1"}},"receipt":{}}]}`)
						}
					default:
						t.Errorf("unexpected method %s", req.Method)
						w.WriteHeader(400)
						return
					}
					json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
				}))
				defer server.Close()
				metadata := store.NewMetadataStore(store.NewMapBackend())
				metadata.Put(&bridge_pb.Metadata{})
				tx := store.NewTransactionsStore(store.NewMapBackend())
				ctx, cancel := context.WithCancel(context.Background())
				var wg sync.WaitGroup
				wg.Add(1)
				defer func() { cancel(); wg.Wait() }()
				problem := make(chan struct{}, 1)
				opts := Options{ObserveOnly: true, ExpectedNetworkID: id, OnIdentityProblem: func() {
					select {
					case problem <- struct{}{}:
					default:
					}
				}}
				if family == "evm" {
					opts.ExpectedNetworkID = "31337"
					go StreamEthereumBlocks(&wg, ctx, metadata, 0, server.URL, "0x1111111111111111111111111111111111111111", 1, nil, "", base58.Encode([]byte{1}), nil, tx, tx, 60000, nil, 0, 1, opts)
				} else {
					go StreamKoinosBlocks(&wg, ctx, metadata, 0, server.URL, nil, "", "0x1111111111111111111111111111111111111111", 1, nil, "", base58.Encode([]byte{1}), nil, tx, tx, 60000, nil, 1, opts)
				}
				select {
				case <-problem:
				case <-time.After(3 * time.Second):
					t.Fatal("identity mismatch not reported")
				}
				m, err := metadata.Get()
				if err != nil || m.LastEthereumBlockParsed != 0 || m.LastKoinosBlockParsed != 0 {
					t.Fatal("wrong-network batch advanced checkpoint", m, err)
				}
				atomic.StoreInt32(&recovered, 1)
				atomic.StoreInt32(&switched, 0)
				deadline := time.Now().Add(3 * time.Second)
				for {
					m, err := metadata.Get()
					if err != nil {
						t.Fatal(err)
					}
					if (family == "evm" && m.LastEthereumBlockParsed == 1) || (family == "koinos" && m.LastKoinosBlockParsed == 1) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("did not resume with verified identity", m)
					}
					time.Sleep(time.Millisecond)
				}
			})
		}
	}
}
