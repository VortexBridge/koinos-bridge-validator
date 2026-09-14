package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	kjson "github.com/koinos/koinos-proto-golang/encoding/json"
	"github.com/koinos/koinos-proto-golang/koinos/protocol"
	"github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
	chainrpc "github.com/koinos/koinos-proto-golang/koinos/rpc/chain"
	kjsonrpc "github.com/koinos/koinos-util-golang/rpc"
	"github.com/multiformats/go-multihash"
	"google.golang.org/protobuf/proto"
)

// RPC service constants
const (
	GetHeadInfoCall       = "chain.get_head_info"
	GetBlocksByHeightCall = "block_store.get_blocks_by_height"
	SubmitBlockCall       = "chain.submit_block"
)

// JsonRPC
type JsonRPC struct {
	client     *kjsonrpc.KoinosRPCClient
	endpoint   string
	httpClient *http.Client
}

// NewBoundedJsonRPC uses one redirect-refusing HTTP transport for network
// identity and block reads. No submission methods are allowed through it.
func NewBoundedJsonRPC(endpoint string) *JsonRPC {
	return &JsonRPC{endpoint: endpoint, httpClient: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}}
}
func (k *JsonRPC) call(ctx context.Context, method string, params, out proto.Message) error {
	if k.httpClient == nil {
		return k.client.Call(ctx, method, params, out)
	}
	if method != GetHeadInfoCall && method != GetBlocksByHeightCall && method != "chain.get_chain_id" {
		return errors.New("runtime RPC method is not read-only")
	}
	encoded, err := kjson.Marshal(params)
	if err != nil {
		return errors.New("invalid RPC parameters")
	}
	raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": json.RawMessage(encoded)})
	req, err := http.NewRequestWithContext(ctx, "POST", k.endpoint, bytes.NewReader(raw))
	if err != nil {
		return errors.New("invalid runtime RPC endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := k.httpClient.Do(req)
	if err != nil {
		return errors.New("runtime RPC unavailable, redirected or timed out")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("runtime RPC HTTP request failed")
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, (32<<20)+1))
	if err != nil || len(raw) > 32<<20 {
		return errors.New("runtime RPC response too large or unreadable")
	}
	var envelope struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.ID != 1 || len(envelope.Result) == 0 || string(envelope.Result) == "null" || (len(envelope.Error) != 0 && string(envelope.Error) != "null") {
		return errors.New("invalid runtime RPC response")
	}
	if kjson.Unmarshal(envelope.Result, out) != nil {
		return errors.New("invalid runtime RPC result")
	}
	return nil
}

func (k *JsonRPC) GetChainID(ctx context.Context) ([]byte, error) {
	var result chainrpc.GetChainIdResponse
	if err := k.call(ctx, "chain.get_chain_id", &chainrpc.GetChainIdRequest{}, &result); err != nil {
		return nil, err
	}
	if len(result.ChainId) != 34 || result.ChainId[0] != 0x12 || result.ChainId[1] != 0x20 {
		return nil, errors.New("invalid Koinos network identity")
	}
	return result.ChainId, nil
}

// NewJsonRPC factory
func NewJsonRPC(client *kjsonrpc.KoinosRPCClient) *JsonRPC {
	rpc := new(JsonRPC)
	rpc.client = client
	return rpc
}

func (k *JsonRPC) GetHeadInfo(ctx context.Context) (*chainrpc.GetHeadInfoResponse, error) {
	params := chainrpc.GetHeadInfoRequest{}

	headInfo := &chainrpc.GetHeadInfoResponse{}

	err := k.call(ctx, GetHeadInfoCall, &params, headInfo)
	if err != nil {
		return nil, err
	}

	return headInfo, nil
}

func (k *JsonRPC) GetBlocksByHeight(ctx context.Context, blockID multihash.Multihash, height uint64, numBlocks uint32) (*block_store.GetBlocksByHeightResponse, error) {
	params := block_store.GetBlocksByHeightRequest{
		ReturnBlock:         true,
		ReturnReceipt:       true,
		NumBlocks:           numBlocks,
		AncestorStartHeight: height,
		HeadBlockId:         blockID,
	}

	blockResponse := &block_store.GetBlocksByHeightResponse{}

	err := k.call(ctx, GetBlocksByHeightCall, &params, blockResponse)
	if err != nil {
		return nil, err
	}

	return blockResponse, nil
}

func (k *JsonRPC) ApplyBlock(ctx context.Context, block *protocol.Block) (*chainrpc.SubmitBlockResponse, error) {
	submitBlockResp := &chainrpc.SubmitBlockResponse{}
	err := k.call(ctx, SubmitBlockCall, &chainrpc.SubmitBlockRequest{Block: block}, submitBlockResp)

	if err != nil {
		return nil, err
	}

	return submitBlockResp, nil
}
