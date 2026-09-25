package governanceexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	kjson "github.com/koinos/koinos-proto-golang/encoding/json"
	koinos "github.com/koinos/koinos-proto-golang/koinos"
	"github.com/koinos/koinos-proto-golang/koinos/canonical"
	"github.com/koinos/koinos-proto-golang/koinos/protocol"
	blockrpc "github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
	chainrpc "github.com/koinos/koinos-proto-golang/koinos/rpc/chain"
	kutil "github.com/koinos/koinos-util-golang"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multihash"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func executorProfile(family string) operator.Profile {
	if family == "evm" {
		return operator.Profile{SchemaVersion: 1, ID: "fixture-evm", Name: "Fixture EVM", Family: "evm", Environment: "local", NetworkID: "31337", BridgeChainID: 2, Contract: "0x1111111111111111111111111111111111111111", Codec: operator.EVMCodec, SourceCommit: operator.EVMSource, CodeHash: strings.Repeat("1", 64), ReviewEvidence: "synthetic executor fixture", Reviewed: true}
	}
	return operator.Profile{SchemaVersion: 1, ID: "fixture-koinos", Name: "Fixture Koinos", Family: "koinos", Environment: "local", NetworkID: "EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==", BridgeChainID: 1, Contract: "1aqHtNRDkiAZeFtuM8fRFuurcje6eHqF8", Codec: operator.KoinosCodec, SourceCommit: operator.KoinosSource, CodeHash: strings.Repeat("2", 64), ReviewEvidence: "synthetic executor fixture", Reviewed: true}
}

func TestFinalizedEVMHeaderUsesNamedFinalityTag(t *testing.T) {
	wantNumber := big.NewInt(7)
	wantHash := common.HexToHash("0x1234")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Method != "eth_getBlockByNumber" || len(request.Params) != 2 || string(request.Params[0]) != `"finalized"` || string(request.Params[1]) != "false" {
			t.Error("finalized EVM read did not use the named RPC finality tag")
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": map[string]string{"number": "0x7", "hash": wantHash.Hex()}})
	}))
	defer server.Close()
	binding := operator.Binding{Profile: executorProfile("evm"), RPC: server.URL}
	gotNumber, gotHash, err := evmHeaderIdentity(context.Background(), binding, "finalized")
	if err != nil || gotNumber.Cmp(wantNumber) != 0 || gotHash != wantHash {
		t.Fatal("named finalized EVM head was not read", err)
	}
}

func executorRoute(t *testing.T, family string) operator.GovernanceRoute {
	t.Helper()
	profile := executorProfile(family)
	pause := true
	payload, err := operator.EncodeAction(profile, operator.Action{Kind: "set_pause", Pause: &pause, Nonce: "4", Expiration: "2000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	route := operator.GovernanceRoute{Profile: profile, Payload: payload}
	digest, _ := hex.DecodeString(payload.Digest)
	for index := byte(1); index <= 2; index++ {
		seed := make([]byte, 32)
		seed[31] = index
		var signature, signer string
		if family == "evm" {
			key, _ := crypto.ToECDSA(seed)
			raw, _ := crypto.Sign(digest, key)
			raw[64] += 27
			signature = "0x" + hex.EncodeToString(raw)
			signer = crypto.PubkeyToAddress(key.PublicKey).Hex()
		} else {
			key, public := btcec.PrivKeyFromBytes(btcec.S256(), seed)
			raw, _ := btcec.SignCompact(btcec.S256(), key, digest, true)
			signature = base64.URLEncoding.EncodeToString(raw)
			address, _ := util.KoinosPublicKeyToAddress(public)
			signer = base58.Encode(address)
		}
		route.Approvals = append(route.Approvals, operator.GovernanceApproval{Signer: signer, Signature: signature})
	}
	return route
}

func TestPreparedEVMTransactionIsBoundToExactRoute(t *testing.T) {
	route := executorRoute(t, "evm")
	binding := operator.Binding{Profile: route.Profile, RPC: "http://127.0.0.1:1"}
	data, err := evmCallData(route)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	seed[31] = 9
	key, _ := crypto.ToECDSA(seed)
	tx := types.NewTransaction(3, common.HexToAddress(route.Profile.Contract), common.Big0, 100000, common.Big1, data)
	tx, err = types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	prepared := preparedSubmission{SchemaVersion: 1, Family: "evm", ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Payer: crypto.PubkeyToAddress(key.PublicKey).Hex(), TransactionID: tx.Hash().Hex(), Raw: base64.RawURLEncoding.EncodeToString(raw)}
	if _, err := validatePrepared(prepared, binding, route); err != nil {
		t.Fatal(err)
	}
	changed := route
	changed.Payload.Action.Expiration = "2000000000001"
	if _, err := validatePrepared(prepared, binding, changed); err == nil {
		t.Fatal("prepared EVM transaction accepted a changed action")
	}
	prepared.Payer = common.HexToAddress("0x2222222222222222222222222222222222222222").Hex()
	if _, err := validatePrepared(prepared, binding, route); err == nil {
		t.Fatal("prepared EVM transaction accepted a changed payer")
	}
}

func TestPreparedKoinosTransactionIsBoundToExactRoute(t *testing.T) {
	route := executorRoute(t, "koinos")
	binding := operator.Binding{Profile: route.Profile, RPC: "http://127.0.0.1:1"}
	operation, err := koinosOperation(binding, route)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	seed[31] = 9
	key, _ := kutil.NewKoinosKeysFromBytes(seed)
	nonce, _ := kutil.UInt64ToNonceBytes(3)
	opHash, _ := kutil.HashMessage(operation)
	root, _ := kutil.CalculateMerkleRoot([][]byte{opHash})
	chain, _ := base64.URLEncoding.DecodeString(route.Profile.NetworkID)
	header := &protocol.TransactionHeader{ChainId: chain, RcLimit: 1000000, Nonce: nonce, OperationMerkleRoot: root, Payer: key.AddressBytes()}
	headerBytes, _ := canonical.Marshal(header)
	h := sha256.Sum256(headerBytes)
	id, _ := multihash.Encode(h[:], multihash.SHA2_256)
	tx := &protocol.Transaction{Id: id, Header: header, Operations: []*protocol.Operation{operation}}
	if err := kutil.SignTransaction(seed, tx); err != nil {
		t.Fatal(err)
	}
	raw, _ := proto.Marshal(tx)
	prepared := preparedSubmission{SchemaVersion: 1, Family: "koinos", ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Payer: base58.Encode(key.AddressBytes()), TransactionID: hex.EncodeToString(tx.Id), Raw: base64.RawURLEncoding.EncodeToString(raw)}
	if _, err := validatePrepared(prepared, binding, route); err != nil {
		t.Fatal(err)
	}
	tx.Operations[0].GetCallContract().Args = append(tx.Operations[0].GetCallContract().Args, 0)
	raw, _ = proto.Marshal(tx)
	prepared.Raw = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := validatePrepared(prepared, binding, route); err == nil {
		t.Fatal("prepared Koinos transaction accepted changed call bytes")
	}
}

func TestPreparedSubmissionFileIsPrivateAndContainsNoScalar(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executor, err := New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	attempt := "attempt-" + strings.Repeat("a", 64)
	path, err := executor.preparedPath(attempt)
	if err != nil {
		t.Fatal(err)
	}
	value := preparedSubmission{SchemaVersion: 1, AttemptID: attempt, Family: "evm", ProfileDigest: strings.Repeat("b", 64), PayloadDigest: strings.Repeat("c", 64), Payer: "0x1111111111111111111111111111111111111111", TransactionID: "0x" + strings.Repeat("d", 64), Raw: base64.RawURLEncoding.EncodeToString([]byte("public-signed-transaction"))}
	if err := writePrepared(dir, path, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("prepared transaction is not owner-only")
	}
	loaded, err := readPrepared(path)
	if err != nil || loaded.AttemptID != attempt {
		t.Fatal("prepared transaction did not round trip", err)
	}
	content, _ := os.ReadFile(filepath.Clean(path))
	if bytes.Contains(content, bytes.Repeat([]byte{9}, 32)) {
		t.Fatal("private scalar appeared in prepared public transaction state")
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(open, nil); err == nil {
		t.Fatal("executor accepted a directory without explicit mode 0700")
	}
}

func TestEVMSubmitPersistsAndReusesExactSignedTransaction(t *testing.T) {
	var submitted [][]byte
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Fatal("invalid request")
		}
		var result interface{}
		switch request.Method {
		case "eth_chainId":
			result = "0x7a69"
		case "eth_getTransactionCount":
			result = "0x0"
		case "eth_gasPrice":
			result = "0x3b9aca00"
		case "eth_estimateGas":
			result = "0x186a0"
		case "eth_sendRawTransaction":
			var encoded string
			_ = json.Unmarshal(request.Params[0], &encoded)
			raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
			if err != nil {
				t.Fatal(err)
			}
			var tx types.Transaction
			if tx.UnmarshalBinary(raw) != nil {
				t.Fatal("invalid submitted transaction")
			}
			submitted = append(submitted, append([]byte{}, raw...))
			result = tx.Hash().Hex()
		default:
			t.Fatalf("unexpected EVM RPC method %s", request.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	defer rpc.Close()

	route := executorRoute(t, "evm")
	route.Receipt = &operator.GovernanceReceipt{TransactionID: "attempt-" + strings.Repeat("a", 64), State: "submitting"}
	binding := operator.Binding{Profile: route.Profile, RPC: rpc.URL}
	seed := make([]byte, 32)
	seed[31] = 9
	evmKey, _ := crypto.ToECDSA(seed)
	koinosSeed := make([]byte, 32)
	koinosSeed[31] = 10
	keys := &keyvault.Keys{EVM: evmKey, Koinos: koinosSeed}
	defer keys.Close()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	executor, err := New(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	first, err := executor.Submit(context.Background(), binding, operator.GovernanceProposal{}, route)
	if err != nil || first.State != "submitted" {
		t.Fatal(first, err)
	}
	second, err := executor.Submit(context.Background(), binding, operator.GovernanceProposal{}, route)
	if err != nil || second.TransactionID != first.TransactionID || len(submitted) != 2 || !bytes.Equal(submitted[0], submitted[1]) {
		t.Fatal("retry did not reuse the exact signed EVM transaction", second, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "attempt-*.json"))
	if len(files) != 1 {
		t.Fatal("exact prepared EVM transaction was not persisted once")
	}
}

func TestKoinosSubmitPersistsAndReusesExactSignedTransaction(t *testing.T) {
	route := executorRoute(t, "koinos")
	chainID, _ := base64.URLEncoding.DecodeString(route.Profile.NetworkID)
	nonce, _ := kutil.UInt64ToNonceBytes(0)
	var submitted [][]byte
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Fatal("invalid request")
		}
		var result proto.Message
		switch request.Method {
		case "chain.get_account_nonce":
			result = &chainrpc.GetAccountNonceResponse{Nonce: nonce}
		case "chain.get_account_rc":
			result = &chainrpc.GetAccountRcResponse{Rc: 1000000}
		case "chain.get_chain_id":
			result = &chainrpc.GetChainIdResponse{ChainId: chainID}
		case "chain.submit_transaction":
			var params chainrpc.SubmitTransactionRequest
			if kjson.Unmarshal(request.Params, &params) != nil || params.Transaction == nil {
				t.Fatal("invalid Koinos submission")
			}
			raw, _ := proto.Marshal(params.Transaction)
			submitted = append(submitted, raw)
			result = &chainrpc.SubmitTransactionResponse{Receipt: &protocol.TransactionReceipt{Id: params.Transaction.Id}}
		default:
			t.Fatalf("unexpected Koinos RPC method %s", request.Method)
		}
		raw, _ := kjson.Marshal(result)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": json.RawMessage(raw)})
	}))
	defer rpc.Close()

	route.Receipt = &operator.GovernanceReceipt{TransactionID: "attempt-" + strings.Repeat("b", 64), State: "submitting"}
	binding := operator.Binding{Profile: route.Profile, RPC: rpc.URL}
	evmSeed := make([]byte, 32)
	evmSeed[31] = 9
	evmKey, _ := crypto.ToECDSA(evmSeed)
	koinosSeed := make([]byte, 32)
	koinosSeed[31] = 10
	keys := &keyvault.Keys{EVM: evmKey, Koinos: koinosSeed}
	defer keys.Close()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	executor, err := New(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	first, err := executor.Submit(context.Background(), binding, operator.GovernanceProposal{}, route)
	if err != nil || first.State != "submitted" {
		t.Fatal(first, err)
	}
	second, err := executor.Submit(context.Background(), binding, operator.GovernanceProposal{}, route)
	if err != nil || second.TransactionID != first.TransactionID || len(submitted) != 2 || !bytes.Equal(submitted[0], submitted[1]) {
		t.Fatal("retry did not reuse the exact signed Koinos transaction", second, err)
	}
}

func TestKoinosReconcileRequiresIrreversibleCanonicalReceipt(t *testing.T) {
	route := executorRoute(t, "koinos")
	route.Anchor.Block = "4"
	transaction := syntheticKoinosTransaction(t, 1)
	transactionID := transaction.Id
	transactionRoot, err := koinosTransactionMerkleRoot([]*protocol.Transaction{transaction})
	if err != nil {
		t.Fatal(err)
	}
	header := &protocol.BlockHeader{Height: 5, TransactionMerkleRoot: transactionRoot}
	headerRaw, _ := canonical.Marshal(header)
	blockHash := sha256.Sum256(headerRaw)
	blockID, _ := multihash.Encode(blockHash[:], multihash.SHA2_256)
	chainID, _ := base64.URLEncoding.DecodeString(route.Profile.NetworkID)
	item := &blockrpc.BlockItem{
		BlockId:     blockID,
		BlockHeight: 5,
		Block:       &protocol.Block{Id: blockID, Header: header, Transactions: []*protocol.Transaction{transaction}},
		Receipt:     &protocol.BlockReceipt{Id: blockID, Height: 5, TransactionReceipts: []*protocol.TransactionReceipt{{Id: transactionID}}},
	}
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Fatal("invalid request")
		}
		var result proto.Message
		switch request.Method {
		case "chain.get_chain_id":
			result = &chainrpc.GetChainIdResponse{ChainId: chainID}
		case "chain.get_head_info":
			result = &chainrpc.GetHeadInfoResponse{HeadTopology: &koinos.BlockTopology{Id: blockID, Height: 5}, LastIrreversibleBlock: 5}
		case "block_store.get_blocks_by_height":
			result = &blockrpc.GetBlocksByHeightResponse{BlockItems: []*blockrpc.BlockItem{item}}
		default:
			t.Fatalf("unexpected Koinos RPC method %s", request.Method)
		}
		raw, _ := kjson.Marshal(result)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": json.RawMessage(raw)})
	}))
	defer rpc.Close()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	executor, _ := New(dir, nil)
	receipt := operator.GovernanceReceipt{TransactionID: hex.EncodeToString(transactionID), State: "submitted"}
	result, err := executor.Reconcile(context.Background(), operator.Binding{Profile: route.Profile, RPC: rpc.URL}, operator.GovernanceProposal{}, route, receipt)
	if err != nil || result.State != "finalized" || result.Block != "5" || result.BlockHash != hex.EncodeToString(blockID) {
		t.Fatal("irreversible Koinos receipt was not reconciled", result, err)
	}
	item.Receipt.TransactionReceipts[0].Reverted = true
	result, err = executor.Reconcile(context.Background(), operator.Binding{Profile: route.Profile, RPC: rpc.URL}, operator.GovernanceProposal{}, route, receipt)
	if err != nil || result.State != "failed" {
		t.Fatal("reverted irreversible Koinos receipt was not failed", result, err)
	}
}

func syntheticKoinosTransaction(t *testing.T, nonce uint64) *protocol.Transaction {
	t.Helper()
	header := &protocol.TransactionHeader{
		ChainId:             []byte("synthetic-chain"),
		RcLimit:             1000 + nonce,
		Nonce:               protowire.AppendVarint(nil, nonce),
		OperationMerkleRoot: []byte("synthetic-operation-root"),
		Payer:               []byte("synthetic-payer"),
	}
	headerBytes, err := canonical.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	headerHash := sha256.Sum256(headerBytes)
	id, err := multihash.Encode(headerHash[:], multihash.SHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Transaction{
		Id:         id,
		Header:     header,
		Signatures: [][]byte{[]byte(fmt.Sprintf("signature-%d-a", nonce)), []byte(fmt.Sprintf("signature-%d-b", nonce))},
	}
}

func TestKoinosTransactionMerkleRootMatchesBlockAlgorithm(t *testing.T) {
	first := syntheticKoinosTransaction(t, 1)
	second := syntheticKoinosTransaction(t, 2)

	var leaves [][]byte
	for _, transaction := range []*protocol.Transaction{first, second} {
		headerBytes, err := canonical.Marshal(transaction.Header)
		if err != nil {
			t.Fatal(err)
		}
		headerHash := sha256.Sum256(headerBytes)
		headerLeaf, _ := multihash.Encode(headerHash[:], multihash.SHA2_256)
		signatureHash := sha256.Sum256(bytes.Join(transaction.Signatures, nil))
		signatureLeaf, _ := multihash.Encode(signatureHash[:], multihash.SHA2_256)
		leaves = append(leaves, headerLeaf, signatureLeaf)
	}
	want, err := kutil.CalculateMerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	got, err := koinosTransactionMerkleRoot([]*protocol.Transaction{first, second})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unexpected transaction root %x, want %x: %v", got, want, err)
	}

	tampered := proto.Clone(first).(*protocol.Transaction)
	tampered.Header.RcLimit++
	if _, err := koinosTransactionMerkleRoot([]*protocol.Transaction{tampered}); err == nil {
		t.Fatal("tampered transaction ID was accepted")
	}
}
