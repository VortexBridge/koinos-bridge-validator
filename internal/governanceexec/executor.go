// Package governanceexec submits already-approved governance routes from an
// explicit protected terminal command. It is intentionally not constructed by
// the browser-facing operator server.
package governanceexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	gethrpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	krpc "github.com/koinos-bridge/koinos-bridge-validator/internal/rpc"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	kjson "github.com/koinos/koinos-proto-golang/encoding/json"
	"github.com/koinos/koinos-proto-golang/koinos/canonical"
	"github.com/koinos/koinos-proto-golang/koinos/protocol"
	chainrpc "github.com/koinos/koinos-proto-golang/koinos/rpc/chain"
	kutil "github.com/koinos/koinos-util-golang"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multihash"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const evmGovernanceABI = `[
  {"inputs":[{"name":"signatures","type":"bytes[]"},{"name":"expiration","type":"uint256"}],"name":"pause","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"signatures","type":"bytes[]"},{"name":"expiration","type":"uint256"}],"name":"unpause","outputs":[],"stateMutability":"nonpayable","type":"function"}
]`

const maxPreparedSize = 1024 * 1024

type preparedSubmission struct {
	SchemaVersion int    `json:"schemaVersion"`
	AttemptID     string `json:"attemptId"`
	Family        string `json:"family"`
	ProfileDigest string `json:"profileDigest"`
	PayloadDigest string `json:"payloadDigest"`
	Payer         string `json:"payer"`
	TransactionID string `json:"transactionId"`
	Raw           string `json:"raw"`
}

// Executor keeps a separately encrypted transaction-payer key only for the
// duration of one terminal command. Signed raw transactions are public data but
// are stored owner-only so retries broadcast the exact same transaction.
type Executor struct {
	stateDir string
	keys     *keyvault.Keys
	now      func() time.Time
}

func New(stateDir string, keys *keyvault.Keys) (*Executor, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("governance executor data needs an absolute directory")
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		return nil, errors.New("governance executor data must be an existing mode-0700 directory")
	}
	stat, ownerOK := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !ownerOK || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("governance executor data must be an existing mode-0700 directory")
	}
	return &Executor{stateDir: stateDir, keys: keys, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (e *Executor) preparedPath(attempt string) (string, error) {
	if !strings.HasPrefix(attempt, "attempt-") || len(attempt) != len("attempt-")+64 {
		return "", errors.New("invalid durable submission attempt")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(attempt, "attempt-")); err != nil {
		return "", errors.New("invalid durable submission attempt")
	}
	return filepath.Join(e.stateDir, attempt+".json"), nil
}

func readPrepared(path string) (preparedSubmission, error) {
	var out preparedSubmission
	info, err := os.Lstat(path)
	if err != nil {
		return out, errors.New("prepared governance transaction is unavailable or unsafe")
	}
	stat, ownerOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxPreparedSize || !ownerOK || int(stat.Uid) != os.Geteuid() {
		return out, errors.New("prepared governance transaction is unavailable or unsafe")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return out, errors.New("prepared governance transaction is unreadable")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, maxPreparedSize))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(interface{})) != io.EOF || out.SchemaVersion != 1 {
		return preparedSubmission{}, errors.New("prepared governance transaction is corrupt")
	}
	return out, nil
}

func writePrepared(dir, path string, value preparedSubmission) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(raw) > maxPreparedSize {
		return errors.New("prepared governance transaction exceeds its bounded format")
	}
	tmp, err := os.CreateTemp(dir, ".governance-submit-*")
	if err != nil {
		return errors.New("cannot create prepared governance transaction")
	}
	name := tmp.Name()
	defer os.Remove(name)
	if tmp.Chmod(0600) != nil || writeAll(tmp, raw) != nil || tmp.Sync() != nil || tmp.Close() != nil || os.Rename(name, path) != nil {
		_ = tmp.Close()
		return errors.New("cannot persist prepared governance transaction")
	}
	d, err := os.Open(dir)
	if err != nil {
		return errors.New("cannot open governance executor directory")
	}
	defer d.Close()
	if d.Sync() != nil {
		return errors.New("cannot sync governance executor directory")
	}
	return nil
}

func writeAll(w io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		raw = raw[n:]
	}
	return nil
}

func (e *Executor) loadOrPrepare(ctx context.Context, binding operator.Binding, route operator.GovernanceRoute) (preparedSubmission, error) {
	if route.Receipt == nil {
		return preparedSubmission{}, errors.New("durable submission intent is missing")
	}
	path, err := e.preparedPath(route.Receipt.TransactionID)
	if err != nil {
		return preparedSubmission{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		prepared, err := readPrepared(path)
		if err != nil || prepared.AttemptID != route.Receipt.TransactionID || prepared.Family != binding.Profile.Family || prepared.ProfileDigest != binding.Profile.Digest() || prepared.PayloadDigest != route.Payload.Digest {
			return preparedSubmission{}, errors.New("prepared governance transaction differs from the reviewed route")
		}
		if _, err := validatePrepared(prepared, binding, route); err != nil {
			return preparedSubmission{}, err
		}
		return prepared, nil
	} else if !os.IsNotExist(err) {
		return preparedSubmission{}, errors.New("prepared governance transaction path is unsafe")
	}
	if e.keys == nil {
		return preparedSubmission{}, errors.New("transaction-payer vault is required for the first submission attempt")
	}
	var prepared preparedSubmission
	if binding.Profile.Family == "evm" {
		prepared, err = e.prepareEVM(ctx, binding, route)
	} else {
		prepared, err = e.prepareKoinos(ctx, binding, route)
	}
	if err != nil {
		return preparedSubmission{}, err
	}
	prepared.SchemaVersion = 1
	prepared.AttemptID = route.Receipt.TransactionID
	prepared.Family = binding.Profile.Family
	prepared.ProfileDigest = binding.Profile.Digest()
	prepared.PayloadDigest = route.Payload.Digest
	if err := writePrepared(e.stateDir, path, prepared); err != nil {
		return preparedSubmission{}, err
	}
	return prepared, nil
}

func validatePrepared(prepared preparedSubmission, binding operator.Binding, route operator.GovernanceRoute) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(prepared.Raw)
	if err != nil || len(raw) == 0 || len(raw) > maxPreparedSize/2 {
		return nil, errors.New("prepared governance transaction bytes are invalid")
	}
	if prepared.Family == "evm" {
		var tx types.Transaction
		chainID, ok := new(big.Int).SetString(binding.Profile.NetworkID, 10)
		expectedData, dataErr := evmCallData(route)
		if !ok || dataErr != nil || tx.UnmarshalBinary(raw) != nil {
			return nil, errors.New("prepared EVM transaction identity is invalid")
		}
		sender, senderErr := types.Sender(types.LatestSignerForChainID(chainID), &tx)
		if tx.Hash().Hex() != prepared.TransactionID || tx.To() == nil || *tx.To() != common.HexToAddress(binding.Profile.Contract) || tx.Value().Sign() != 0 || !bytes.Equal(tx.Data(), expectedData) || tx.ChainId().Cmp(chainID) != 0 || senderErr != nil || !strings.EqualFold(sender.Hex(), prepared.Payer) || tx.Gas() > 1_000_000 || tx.GasPrice().Sign() <= 0 || tx.GasPrice().Cmp(new(big.Int).Mul(big.NewInt(1000), big.NewInt(1_000_000_000))) > 0 {
			return nil, errors.New("prepared EVM transaction identity is invalid")
		}
	} else if prepared.Family == "koinos" {
		var tx protocol.Transaction
		expected, expectedErr := koinosOperation(binding, route)
		if proto.Unmarshal(raw, &tx) != nil || hex.EncodeToString(tx.Id) != prepared.TransactionID || expectedErr != nil || len(tx.Operations) != 1 || !proto.Equal(tx.Operations[0], expected) || tx.Header == nil || base64.URLEncoding.EncodeToString(tx.Header.ChainId) != binding.Profile.NetworkID || base58.Encode(tx.Header.Payer) != prepared.Payer || len(tx.Signatures) != 1 || validateKoinosTransaction(&tx) != nil {
			return nil, errors.New("prepared Koinos transaction identity is invalid")
		}
	} else {
		return nil, errors.New("prepared transaction family is invalid")
	}
	return raw, nil
}

func evmCallData(route operator.GovernanceRoute) ([]byte, error) {
	parsed, err := abi.JSON(strings.NewReader(evmGovernanceABI))
	if err != nil {
		return nil, errors.New("invalid built-in EVM governance ABI")
	}
	signatures, err := approvalBytes(route, true)
	if err != nil {
		return nil, err
	}
	expiration, ok := new(big.Int).SetString(route.Payload.Action.Expiration, 10)
	if !ok || route.Payload.Action.Pause == nil {
		return nil, errors.New("invalid reviewed EVM governance action")
	}
	method := "unpause"
	if *route.Payload.Action.Pause {
		method = "pause"
	}
	data, err := parsed.Pack(method, signatures, expiration)
	if err != nil {
		return nil, errors.New("cannot encode reviewed EVM governance call")
	}
	return data, nil
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

func evmClient(ctx context.Context, binding operator.Binding) (*ethclient.Client, func(), error) {
	if err := binding.Validate(); err != nil || binding.Profile.Family != "evm" || binding.Profile.Environment != "local" || !binding.Profile.Reviewed {
		return nil, nil, errors.New("reviewed local EVM binding required")
	}
	rpcClient, err := gethrpc.DialHTTPWithClient(binding.RPC, httpClient())
	if err != nil {
		return nil, nil, errors.New("EVM RPC unavailable")
	}
	client := ethclient.NewClient(rpcClient)
	want, ok := new(big.Int).SetString(binding.Profile.NetworkID, 10)
	got, err := client.ChainID(ctx)
	if !ok || err != nil || got.Cmp(want) != 0 {
		client.Close()
		return nil, nil, errors.New("EVM network differs from the reviewed profile")
	}
	return client, client.Close, nil
}

func approvalBytes(route operator.GovernanceRoute, evm bool) ([][]byte, error) {
	result := make([][]byte, len(route.Approvals))
	for i, approval := range route.Approvals {
		var raw []byte
		var err error
		if evm {
			if !strings.HasPrefix(approval.Signature, "0x") {
				return nil, errors.New("invalid EVM governance approval")
			}
			raw, err = hex.DecodeString(strings.TrimPrefix(approval.Signature, "0x"))
		} else {
			raw, err = base64.URLEncoding.DecodeString(approval.Signature)
		}
		if err != nil || len(raw) != 65 {
			return nil, errors.New("invalid governance approval encoding")
		}
		result[i] = raw
	}
	return result, nil
}

func (e *Executor) prepareEVM(ctx context.Context, binding operator.Binding, route operator.GovernanceRoute) (preparedSubmission, error) {
	client, closeClient, err := evmClient(ctx, binding)
	if err != nil {
		return preparedSubmission{}, err
	}
	defer closeClient()
	data, err := evmCallData(route)
	if err != nil {
		return preparedSubmission{}, err
	}
	if e.keys == nil || e.keys.EVM == nil {
		return preparedSubmission{}, errors.New("EVM transaction-payer key is unavailable")
	}
	from := crypto.PubkeyToAddress(e.keys.EVM.PublicKey)
	contract := common.HexToAddress(binding.Profile.Contract)
	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return preparedSubmission{}, errors.New("cannot read EVM payer nonce")
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil || gasPrice.Sign() <= 0 || gasPrice.Cmp(new(big.Int).Mul(big.NewInt(1000), big.NewInt(1_000_000_000))) > 0 {
		return preparedSubmission{}, errors.New("EVM gas price is unavailable or above the isolated-chain safety cap")
	}
	estimate, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &contract, Data: data})
	if err != nil || estimate == 0 || estimate > 1_000_000 {
		return preparedSubmission{}, errors.New("EVM governance call failed simulation or exceeds the gas cap")
	}
	gas := estimate + estimate/5
	if gas > 1_000_000 {
		gas = 1_000_000
	}
	chainID, _ := new(big.Int).SetString(binding.Profile.NetworkID, 10)
	tx := types.NewTransaction(nonce, contract, big.NewInt(0), gas, gasPrice, data)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), e.keys.EVM)
	if err != nil {
		return preparedSubmission{}, errors.New("cannot sign reviewed EVM payer transaction")
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return preparedSubmission{}, errors.New("cannot serialize EVM payer transaction")
	}
	return preparedSubmission{Payer: from.Hex(), TransactionID: signed.Hash().Hex(), Raw: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

func wireBytes(out []byte, field protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(out, field, protowire.BytesType), value)
}

func wireUint(out []byte, field protowire.Number, value uint64) []byte {
	if value == 0 {
		return out
	}
	return protowire.AppendVarint(protowire.AppendTag(out, field, protowire.VarintType), value)
}

func koinosCall(ctx context.Context, endpoint, method string, params, out proto.Message) error {
	if operator.ValidateEndpoint(endpoint) != nil || (method != "chain.get_chain_id" && method != "chain.get_account_nonce" && method != "chain.get_account_rc" && method != "chain.submit_transaction") {
		return errors.New("Koinos RPC call is not allowed")
	}
	encoded, err := kjson.Marshal(params)
	if err != nil {
		return errors.New("invalid Koinos RPC parameters")
	}
	raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": json.RawMessage(encoded)})
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if err != nil {
		return errors.New("invalid Koinos RPC request")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient().Do(req)
	if err != nil {
		return errors.New("Koinos RPC unavailable")
	}
	defer res.Body.Close()
	response, err := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if err != nil || res.StatusCode != 200 || len(response) > 2<<20 {
		return errors.New("Koinos RPC response is unavailable or oversized")
	}
	var envelope struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(response, &envelope) != nil || envelope.ID != 1 || len(envelope.Result) == 0 || string(envelope.Result) == "null" || (len(envelope.Error) > 0 && string(envelope.Error) != "null") || kjson.Unmarshal(envelope.Result, out) != nil {
		return errors.New("Koinos RPC rejected the reviewed transaction")
	}
	return nil
}

func buildKoinosTransaction(ctx context.Context, endpoint, expectedNetwork string, key *kutil.KoinosKey, operation *protocol.Operation) (*protocol.Transaction, error) {
	address := key.AddressBytes()
	var nonceResponse chainrpc.GetAccountNonceResponse
	if err := koinosCall(ctx, endpoint, "chain.get_account_nonce", &chainrpc.GetAccountNonceRequest{Account: address}, &nonceResponse); err != nil {
		return nil, err
	}
	nonce, err := kutil.NonceBytesToUInt64(nonceResponse.Nonce)
	if err != nil {
		return nil, errors.New("invalid Koinos payer nonce")
	}
	nonceBytes, err := kutil.UInt64ToNonceBytes(nonce + 1)
	if err != nil {
		return nil, errors.New("Koinos payer nonce overflow")
	}
	var rcResponse chainrpc.GetAccountRcResponse
	if err := koinosCall(ctx, endpoint, "chain.get_account_rc", &chainrpc.GetAccountRcRequest{Account: address}, &rcResponse); err != nil || rcResponse.Rc == 0 {
		return nil, errors.New("Koinos payer has no available RC")
	}
	var chainResponse chainrpc.GetChainIdResponse
	if err := koinosCall(ctx, endpoint, "chain.get_chain_id", &chainrpc.GetChainIdRequest{}, &chainResponse); err != nil {
		return nil, err
	}
	if base64.URLEncoding.EncodeToString(chainResponse.ChainId) != expectedNetwork {
		return nil, errors.New("Koinos network differs from the reviewed profile")
	}
	opHash, err := kutil.HashMessage(operation)
	if err != nil {
		return nil, errors.New("cannot hash Koinos governance operation")
	}
	root, err := kutil.CalculateMerkleRoot([][]byte{opHash})
	if err != nil {
		return nil, errors.New("cannot build Koinos operation root")
	}
	header := &protocol.TransactionHeader{ChainId: chainResponse.ChainId, RcLimit: rcResponse.Rc, Nonce: nonceBytes, OperationMerkleRoot: root, Payer: address}
	headerBytes, err := canonical.Marshal(header)
	if err != nil {
		return nil, errors.New("cannot encode Koinos transaction header")
	}
	hash := sha256.Sum256(headerBytes)
	id, err := multihash.Encode(hash[:], multihash.SHA2_256)
	if err != nil {
		return nil, errors.New("cannot identify Koinos transaction")
	}
	tx := &protocol.Transaction{Id: id, Header: header, Operations: []*protocol.Operation{operation}}
	if err := kutil.SignTransaction(key.PrivateBytes(), tx); err != nil {
		return nil, errors.New("cannot sign Koinos payer transaction")
	}
	return tx, nil
}

func koinosOperation(binding operator.Binding, route operator.GovernanceRoute) (*protocol.Operation, error) {
	if binding.Validate() != nil || binding.Profile.Family != "koinos" || binding.Profile.Environment != "local" || !binding.Profile.Reviewed || route.Payload.Action.Pause == nil {
		return nil, errors.New("reviewed local Koinos binding required")
	}
	signatures, err := approvalBytes(route, false)
	if err != nil {
		return nil, err
	}
	expiration, err := strconv.ParseUint(route.Payload.Action.Expiration, 10, 64)
	if err != nil {
		return nil, errors.New("invalid reviewed Koinos governance action")
	}
	args := []byte{}
	for _, signature := range signatures {
		args = wireBytes(args, 1, signature)
	}
	if *route.Payload.Action.Pause {
		args = wireUint(args, 2, 1)
	}
	args = wireUint(args, 3, expiration)
	contract, err := base58.Decode(binding.Profile.Contract)
	if err != nil || len(contract) != 25 {
		return nil, errors.New("invalid reviewed Koinos contract")
	}
	entryHash := sha256.Sum256([]byte("set_pause"))
	entry := binary.BigEndian.Uint32(entryHash[:4])
	return &protocol.Operation{Op: &protocol.Operation_CallContract{CallContract: &protocol.CallContractOperation{ContractId: contract, EntryPoint: entry, Args: args}}}, nil
}

func validateKoinosTransaction(tx *protocol.Transaction) error {
	if tx == nil || tx.Header == nil || len(tx.Operations) != 1 || len(tx.Signatures) != 1 || len(tx.Id) != 34 {
		return errors.New("invalid Koinos payer transaction")
	}
	opHash, err := kutil.HashMessage(tx.Operations[0])
	if err != nil {
		return err
	}
	root, err := kutil.CalculateMerkleRoot([][]byte{opHash})
	if err != nil || !bytes.Equal(root, tx.Header.OperationMerkleRoot) {
		return errors.New("invalid Koinos operation root")
	}
	headerBytes, err := canonical.Marshal(tx.Header)
	if err != nil {
		return errors.New("invalid Koinos transaction header")
	}
	h := sha256.Sum256(headerBytes)
	id, err := multihash.Encode(h[:], multihash.SHA2_256)
	if err != nil || !bytes.Equal(id, tx.Id) {
		return errors.New("invalid Koinos transaction id")
	}
	decoded, err := multihash.Decode(tx.Id)
	if err != nil {
		return errors.New("invalid Koinos transaction id")
	}
	public, _, err := btcec.RecoverCompact(btcec.S256(), tx.Signatures[0], decoded.Digest)
	if err != nil {
		return errors.New("invalid Koinos payer signature")
	}
	address, err := util.KoinosPublicKeyToAddress(public)
	if err != nil || !bytes.Equal(address, tx.Header.Payer) {
		return errors.New("Koinos payer signature does not match the header")
	}
	return nil
}

func (e *Executor) prepareKoinos(ctx context.Context, binding operator.Binding, route operator.GovernanceRoute) (preparedSubmission, error) {
	operation, err := koinosOperation(binding, route)
	if err != nil {
		return preparedSubmission{}, err
	}
	if e.keys == nil || len(e.keys.Koinos) != 32 {
		return preparedSubmission{}, errors.New("Koinos transaction-payer key is unavailable")
	}
	key, err := kutil.NewKoinosKeysFromBytes(e.keys.Koinos)
	if err != nil {
		return preparedSubmission{}, errors.New("invalid Koinos transaction-payer key")
	}
	tx, err := buildKoinosTransaction(ctx, binding.RPC, binding.Profile.NetworkID, key, operation)
	if err != nil {
		return preparedSubmission{}, err
	}
	raw, err := proto.Marshal(tx)
	if err != nil {
		return preparedSubmission{}, errors.New("cannot serialize Koinos payer transaction")
	}
	return preparedSubmission{Payer: base58.Encode(key.AddressBytes()), TransactionID: hex.EncodeToString(tx.Id), Raw: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

func (e *Executor) Submit(ctx context.Context, binding operator.Binding, _ operator.GovernanceProposal, route operator.GovernanceRoute) (operator.GovernanceReceipt, error) {
	prepared, err := e.loadOrPrepare(ctx, binding, route)
	if err != nil {
		return operator.GovernanceReceipt{}, err
	}
	raw, err := validatePrepared(prepared, binding, route)
	if err != nil {
		return operator.GovernanceReceipt{}, err
	}
	if prepared.Family == "evm" {
		client, closeClient, err := evmClient(ctx, binding)
		if err != nil {
			return operator.GovernanceReceipt{}, err
		}
		defer closeClient()
		var tx types.Transaction
		_ = tx.UnmarshalBinary(raw)
		if err := client.SendTransaction(ctx, &tx); err != nil {
			known, _, lookupErr := client.TransactionByHash(ctx, tx.Hash())
			if lookupErr != nil || known.Hash() != tx.Hash() {
				return operator.GovernanceReceipt{}, errors.New("EVM node did not accept the exact prepared transaction")
			}
		}
	} else {
		var tx protocol.Transaction
		_ = proto.Unmarshal(raw, &tx)
		var result chainrpc.SubmitTransactionResponse
		if err := koinosCall(ctx, binding.RPC, "chain.submit_transaction", &chainrpc.SubmitTransactionRequest{Transaction: &tx, Broadcast: true}, &result); err != nil || result.Receipt == nil || !bytes.Equal(result.Receipt.Id, tx.Id) || result.Receipt.Reverted {
			return operator.GovernanceReceipt{}, errors.New("Koinos node did not accept the exact prepared transaction")
		}
	}
	return operator.GovernanceReceipt{TransactionID: prepared.TransactionID, State: "submitted", SubmittedAt: e.now(), Message: "Exact prepared local-chain transaction accepted; finality is pending."}, nil
}

func (e *Executor) reconcileEVM(ctx context.Context, binding operator.Binding, receipt operator.GovernanceReceipt) (operator.GovernanceReceipt, error) {
	client, closeClient, err := evmClient(ctx, binding)
	if err != nil {
		return receipt, err
	}
	defer closeClient()
	txHash := common.HexToHash(receipt.TransactionID)
	chainReceipt, err := client.TransactionReceipt(ctx, txHash)
	if errors.Is(err, ethereum.NotFound) {
		return receipt, nil
	}
	if err != nil {
		return receipt, errors.New("EVM receipt is unavailable")
	}
	if chainReceipt.TxHash != txHash || chainReceipt.Status != types.ReceiptStatusSuccessful {
		receipt.State = "failed"
		receipt.Message = "EVM transaction finalized unsuccessfully."
		return receipt, nil
	}
	finalized, err := client.HeaderByNumber(ctx, big.NewInt(int64(gethrpc.FinalizedBlockNumber)))
	if err != nil || finalized.Number.Cmp(chainReceipt.BlockNumber) < 0 {
		return receipt, nil
	}
	canonical, err := client.HeaderByNumber(ctx, chainReceipt.BlockNumber)
	if err != nil || canonical.Hash() != chainReceipt.BlockHash {
		return receipt, errors.New("EVM receipt block is not canonical")
	}
	receipt.State = "finalized"
	receipt.FinalizedAt = e.now()
	receipt.Block = chainReceipt.BlockNumber.String()
	receipt.BlockHash = chainReceipt.BlockHash.Hex()
	receipt.Message = "EVM governance transaction is finalized and canonical."
	return receipt, nil
}

func (e *Executor) reconcileKoinos(ctx context.Context, binding operator.Binding, route operator.GovernanceRoute, receipt operator.GovernanceReceipt) (operator.GovernanceReceipt, error) {
	want, err := hex.DecodeString(receipt.TransactionID)
	if err != nil || len(want) != 34 {
		return receipt, errors.New("invalid Koinos governance transaction identity")
	}
	start, err := strconv.ParseUint(route.Anchor.Block, 10, 64)
	if err != nil || start == ^uint64(0) {
		return receipt, errors.New("invalid Koinos proposal anchor")
	}
	start++
	node := krpc.NewBoundedJsonRPC(binding.RPC)
	chainID, err := node.GetChainID(ctx)
	if err != nil || base64.URLEncoding.EncodeToString(chainID) != binding.Profile.NetworkID {
		return receipt, errors.New("Koinos network differs from the reviewed profile")
	}
	head, err := node.GetHeadInfo(ctx)
	if err != nil || head.HeadTopology == nil || head.LastIrreversibleBlock > head.HeadTopology.Height {
		return receipt, errors.New("Koinos irreversible head is unavailable")
	}
	if head.LastIrreversibleBlock < start {
		return receipt, nil
	}
	count := head.LastIrreversibleBlock - start + 1
	if count > 4096 {
		return receipt, errors.New("Koinos finality search exceeds 4096 blocks; use reviewed receipt recovery")
	}
	for offset := uint64(0); offset < count; {
		chunk := count - offset
		if chunk > 128 {
			chunk = 128
		}
		blocks, err := node.GetBlocksByHeight(ctx, multihash.Multihash(head.HeadTopology.Id), start+offset, uint32(chunk))
		if err != nil {
			return receipt, errors.New("Koinos irreversible blocks are unavailable")
		}
		for _, item := range blocks.BlockItems {
			if item == nil || item.Block == nil || item.Block.Header == nil || item.Receipt == nil || item.BlockHeight < start+offset || item.BlockHeight >= start+offset+chunk || item.BlockHeight > head.LastIrreversibleBlock || item.Block.Header.Height != item.BlockHeight || item.Receipt.Height != item.BlockHeight || len(item.BlockId) != 34 || item.BlockId[0] != 0x12 || item.BlockId[1] != 0x20 || !bytes.Equal(item.Block.Id, item.BlockId) || !bytes.Equal(item.Receipt.Id, item.BlockId) {
				return receipt, errors.New("invalid Koinos irreversible block evidence")
			}
			headerBytes, err := canonical.Marshal(item.Block.Header)
			headerHash := sha256.Sum256(headerBytes)
			if err != nil || !bytes.Equal(headerHash[:], item.BlockId[2:]) {
				return receipt, errors.New("invalid Koinos irreversible block header")
			}
			for _, tx := range item.Block.Transactions {
				if tx != nil && bytes.Equal(tx.Id, want) {
					transactionIDs := make([][]byte, len(item.Block.Transactions))
					for index, candidate := range item.Block.Transactions {
						if candidate == nil || len(candidate.Id) != 34 {
							return receipt, errors.New("invalid Koinos transaction in irreversible block")
						}
						transactionIDs[index] = candidate.Id
					}
					transactionRoot, err := kutil.CalculateMerkleRoot(transactionIDs)
					if err != nil || !bytes.Equal(transactionRoot, item.Block.Header.TransactionMerkleRoot) {
						return receipt, errors.New("Koinos transaction root differs from irreversible block header")
					}
					var transactionReceipt *protocol.TransactionReceipt
					for _, candidate := range item.Receipt.TransactionReceipts {
						if candidate != nil && bytes.Equal(candidate.Id, want) {
							transactionReceipt = candidate
						}
					}
					if transactionReceipt == nil {
						return receipt, errors.New("Koinos governance receipt is missing")
					}
					if transactionReceipt.Reverted {
						receipt.State = "failed"
						receipt.Message = "Koinos transaction finalized unsuccessfully."
						return receipt, nil
					}
					after, err := node.GetHeadInfo(ctx)
					if err != nil || after.HeadTopology == nil || after.LastIrreversibleBlock < item.BlockHeight {
						return receipt, errors.New("Koinos irreversible anchor changed during receipt verification")
					}
					canonical, err := node.GetBlocksByHeight(ctx, multihash.Multihash(after.HeadTopology.Id), item.BlockHeight, 1)
					if err != nil || len(canonical.BlockItems) != 1 || canonical.BlockItems[0] == nil || !bytes.Equal(canonical.BlockItems[0].BlockId, item.BlockId) {
						return receipt, errors.New("Koinos governance receipt block is not canonical")
					}
					afterChain, err := node.GetChainID(ctx)
					if err != nil || !bytes.Equal(afterChain, chainID) {
						return receipt, errors.New("Koinos network changed during receipt verification")
					}
					receipt.State = "finalized"
					receipt.FinalizedAt = e.now()
					receipt.Block = fmt.Sprint(item.BlockHeight)
					receipt.BlockHash = hex.EncodeToString(item.BlockId)
					receipt.Message = "Koinos governance transaction is irreversible."
					return receipt, nil
				}
			}
		}
		offset += chunk
	}
	return receipt, nil
}

func (e *Executor) Reconcile(ctx context.Context, binding operator.Binding, _ operator.GovernanceProposal, route operator.GovernanceRoute, receipt operator.GovernanceReceipt) (operator.GovernanceReceipt, error) {
	if binding.Profile.Family == "evm" {
		return e.reconcileEVM(ctx, binding, receipt)
	}
	return e.reconcileKoinos(ctx, binding, route, receipt)
}
