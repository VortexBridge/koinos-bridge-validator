// vortex-candidate-check is a fixed synthetic observation qualification suite.
// It runs only inside the restricted candidate container and never consumes
// host configuration, networks, keys, databases or mount points.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	kjson "github.com/koinos/koinos-proto-golang/encoding/json"
	"github.com/koinos/koinos-proto-golang/koinos/protocol"
	"github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	evmContract    = "0x1111111111111111111111111111111111111111"
	evmToken       = "0x2222222222222222222222222222222222222222"
	koinosContract = "1111111111111111111114oLvT2"
	evmNetworkID   = "31337"
)

var (
	evmTransactionID    = common.HexToHash("0x01").Hex()
	koinosTransactionID = "0x" + strings.Repeat("00", 31) + "02"
)

type boundedLog struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (l *boundedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	remaining := 4096 - l.data.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		l.data.Write(p)
	}
	return n, nil
}

func (l *boundedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.data.String()
}

type Report struct {
	SchemaVersion  int      `json:"schemaVersion"`
	Scope          string   `json:"scope"`
	ArtifactSHA256 string   `json:"artifactSha256"`
	State          string   `json:"state"`
	Checks         []string `json:"checks"`
	Error          string   `json:"error,omitempty"`
}

type fixtures struct {
	koinosNetworkID string
	evmLogs         json.RawMessage
	koinosBlocks    json.RawMessage
}

func main() {
	report := Report{SchemaVersion: 2, Scope: "isolated-observation-transfer-v2", State: "failed", Checks: []string{}}
	if err := run(&report); err != nil {
		report.Error = err.Error()
	} else {
		report.State = "checks-passed"
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	if report.State != "checks-passed" {
		os.Exit(1)
	}
}

func makeFixtures() (fixtures, error) {
	contractBytes, err := base58.Decode(koinosContract)
	if err != nil {
		return fixtures{}, errors.New("invalid fixed Koinos fixture address")
	}
	eventABI, err := abi.JSON(strings.NewReader(`[{"type":"event","name":"TokensLockedEvent","inputs":[{"name":"from","type":"address"},{"name":"token","type":"address"},{"name":"amount","type":"uint256"},{"name":"payment","type":"uint256"},{"name":"relayer","type":"string"},{"name":"recipient","type":"string"},{"name":"metadata","type":"string"},{"name":"blocktime","type":"uint256"},{"name":"chain","type":"uint32"}]}]`))
	if err != nil {
		return fixtures{}, errors.New("invalid fixed EVM event ABI")
	}
	data, err := eventABI.Events["TokensLockedEvent"].Inputs.Pack(
		common.HexToAddress("0x3333333333333333333333333333333333333333"),
		common.HexToAddress(evmToken), big.NewInt(50), big.NewInt(1),
		koinosContract, koinosContract, "candidate-fixture", big.NewInt(1700000000), uint32(1),
	)
	if err != nil {
		return fixtures{}, errors.New("cannot encode fixed EVM event")
	}
	eventLog := types.Log{
		Address:     common.HexToAddress(evmContract),
		Topics:      []common.Hash{crypto.Keccak256Hash([]byte("TokensLockedEvent(address,address,uint256,uint256,string,string,string,uint256,uint32)"))},
		Data:        data,
		BlockNumber: 5,
		TxHash:      common.HexToHash("0x01"),
		BlockHash:   common.HexToHash("0x05"),
	}
	evmLogs, err := json.Marshal([]types.Log{eventLog})
	if err != nil {
		return fixtures{}, errors.New("cannot serialize fixed EVM event")
	}
	koinosPayload, err := proto.Marshal(&bridge_pb.TokensLockedEvent{
		From: contractBytes, Token: contractBytes, Amount: "75", Payment: "2",
		Recipient: common.HexToAddress("0x4444444444444444444444444444444444444444").Hex(),
		Relayer:   common.HexToAddress("0x5555555555555555555555555555555555555555").Hex(),
		Metadata:  "candidate-fixture", ChainId: 1,
	})
	if err != nil {
		return fixtures{}, errors.New("cannot encode fixed Koinos event")
	}
	receiptID := make([]byte, 32)
	receiptID[len(receiptID)-1] = 2
	response := &block_store.GetBlocksByHeightResponse{BlockItems: []*block_store.BlockItem{{
		BlockHeight: 1,
		Block:       &protocol.Block{Header: &protocol.BlockHeader{Height: 1, Timestamp: 1700000000}},
		Receipt: &protocol.BlockReceipt{TransactionReceipts: []*protocol.TransactionReceipt{{
			Id:     receiptID,
			Events: []*protocol.EventData{{Sequence: 1, Source: contractBytes, Name: "bridge.tokens_locked_event", Data: koinosPayload}},
		}}},
	}}}
	koinosBlocks, err := kjson.Marshal(response)
	if err != nil {
		return fixtures{}, errors.New("cannot serialize fixed Koinos block")
	}
	network := append([]byte{0x12, 0x20}, make([]byte, 32)...)
	return fixtures{
		koinosNetworkID: base64.URLEncoding.EncodeToString(network),
		evmLogs:         json.RawMessage(evmLogs),
		koinosBlocks:    json.RawMessage(koinosBlocks),
	}, nil
}

func transaction(ctx context.Context, client *http.Client, endpoint string, expected bridge_pb.TransactionType) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("invalid synthetic transaction query")
	}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("candidate transaction read unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("candidate synthetic transaction missing: HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("candidate transaction response unreadable or oversized")
	}
	var tx bridge_pb.Transaction
	if protojson.Unmarshal(raw, &tx) != nil || tx.Type != expected || tx.Id == "" || tx.Hash == "" {
		return errors.New("candidate returned an invalid synthetic transaction")
	}
	if len(tx.Signatures) != 0 || len(tx.Validators) != 0 {
		return errors.New("observation candidate produced a transfer signature")
	}
	if tx.Status != bridge_pb.TransactionStatus_gathering_signatures {
		return errors.New("synthetic transaction has an unexpected state")
	}
	return nil
}

func checkTransactions(ctx context.Context, client *http.Client) error {
	if err := transaction(ctx, client, "http://127.0.0.1:13000/GetEthereumTransaction?TransactionId="+url.QueryEscape(evmTransactionID), bridge_pb.TransactionType_ethereum); err != nil {
		return err
	}
	return transaction(ctx, client, "http://127.0.0.1:13000/GetKoinosTransaction?TransactionId="+url.QueryEscape(koinosTransactionID)+"&OpId=1", bridge_pb.TransactionType_koinos)
}

func boundHealth(h worker.Health, f fixtures) bool {
	return h.Mode == "observation-only" && h.EVMAddress == "" && h.KoinosAddress == "" && h.NetworkBinding != nil &&
		h.NetworkBinding.EVMNetworkID == evmNetworkID && h.NetworkBinding.KoinosNetworkID == f.koinosNetworkID &&
		strings.EqualFold(h.NetworkBinding.EVMContract, evmContract) && h.NetworkBinding.KoinosContract == koinosContract
}

func firstRunHealth(h worker.Health, f fixtures) bool {
	if !boundHealth(h, f) || h.Chains["evm"].Height != 5 || h.Chains["evm"].Status != "observed" || h.Chains["koinos"].Height != 1 || h.Chains["koinos"].Status != "observed" {
		return false
	}
	for _, direction := range []string{"evm-to-koinos", "koinos-to-evm"} {
		a, ok := h.Activity[direction]
		if !ok || !a.Enabled || !a.Complete || a.Writes != 1 || a.NewRecords != 1 || a.LocalSignatureChanges != 0 || a.OtherSignatureChanges != 0 || a.CompletionTransitions != 0 {
			return false
		}
	}
	return true
}

func restartedHealth(h worker.Health, f fixtures) bool {
	if !boundHealth(h, f) || h.Chains["evm"].Height != 5 || h.Chains["evm"].Status != "observed" || h.Chains["koinos"].Height != 1 || h.Chains["koinos"].Status != "observed" {
		return false
	}
	for _, direction := range []string{"evm-to-koinos", "koinos-to-evm"} {
		a, ok := h.Activity[direction]
		if !ok || !a.Enabled || !a.Complete || a.Writes != 0 || a.NewRecords != 0 || a.LocalSignatureChanges != 0 || a.OtherSignatureChanges != 0 || a.CompletionTransitions != 0 {
			return false
		}
	}
	return true
}

func waitHealth(ctx context.Context, control string, pid int, accept func(worker.Health) bool, logs *boundedLog) (worker.Health, error) {
	for {
		var health worker.Health
		if worker.Call(ctx, control, http.MethodGet, "/health", &health) == nil && health.PID == pid && accept(health) {
			return health, nil
		}
		select {
		case <-ctx.Done():
			return health, fmt.Errorf("candidate health condition timed out; mode=%s evm=%s/%d koinos=%s/%d; bounded synthetic log: %s", health.Mode, health.Chains["evm"].Status, health.Chains["evm"].Height, health.Chains["koinos"].Status, health.Chains["koinos"].Height, logs.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func run(report *Report) error {
	if os.Getenv("VORTEX_CANDIDATE_SANDBOX") != "1" {
		return errors.New("run through the restricted candidate container workflow")
	}
	file, err := os.Open("/candidate/validator")
	if err != nil {
		return errors.New("candidate artifact unavailable")
	}
	h := sha256.New()
	_, err = io.Copy(h, file)
	file.Close()
	if err != nil {
		return errors.New("candidate artifact unreadable")
	}
	report.ArtifactSHA256 = hex.EncodeToString(h.Sum(nil))
	f, err := makeFixtures()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var forbidden, evmBatches, koinosBatches, wrongEVM, wrongKoinos int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	rpc := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var result interface{}
		switch req.Method {
		case "eth_chainId":
			result = "0x7a69"
			if atomic.LoadInt32(&wrongEVM) != 0 {
				result = "0x1"
			}
		case "eth_blockNumber":
			result = "0x6"
		case "eth_getLogs":
			atomic.AddInt32(&evmBatches, 1)
			result = f.evmLogs
		case "chain.get_chain_id":
			identity := f.koinosNetworkID
			if atomic.LoadInt32(&wrongKoinos) != 0 {
				identity = base64.URLEncoding.EncodeToString(append([]byte{0x12, 0x20}, bytes.Repeat([]byte{1}, 32)...))
			}
			result = map[string]string{"chain_id": identity}
		case "chain.get_head_info":
			result = map[string]interface{}{"last_irreversible_block": "1", "head_topology": map[string]interface{}{"height": "1", "id": "0x12200000000000000000000000000000000000000000000000000000000000000000"}}
		case "block_store.get_blocks_by_height":
			atomic.AddInt32(&koinosBatches, 1)
			result = f.koinosBlocks
		default:
			atomic.AddInt32(&forbidden, 1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	})}
	go rpc.Serve(listener)
	defer rpc.Close()
	rpcURL := "http://" + listener.Addr().String()
	base := "/work/validator"
	if err := os.Mkdir(base, 0700); err != nil {
		return err
	}
	cfg := fmt.Sprintf("bridge:\n  instance-id: isolated-candidate\n  log-level: error\n  api-url: 127.0.0.1:13000\n  ethereum-rpc: %s\n  ethereum-network-id: '%s'\n  ethereum-contract: '%s'\n  ethereum-max-blocks-stream: 10\n  ethereum-confirmations: 1\n  ethereum-polling-time: 20\n  koinos-rpc: %s\n  koinos-network-id: '%s'\n  koinos-contract: '%s'\n  koinos-max-blocks-stream: 10\n  koinos-polling-time: 20\n  ethereum-pk-file: /production-keys-not-mounted/evm\n  koinos-pk-file: /production-keys-not-mounted/koinos\n  tokens:\n    synthetic:\n      ethereum-address: '%s'\n      koinos-address: '%s'\n", rpcURL, evmNetworkID, evmContract, rpcURL, f.koinosNetworkID, koinosContract, evmToken, koinosContract)
	if err := os.WriteFile(filepath.Join(base, "config.yml"), []byte(cfg), 0600); err != nil {
		return err
	}
	logs := &boundedLog{}
	start := func() (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, "/candidate/validator", "--basedir", base, "--observe-only")
		cmd.Env = []string{"HOME=/work", "PATH=/usr/bin:/bin"}
		cmd.Stdout = logs
		cmd.Stderr = logs
		return cmd, cmd.Start()
	}
	control := filepath.Join(base, "bridge", ".operator")
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	first, err := start()
	if err != nil {
		return errors.New("candidate failed to execute")
	}
	defer stopProcess(first)
	if _, err := waitHealth(ctx, control, first.Process.Pid, func(h worker.Health) bool { return firstRunHealth(h, f) }, logs); err != nil {
		return err
	}
	if err := checkTransactions(ctx, client); err != nil {
		return err
	}
	report.Checks = append(report.Checks, "pinned-networks-and-both-direction-transfer-records")
	report.Checks = append(report.Checks, "observation-produced-zero-signatures")
	response, err := client.Post("http://127.0.0.1:13000/SubmitSignature", "application/json", nil)
	if err != nil {
		return errors.New("candidate signature endpoint unavailable")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		return errors.New("candidate allows signature exchange in observation mode")
	}
	report.Checks = append(report.Checks, "signature-exchange-refused")
	duplicate, err := start()
	if err != nil {
		return errors.New("duplicate-process check could not execute candidate")
	}
	if duplicate.Wait() == nil {
		return errors.New("duplicate candidate instance admitted")
	}
	report.Checks = append(report.Checks, "duplicate-process-excluded")
	atomic.StoreInt32(&wrongEVM, 1)
	atomic.StoreInt32(&wrongKoinos, 1)
	if _, err := waitHealth(ctx, control, first.Process.Pid, func(h worker.Health) bool {
		return boundHealth(h, f) && h.Chains["evm"].Status == "network-unverified" && h.Chains["koinos"].Status == "network-unverified"
	}, logs); err != nil {
		return err
	}
	atomic.StoreInt32(&wrongEVM, 0)
	atomic.StoreInt32(&wrongKoinos, 0)
	if _, err := waitHealth(ctx, control, first.Process.Pid, func(h worker.Health) bool { return firstRunHealth(h, f) }, logs); err != nil {
		return err
	}
	report.Checks = append(report.Checks, "network-mismatch-pauses-and-recovers")
	beforeEVM := atomic.LoadInt32(&evmBatches)
	beforeKoinos := atomic.LoadInt32(&koinosBatches)
	if err := first.Process.Kill(); err != nil {
		return errors.New("candidate crash simulation failed")
	}
	_ = first.Wait()
	second, err := start()
	if err != nil {
		return errors.New("candidate failed to restart")
	}
	defer stopProcess(second)
	health, err := waitHealth(ctx, control, second.Process.Pid, func(h worker.Health) bool { return restartedHealth(h, f) }, logs)
	if err != nil {
		return err
	}
	if atomic.LoadInt32(&evmBatches) != beforeEVM || atomic.LoadInt32(&koinosBatches) != beforeKoinos {
		return errors.New("candidate replayed a durably checkpointed range")
	}
	if err := checkTransactions(ctx, client); err != nil {
		return errors.New("candidate did not retain synthetic transfers across restart")
	}
	report.Checks = append(report.Checks, "crash-restart-checkpoints-and-records-retained")
	var stopped map[string]bool
	if err := worker.Call(ctx, control, http.MethodPost, "/stop", &stopped, health); err != nil {
		return errors.New("candidate graceful stop refused")
	}
	if err := second.Wait(); err != nil {
		return errors.New("candidate did not stop cleanly")
	}
	report.Checks = append(report.Checks, "graceful-stop")
	if atomic.LoadInt32(&forbidden) != 0 {
		return errors.New("candidate requested a non-observation RPC method")
	}
	report.Checks = append(report.Checks, "only-read-rpc-methods")
	return nil
}
