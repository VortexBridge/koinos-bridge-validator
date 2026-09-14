// vortex-candidate-check is a fixed synthetic runtime smoke suite. It runs only
// inside the restricted candidate container and never consumes host config/keys.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

type Report struct {
	SchemaVersion  int      `json:"schemaVersion"`
	Scope          string   `json:"scope"`
	ArtifactSHA256 string   `json:"artifactSha256"`
	State          string   `json:"state"`
	Checks         []string `json:"checks"`
	Error          string   `json:"error,omitempty"`
}

func main() {
	report := Report{SchemaVersion: 1, Scope: "isolated-observation-smoke-v1", State: "failed", Checks: []string{}}
	if err := run(&report); err != nil {
		report.Error = err.Error()
	} else {
		report.State = "smoke-passed"
	}
	json.NewEncoder(os.Stdout).Encode(report)
	if report.State != "smoke-passed" {
		os.Exit(1)
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	var forbidden, logReads int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	rpc := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req) != nil {
			w.WriteHeader(400)
			return
		}
		var result interface{}
		switch req.Method {
		case "eth_blockNumber":
			result = "0x6"
		case "eth_getLogs":
			atomic.AddInt32(&logReads, 1)
			result = []interface{}{}
		case "chain.get_head_info":
			result = map[string]interface{}{"last_irreversible_block": "0", "head_topology": map[string]interface{}{"height": "0", "id": "0x12200000000000000000000000000000000000000000000000000000000000000000"}}
		default:
			atomic.AddInt32(&forbidden, 1)
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	})}
	go rpc.Serve(listener)
	defer rpc.Close()
	rpcURL := "http://" + listener.Addr().String()
	base := "/work/validator"
	if err := os.Mkdir(base, 0700); err != nil {
		return err
	}
	cfg := fmt.Sprintf("bridge:\n  instance-id: isolated-candidate\n  log-level: error\n  api-url: 127.0.0.1:13000\n  ethereum-rpc: %s\n  koinos-rpc: %s\n  ethereum-contract: '0x1111111111111111111111111111111111111111'\n  koinos-contract: '1111111111111111111114oLvT2'\n  ethereum-confirmations: 1\n  ethereum-polling-time: 20\n  koinos-polling-time: 20\n  ethereum-pk-file: /production-keys-not-mounted/evm\n  koinos-pk-file: /production-keys-not-mounted/koinos\n", rpcURL, rpcURL)
	if err := os.WriteFile(filepath.Join(base, "config.yml"), []byte(cfg), 0600); err != nil {
		return err
	}
	start := func() (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, "/candidate/validator", "--basedir", base, "--observe-only")
		cmd.Env = []string{"HOME=/work", "PATH=/usr/bin:/bin"}
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		return cmd, cmd.Start()
	}
	control := filepath.Join(base, "bridge", ".operator")
	wait := func(pid int) (worker.Health, error) {
		for {
			var health worker.Health
			if worker.Call(ctx, control, "GET", "/health", &health) == nil && health.PID == pid && health.Mode == "observation-only" && health.EVMAddress == "" && health.KoinosAddress == "" && health.Chains["evm"].Height == 5 && health.Chains["evm"].Status == "observed" && health.Chains["koinos"].Status == "observed" {
				return health, nil
			}
			select {
			case <-ctx.Done():
				return health, errors.New("candidate did not pass independent health/checkpoint check")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	first, err := start()
	if err != nil {
		return errors.New("candidate failed to execute")
	}
	defer func() { first.Process.Kill(); first.Wait() }()
	if _, err := wait(first.Process.Pid); err != nil {
		return err
	}
	report.Checks = append(report.Checks, "keyless-start-and-both-chain-observation")
	client := &http.Client{Timeout: time.Second}
	response, err := client.Post("http://127.0.0.1:13000/SubmitSignature", "application/json", nil)
	if err != nil {
		return errors.New("candidate signature endpoint unavailable")
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		return errors.New("candidate allows signature exchange in observation mode")
	}
	report.Checks = append(report.Checks, "signature-exchange-refused")
	duplicate, err := start()
	if err == nil {
		if duplicate.Wait() == nil {
			return errors.New("duplicate candidate instance admitted")
		}
	}
	report.Checks = append(report.Checks, "duplicate-process-excluded")
	beforeRestart := atomic.LoadInt32(&logReads)
	first.Process.Kill()
	first.Wait()
	second, err := start()
	if err != nil {
		return errors.New("candidate failed to restart")
	}
	defer func() { second.Process.Kill(); second.Wait() }()
	health, err := wait(second.Process.Pid)
	if err != nil {
		return err
	}
	if atomic.LoadInt32(&logReads) != beforeRestart {
		return errors.New("candidate replayed a durably checkpointed range")
	}
	report.Checks = append(report.Checks, "crash-restart-checkpoint-retained")
	var result map[string]bool
	if err := worker.Call(ctx, control, "POST", "/stop", &result, health); err != nil {
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
