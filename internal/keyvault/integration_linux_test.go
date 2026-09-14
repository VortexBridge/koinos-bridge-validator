//go:build linux
// +build linux

package keyvault_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	koinos "github.com/koinos/koinos-util-golang"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

var keyTool = flag.String("key-tool", "", "compiled Linux vortex-keys for isolated integration test")
var validatorTool = flag.String("validator-tool", "", "compiled Linux validator for isolated integration test")

func pipeSecret(t *testing.T, cmd *exec.Cmd, secret []byte) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.ExtraFiles = []*os.File{r}
	if _, err := w.Write(append(append([]byte{}, secret...), '\n')); err != nil {
		t.Fatal(err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
}

func TestLinuxEncryptedKeyCommandsAndSigningRuntime(t *testing.T) {
	if *keyTool == "" || *validatorTool == "" {
		t.Skip("supply compiled Linux tools for isolated runtime acceptance")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run acceptance as a dedicated non-root user")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	password := []byte("disposable-linux-fixture-passphrase")
	defer keyvault.Clear(password)
	path := filepath.Join(dir, "keys.vault")
	run := func(secret []byte, args ...string) ([]byte, error) {
		cmd := exec.Command(*keyTool, args...)
		pipeSecret(t, cmd, secret)
		out, err := cmd.CombinedOutput()
		if bytes.Contains(out, password) {
			t.Fatal("secret reached command output")
		}
		return out, err
	}
	created, err := run(password, "--vault", path, "--passphrase-fd", "3", "generate")
	if err != nil {
		t.Fatalf("create: %v %s", err, created)
	}
	var public keyvault.Public
	if json.Unmarshal(created, &public) != nil || public.EVMAddress == "" || public.KoinosAddress == "" {
		t.Fatal("missing public identities")
	}
	encrypted, err := os.ReadFile(path)
	if err != nil || bytes.Contains(encrypted, password) {
		t.Fatal("missing or plaintext vault")
	}
	if _, err := run(password, "--vault", path, "--passphrase-fd", "3", "generate"); err == nil {
		t.Fatal("overwrote an existing vault")
	}
	inspected, err := run(password, "--vault", path, "--passphrase-fd", "3", "inspect")
	if err != nil || !bytes.Equal(created, inspected) {
		t.Fatal("restart inspection changed identities")
	}
	if _, err := run([]byte("incorrect-fixture-passphrase"), "--vault", path, "--passphrase-fd", "3", "inspect"); err == nil {
		t.Fatal("wrong passphrase unlocked vault")
	}
	// A regular file must never serve as the unlock-password descriptor.
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(*keyTool, "--vault", path, "--passphrase-fd", "3", "inspect")
	cmd.ExtraFiles = []*os.File{file}
	_, err = cmd.CombinedOutput()
	file.Close()
	if err == nil {
		t.Fatal("accepted password file descriptor")
	}
	fifo := filepath.Join(dir, "named-fifo")
	if syscall.Mkfifo(fifo, 0600) != nil {
		t.Fatal("cannot create FIFO fixture")
	}
	file, err = os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(*keyTool, "--vault", path, "--passphrase-fd", "3", "inspect")
	cmd.ExtraFiles = []*os.File{file}
	_, err = cmd.CombinedOutput()
	file.Close()
	if err == nil {
		t.Fatal("accepted named FIFO secret input")
	}
	if _, _, err := keyvault.Unlock(path, "0x1111111111111111111111111111111111111111", public.KoinosAddress, func() ([]byte, error) { return append([]byte{}, password...), nil }); err == nil {
		t.Fatal("substituted vault identity")
	}
	// The password callback is not called for an unreadable encrypted file.
	called := false
	_, _, err = keyvault.Unlock(path+"-missing", "", "", func() ([]byte, error) { called = true; return nil, nil })
	if err == nil || called {
		t.Fatal("requested a password before checking the vault")
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dumpable != 0 {
		t.Fatal("process remained dumpable after vault unlock")
	}
	var core unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_CORE, &core) != nil || core.Cur != 0 || core.Max != 0 {
		t.Fatal("process core limits remained enabled")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	locked := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmLck:") {
			fields := strings.Fields(line)
			locked = len(fields) >= 2 && fields[1] != "0"
		}
	}
	swapInventory, err := os.ReadFile("/proc/swaps")
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.Split(bytes.TrimSpace(swapInventory), []byte("\n"))) > 1 && !locked {
		t.Fatal("process memory was not locked despite active swap")
	}
	keys, _, err := keyvault.Unlock(path, public.EVMAddress, public.KoinosAddress, func() ([]byte, error) { return append([]byte{}, password...), nil })
	if err != nil {
		t.Fatal(err)
	}
	evmRaw := keys.EVM.D.FillBytes(make([]byte, 32))
	secrets := [][]byte{password, evmRaw, append([]byte{}, keys.Koinos...), []byte(hex.EncodeToString(evmRaw)), []byte(koinos.EncodeWIF(keys.Koinos, true, 128))}
	keys.Close()
	defer func() {
		for _, secret := range secrets {
			keyvault.Clear(secret)
		}
	}()
	leaks := func(data []byte) bool {
		for _, secret := range secrets {
			if bytes.Contains(data, secret) {
				return true
			}
		}
		return false
	}
	// Exercise the actual controlling-terminal path, including echo suppression
	// and confirmation. The imported identities must match the generated vault.
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	ptyNumber, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptyNumber), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	importedPath := filepath.Join(dir, "imported.vault")
	importCmd := exec.Command(*keyTool, "--vault", importedPath, "import")
	importCmd.Stdin = slave
	importCmd.Stdout = slave
	importCmd.Stderr = slave
	importCmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := importCmd.Start(); err != nil {
		slave.Close()
		t.Fatal(err)
	}
	slave.Close()
	t.Cleanup(func() { importCmd.Process.Kill() })
	chunks := make(chan []byte)
	ptyStop := make(chan struct{})
	defer close(ptyStop)
	go func() {
		defer close(chunks)
		for {
			buf := make([]byte, 4096)
			n, err := master.Read(buf)
			if n > 0 {
				select {
				case chunks <- buf[:n]:
				case <-ptyStop:
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	transcript := []byte{}
	exchange := func(prompt string, value []byte) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for !bytes.Contains(transcript, []byte(prompt)) {
			select {
			case chunk, ok := <-chunks:
				if !ok {
					t.Fatal("terminal closed before prompt")
				}
				transcript = append(transcript, chunk...)
			case <-deadline:
				t.Fatal("terminal prompt timed out")
			}
		}
		if _, err := master.Write(append(append([]byte{}, value...), '\n')); err != nil {
			t.Fatal(err)
		}
	}
	exchange("Existing EVM private key (64 hexadecimal characters):", secrets[3])
	exchange("Existing Koinos private key (WIF):", secrets[4])
	exchange("Vault passphrase:", password)
	exchange("Repeat vault passphrase:", password)
	terminalTimeout := time.After(8 * time.Second)
	reading := true
	for reading {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				reading = false
			} else {
				transcript = append(transcript, chunk...)
			}
		case <-terminalTimeout:
			t.Fatal("terminal import did not complete")
		}
	}
	if err := importCmd.Wait(); err != nil {
		t.Fatal("interactive import failed", err)
	}
	if leaks(transcript) {
		t.Fatal("hidden terminal echoed secret input")
	}
	importedKeys, importedPublic, err := keyvault.Unlock(importedPath, public.EVMAddress, public.KoinosAddress, func() ([]byte, error) { return append([]byte{}, password...), nil })
	if err != nil {
		t.Fatal("imported vault cannot unlock", err)
	}
	importedKeys.Close()
	if importedPublic.VaultSHA256 == public.VaultSHA256 {
		t.Fatal("import reused ciphertext randomness")
	}

	network := "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid RPC request")
			return
		}
		var result interface{}
		switch request.Method {
		case "eth_chainId":
			result = "0x7a69"
		case "chain.get_chain_id":
			result = map[string]string{"chain_id": network}
		case "eth_blockNumber":
			result = "0x2"
		case "eth_getLogs":
			result = []interface{}{}
		case "chain.get_head_info":
			result = map[string]interface{}{"last_irreversible_block": "0", "head_topology": map[string]string{"height": "0", "id": "0x12200000000000000000000000000000000000000000000000000000000000000000"}}
		default:
			t.Errorf("unexpected method %s", request.Method)
			http.Error(w, "disallowed", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	defer rpc.Close()
	makeConfig := func(id string, observer bool) string {
		base := filepath.Join(dir, id)
		if err := os.Mkdir(base, 0700); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		listener.Close()
		cfg := util.YamlConfig{Bridge: util.BridgeConfig{InstanceID: id, LogLevel: "error", ApiUrl: addr, EthereumRpc: rpc.URL, KoinosRpc: rpc.URL, EthereumNetworkID: "31337", KoinosNetworkID: network, EthereumContract: "0x1111111111111111111111111111111111111111", KoinosContract: "1111111111111111111114oLvT2", EthereumConfirmations: 1, EthereumPollingTime: 25, KoinosPollingTime: 25, SigningVaultFile: path, EthereumSignerAddress: public.EVMAddress, KoinosSignerAddress: public.KoinosAddress}}
		if observer {
			cfg.Bridge.SigningVaultFile = path + "-does-not-exist"
		}
		data, err := yaml.Marshal(cfg)
		if err != nil || os.WriteFile(filepath.Join(base, "config.yml"), data, 0600) != nil {
			t.Fatal("cannot save synthetic config")
		}
		return base
	}
	// User config path is disposable, so same-user identity locks cannot touch a
	// real operator's configuration. Docker also isolates its home and network.
	runWorker := func(base string, observer bool, secret []byte) (*exec.Cmd, *bytes.Buffer, chan error) {
		args := []string{"--basedir", base, "--unlock-passphrase-fd", "3"}
		if observer {
			args = append(args, "--observe-only")
		}
		cmd := exec.Command(*validatorTool, args...)
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+filepath.Join(dir, "user-config"))
		pipeSecret(t, cmd, secret)
		output := &bytes.Buffer{}
		cmd.Stdout = output
		cmd.Stderr = output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() { cmd.Process.Kill() })
		return cmd, output, done
	}
	for _, observer := range []bool{true, false} {
		base := makeConfig(fmt.Sprintf("worker-%t", observer), observer)
		cmd, output, done := runWorker(base, observer, password)
		control := filepath.Join(base, "bridge", ".operator")
		var health worker.Health
		deadline := time.Now().Add(15 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			select {
			case err := <-done:
				t.Fatalf("worker exited: %v %s", err, output.String())
			default:
			}
			if worker.Call(context.Background(), control, "GET", "/health", &health) == nil && health.Chains["evm"].Status == "observed" && health.Chains["koinos"].Status == "observed" {
				ready = true
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		if !ready {
			t.Fatal("worker did not become healthy")
		}
		if observer {
			unread, err := io.ReadAll(cmd.ExtraFiles[0])
			if err != nil || !bytes.Equal(unread, append(append([]byte{}, password...), '\n')) {
				t.Fatal("observer consumed unlock pipe")
			}
			if health.Mode != "observation-only" || health.EVMAddress != "" || health.KoinosAddress != "" {
				t.Fatal("observer loaded keys")
			}
		} else {
			if health.EVMAddress != public.EVMAddress || health.KoinosAddress != public.KoinosAddress {
				t.Fatal("worker used different identities")
			}
			proof, err := worker.CallSigningProof(context.Background(), control, strings.Repeat("a", 64), health)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := worker.SigningProofDigest(proof.Challenge)
			if err != nil {
				t.Fatal(err)
			}
			evm, evmErr := util.RecoverEthereumAddressFromSignature(proof.EVMSignature, digest)
			native, nativeErr := util.RecoverKoinosAddressFromSignature(proof.KoinosSignature, digest)
			if evmErr != nil || nativeErr != nil || !strings.EqualFold(evm, public.EVMAddress) || native != public.KoinosAddress {
				t.Fatal("unlocked runtime did not prove both signing keys")
			}
			// The Linux kernel confirms the running worker's core limit is zero.
			limits, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", health.PID))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, line := range strings.Split(string(limits), "\n") {
				if strings.HasPrefix(line, "Max core file size") {
					fields := strings.Fields(line)
					found = len(fields) >= 6 && fields[4] == "0" && fields[5] == "0"
				}
			}
			if !found {
				t.Fatal("running signer did not disable core dumps")
			}
		}
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("worker shutdown failed", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not stop")
		}
		if leaks(output.Bytes()) {
			t.Fatal("secret reached worker output")
		}
	}
	badBase := makeConfig("wrong-password", false)
	_, output, done := runWorker(badBase, false, []byte("wrong-synthetic-passphrase"))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("worker accepted bad password")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("bad password did not terminate startup")
	}
	if bytes.Contains(output.Bytes(), password) {
		t.Fatal("startup failure exposed password")
	}
	if _, err := os.Lstat(filepath.Join(badBase, "bridge", "metadata")); !os.IsNotExist(err) {
		t.Fatal("opened transaction stores before successful unlock")
	}
	// Files created by this workflow contain no plaintext password. Public
	// identities and encrypted vault remain inspectable for enrollment/recovery.
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err == nil && leaks(data) {
			t.Errorf("plaintext secret in generated file")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
