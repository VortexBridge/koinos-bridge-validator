// vortex-operator is the private, keyless operator control plane. The legacy
// validator binary remains a separate process with a separate lifecycle.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vortex-operator:", err)
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("vortex-operator", flag.ContinueOnError)
	dir := flags.String("data", "", "private operator state directory (required)")
	instance := flags.String("instance", "", "local instance slot; omitted uses default (serve and token-path use the root)")
	listen := flags.String("listen", "127.0.0.1:3021", "loopback listen address")
	origins := flags.String("origins", "http://127.0.0.1:5173", "comma-separated exact trusted UI origins")
	workerBase := flags.String("worker-base", "", "private validator base directory for local registration")
	workerBinary := flags.String("worker-binary", "", "reviewed local validator executable")
	workerSHA := flags.String("worker-sha256", "", "reviewed validator executable digest")
	releaseFile := flags.String("release-file", "", "local signed release JSON")
	artifactFile := flags.String("artifact-file", "", "local artifact bytes to verify and stage")
	artifactPlatform := flags.String("artifact-platform", "", "platform named in signed release")
	candidateDigest := flags.String("release-digest", "", "exact staged release digest")
	checkerPath := flags.String("candidate-checker", "", "reviewed Linux candidate checker executable")
	checkerHash := flags.String("checker-sha256", "", "reviewed checker digest")
	backupFile := flags.String("backup-file", "", "absolute encrypted backup file path")
	restoreBase := flags.String("restore-base", "", "absolute new validator directory for restore")
	recipient := flags.String("recovery-recipient", "", "public age X25519 recovery recipient")
	identity := flags.String("recovery-identity-file", "", "private local age recovery identity file (restore only)")
	cryptoPath := flags.String("backup-crypto", "", "reviewed local backup crypto helper executable")
	cryptoHash := flags.String("backup-crypto-sha256", "", "reviewed backup crypto executable digest")
	backupDigest := flags.String("backup-digest", "", "exact recovered backup manifest digest")
	reviewNote := flags.String("review-note", "", "non-secret restore checkpoint/configuration review note")
	ethereumHeight := flags.String("review-ethereum-height", "", "exact restored Ethereum checkpoint in decimal")
	koinosHeight := flags.String("review-koinos-height", "", "exact restored Koinos checkpoint in decimal")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("--data is required; use a new private directory, separate from validator data")
	}
	command := "serve"
	if flags.NArg() > 0 {
		command = flags.Arg(0)
	}
	if flags.NArg() > 1 {
		return errors.New("provide one command; place all flags before it")
	}
	if command != "serve" && command != "status" && command != "token-path" && command != "worker-register" && command != "release-stage" && command != "candidate-test" && command != "backup-create" && command != "backup-restore" && command != "restore-review" && command != "instance-create" && command != "instances" && command != "doctor" && command != "worker-prepare" {
		return errors.New("commands: serve, status, token-path, worker-register, release-stage, candidate-test, backup-create, backup-restore, restore-review, instance-create, instances, doctor, worker-prepare")
	}
	s, err := operator.OpenStore(*dir)
	if err != nil {
		return err
	}
	defer s.Close()
	if command == "instance-create" {
		created, err := s.CreateInstance(*instance)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"id": *instance, "operatorInstanceId": created.InstanceID(), "state": "created", "mode": "observation-only"})
	}
	if command == "instances" {
		return json.NewEncoder(os.Stdout).Encode(s.LocalInstances())
	}
	if *instance != "" && *instance != "default" {
		if command == "serve" || command == "token-path" {
			return errors.New("serve and token-path use the root operator; select an instance in the console")
		}
		selected, ok := s.LocalInstance(*instance)
		if !ok {
			return errors.New("unknown local instance; create it using instance-create first")
		}
		s = selected
	}
	if command == "worker-prepare" {
		preparation, err := s.PrepareWorker(*workerBinary, *workerSHA)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(preparation)
	}
	if command == "doctor" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		report := s.Doctor(ctx)
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
		if report.Status != "checks-passed" {
			return errors.New("preflight needs attention; see the diagnostic report")
		}
		return nil
	}
	if command == "backup-create" || command == "backup-restore" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		provider := operator.CryptoProvider{Path: *cryptoPath, SHA256: *cryptoHash}
		var receipt operator.BackupReceipt
		if command == "backup-create" {
			receipt, err = s.CreateBackup(ctx, *workerBase, *backupFile, *recipient, provider)
		} else {
			receipt, err = operator.RestoreBackup(ctx, *backupFile, *restoreBase, *identity, provider)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(receipt)
	}
	if command == "restore-review" {
		evm, evmErr := strconv.ParseUint(*ethereumHeight, 10, 64)
		koinos, koinosErr := strconv.ParseUint(*koinosHeight, 10, 64)
		if evmErr != nil || koinosErr != nil {
			return errors.New("restore review requires both explicit decimal checkpoint heights")
		}
		result, err := operator.ReviewRestoreObservation(*workerBase, *backupDigest, *reviewNote, evm, koinos)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "candidate-test" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		result, err := s.TestCandidate(ctx, *candidateDigest, *artifactPlatform, *checkerPath, *checkerHash)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "release-stage" {
		release, err := operator.ReadSignedRelease(*releaseFile)
		if err != nil {
			return err
		}
		staged, err := s.StageRelease(release, *artifactPlatform, *artifactFile, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"digest": staged.Digest, "platform": staged.Platform, "artifactSha256": staged.Artifact.SHA256, "state": "artifact-verified", "installed": false})
	}
	if command == "worker-register" {
		if *workerBase == "" || *workerBinary == "" {
			return errors.New("worker-register requires --worker-base, --worker-binary and --worker-sha256 before the command")
		}
		_, err := s.RegisterWorker(*workerBase, *workerBinary, *workerSHA)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(s.WorkerStatus(context.Background()))
	}
	if command == "status" {
		revision, profiles, events := s.Summary()
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"revision": revision, "profiles": profiles, "events": events, "mode": "observation-only"})
	}
	token, err := s.Token()
	if err != nil {
		return err
	}
	if command == "token-path" {
		p, err := filepath.Abs(filepath.Join(*dir, "access-token"))
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return errors.New("invalid listen address")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("management must bind a literal loopback address; use an SSH tunnel for remote access")
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer l.Close()
	api := operator.NewServer(s, token, l.Addr().String(), strings.Split(*origins, ","))
	server := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	fmt.Printf("Private operator API: http://%s\nMode: observation-only; no signing keys loaded.\nAccess token file: %s\n", l.Addr(), filepath.Join(*dir, "access-token"))
	err = server.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
