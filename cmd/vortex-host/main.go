package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/managed"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

func read(path string, v interface{}) error {
	b, e := worker.ReadPrivateFile(path, 65536)
	if e != nil {
		return e
	}
	return host.JSON(b, v)
}
func run() error {
	f := flag.NewFlagSet("vortex-host", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	hostProfile := f.String("host-profile", "standard", "host review profile")
	config := f.String("config", "", "private managed runtime configuration")
	root := f.String("root", "", "private installation directory")
	instance := f.String("instance", "", "local installation identity")
	bundle := f.String("bundle", "", "private uncompressed tar")
	release := f.String("release", "", "signed operator bundle release")
	trust := f.String("trust", "", "local publisher policy")
	validatorRelease := f.String("validator-release", "", "signed validator executable release")
	candidateResult := f.String("candidate-result", "", "private isolated runner result")
	approval := f.String("approval", "", "local approval record")
	previousReview := f.String("previous-host-review", "", "private signed review of the prior artifact on this host")
	previousPolicy := f.String("previous-policy", "", "private public-identity policy for the retired signer")
	previousJournal := f.String("previous-journal", "", "private journal backup for the retired signer")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 1 {
		return errors.New("use install, uninstall, doctor, authorize, qualify, review-request, recover-retired, upgrade-state, activate or run with flags before the command")
	}
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return errors.New("host commands require a dedicated non-root Linux user")
	}
	if !filepath.IsAbs(*root) {
		return errors.New("absolute private installation root required")
	}
	if f.Arg(0) == "doctor" {

		i, e := host.Read(*root)
		if e != nil {
			return e
		}
		if e = host.Verify(*root, i); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"installed": true, "enabled": i.Enabled, "version": i.Version, "managedSigning": false, "notice": "Artifact verified. Public signing is blocked; use the operator doctor for configured observers."})

	}

	if f.Arg(0) == "authorize" {
		var t operator.ReleaseTrust
		if e := read(*trust, &t); e != nil {
			return e
		}
		i, e := host.Authorize(*root, t, *instance, time.Now())
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"instance": i.Instance, "version": i.Version, "releaseDigest": i.Digest, "releaseApproved": true, "managedSigning": false, "notice": "Local release approval and exact artifact verified; chain, custody and recovery gates still required."})
	}
	if f.Arg(0) == "qualify" {
		var t operator.ReleaseTrust
		var release operator.SignedRelease
		var result operator.CandidateResult
		if e := read(*trust, &t); e != nil {
			return e
		}
		if e := read(*validatorRelease, &release); e != nil {
			return e
		}
		if e := read(*candidateResult, &result); e != nil {
			return e
		}
		if _, e := managed.ImportCandidate(*root, *instance, t, release, result, time.Now()); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"candidateQualified": true, "managedSigning": false, "notice": "Exact installed validator and checker qualified from local observation evidence; host, chain, custody and recovery gates still required."})
	}
	if f.Arg(0) == "review-request" {
		var t operator.ReleaseTrust
		if e := read(*trust, &t); e != nil {
			return e
		}
		if _, e := managed.CreateHostReviewRequest(*root, *config, t, *hostProfile, time.Now()); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"reviewRequested": true, "approved": false, "managedSigning": false, "notice": "Unsigned private host-review-request.json prepared; independent control review and signature still required."})
	}
	lease, e := worker.Acquire(*root, "host.lock")
	if e != nil {
		return e
	}
	defer lease.Close()
	switch f.Arg(0) {
	case "install":
		var s operator.SignedRelease
		var t operator.ReleaseTrust
		var a operator.ReleaseApproval
		if e = read(*release, &s); e != nil {
			return e
		}
		if e = read(*trust, &t); e != nil {
			return e
		}
		if e = read(*approval, &a); e != nil {
			return e
		}
		b, e := worker.ReadPrivateFile(*bundle, host.MaxBundle)
		if e != nil {
			return e
		}
		i, e := host.Install(*root, *instance, b, s, t, a, time.Now())
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(i)
	case "upgrade-state":
		var previous managed.Policy
		var review managed.SignedHostReview
		if !filepath.IsAbs(*previousPolicy) || !filepath.IsAbs(*previousReview) {
			return errors.New("absolute private upgrade input paths required")
		}
		if e = read(*previousPolicy, &previous); e != nil {
			return e
		}
		if e = read(*previousReview, &review); e != nil {
			return e
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer cancel()
		session, _, e := managed.PrepareArtifactUpgrade(ctx, *root, *config, *trust, previous, review)
		if e != nil {
			return e
		}
		defer session.Close()
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"retainedOperations": len(session.Status().Operations), "managedSigning": false, "notice": "Artifact transition reconciled on the same reviewed host. Existing signatures retained; vault remains locked."})
	case "recover-retired":
		var previous managed.Policy
		var source managed.Journal
		if !filepath.IsAbs(*previousPolicy) || !filepath.IsAbs(*previousJournal) {
			return errors.New("absolute private recovery input paths required")
		}
		if e = read(*previousPolicy, &previous); e != nil {
			return e
		}
		raw, e := worker.ReadPrivateFile(*previousJournal, 4<<20)
		if e != nil {
			return e
		}
		if e = host.JSON(raw, &source); e != nil {
			return e
		}
		if source.Schema == 1 && source.PolicySHA256 == managed.Digest(previous) {
			if e = managed.RecoveryHintPreflight(*root, *config, source); e != nil {
				return e
			}
		}
		session, _, e := managed.PrepareRuntime(*root, *config, *trust)
		if e != nil {
			return e
		}
		defer session.Close()
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer cancel()
		if e = session.ImportRetiredJournal(ctx, previous, source); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"recoveredOperations": len(session.Status().Operations), "managedSigning": false, "notice": "Public operations reconciled after retirement of both previous identities. Vault remains locked; activation repeats live checks."})
	case "activate":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer cancel()
		session, vault, e := managed.PrepareRuntime(*root, *config, *trust)
		if e != nil {
			return e
		}
		return managed.RunInteractive(ctx, session, vault, os.Stdin, os.Stdout, func() ([]byte, error) { return keyvault.ReadSecret(-1, "Unlock local validator vault") })
	case "uninstall":
		return host.Uninstall(*root)
	case "run":
		i, e := host.Read(*root)
		if e != nil {
			return e
		}
		if !i.Enabled {
			return errors.New("installation disabled")
		}
		if e = host.Verify(*root, i); e != nil {
			return e
		}
		// Never launch the legacy signer here. The bundled operator starts keyless.
		cmd := exec.Command(filepath.Join(*root, "releases", i.Artifact, "vortex-operator"), "--data", filepath.Join(*root, "state"), "serve")
		protectChild(cmd)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME")}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if e = cmd.Start(); e != nil {
			return errors.New("operator could not start")
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case e = <-done:
			if e != nil {
				return errors.New("operator exited unsuccessfully")
			}
			return nil
		case <-ctx.Done():
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
			return nil
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			return errors.New("operator required forced termination; inspect state before restart")
		}
	default:
		return errors.New("unsupported host command")
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
