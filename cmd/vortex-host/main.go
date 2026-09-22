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
	root := f.String("root", "", "private installation directory")
	instance := f.String("instance", "", "local installation identity")
	bundle := f.String("bundle", "", "private uncompressed tar")
	release := f.String("release", "", "signed operator bundle release")
	trust := f.String("trust", "", "local publisher policy")
	approval := f.String("approval", "", "local approval record")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 1 {
		return errors.New("use install, uninstall, doctor or run with flags before the command")
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
