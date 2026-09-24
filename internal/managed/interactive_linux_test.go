//go:build linux
// +build linux

package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type trackedCommands struct {
	io.Reader
	closed           bool
	readBeforeUnlock *bool
	unlocked         *bool
}

func (r *trackedCommands) Read(b []byte) (int, error) {
	if !*r.unlocked {
		*r.readBeforeUnlock = true
	}
	return r.Reader.Read(b)
}
func (r *trackedCommands) Close() error { r.closed = true; return nil }
func TestLinuxInteractiveBothDirectionsAndStop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root Linux required")
	}
	root := dir(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "user-config"))
	vault, p := makeVault(t, root)
	v, forward, reverse, _ := routeFixture(t)
	s, e := Open(filepath.Join(root, "session"), p, v)
	if e != nil {
		t.Fatal(e)
	}
	unlocked, premature := false, false
	commands := &trackedCommands{Reader: strings.NewReader("status\nsign " + EVMToKoinos + "/" + forward.observation.ID + "\nsign " + KoinosToEVM + "/" + reverse.observation.ID + "\ndrain\nstatus\nstop\n"), unlocked: &unlocked, readBeforeUnlock: &premature}
	var output bytes.Buffer
	e = RunInteractive(context.Background(), s, vault, commands, &output, func() ([]byte, error) { unlocked = true; return password() })
	if e != nil || premature || !commands.closed || s.keys != nil || !s.closed || len(s.Status().Operations) != 2 {
		t.Fatal("interactive lifecycle failed", e)
	}
	decoder := json.NewDecoder(&output)
	families := map[string]bool{}
	drainRejected, activeAfterDrain := false, false
	for {
		var record map[string]interface{}
		e := decoder.Decode(&record)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if family, ok := record["family"].(string); ok {
			families[family] = record["signature"] != ""
		}
		if message, ok := record["error"].(string); ok && strings.Contains(message, "drain blocked") {
			drainRejected = true
		}
		if drainRejected && record["state"] == "active" && record["unfinalizedRetainedOperations"] == float64(2) {
			activeAfterDrain = true
		}
	}
	if !families["evm"] || !families["koinos"] || !drainRejected || !activeAfterDrain {
		t.Fatal("both signatures and blocked-drain continuation required")
	}
}

type cancelOnOutput struct{ cancel context.CancelFunc }

func (w cancelOnOutput) Write(b []byte) (int, error) { w.cancel(); return len(b), nil }
func TestLinuxInteractiveCancellationClosesKeysAndInput(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root Linux required")
	}
	root := dir(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "user-config"))
	vault, p := makeVault(t, root)
	s, e := Open(filepath.Join(root, "session"), p, &fixtureVerifier{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	if e = RunInteractive(ctx, s, vault, reader, cancelOnOutput{cancel}, password); e != nil {
		t.Fatal(e)
	}
	if s.keys != nil || !s.closed {
		t.Fatal("cancelled interface retained keys")
	}
	if _, e = writer.Write([]byte("status\n")); e == nil {
		t.Fatal("input pipe remained open")
	}
}
