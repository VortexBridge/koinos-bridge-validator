package managed

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func TestRuntimeRejectsReadinessFlagsAndPublicRoutes(t *testing.T) {
	root := dir(t)
	path := filepath.Join(root, "runtime.json")
	if e := os.WriteFile(path, []byte(`{"schemaVersion":1,"hostSecure":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if s, _, e := PrepareRuntime(root, path, filepath.Join(root, "trust.json")); e == nil || s != nil {
		t.Fatal("caller-supplied readiness accepted")
	}
	v, p, _, _ := chainFixture(t)
	v.koinos.live.Profile.NetworkID = "EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA=="
	cfg := RuntimeConfig{Schema: 1, Instance: p.Instance, EVM: operator.Binding{Profile: v.evm.binding.Profile, RPC: "http://127.0.0.1:1"}, Koinos: v.koinos.live, Replica: "http://127.0.0.1:2", Vault: filepath.Join(root, "vault")}
	if e := host.Atomic(root, "runtime.json", cfg); e != nil {
		t.Fatal(e)
	}
	if s, _, e := PrepareRuntime(root, path, filepath.Join(root, "trust.json")); e == nil || s != nil {
		t.Fatal("public runtime prepared")
	}
	if _, e := os.Stat(filepath.Join(root, "managed-session")); !os.IsNotExist(e) {
		t.Fatal("rejected config created signer state")
	}
}

func TestRuntimeHintsAreFreshPrivateAndCannotOverridePinnedHints(t *testing.T) {
	root := dir(t)
	ctx := context.Background()
	if _, err := locateRuntimeOperation(ctx, root, nil, "tx:0"); err == nil {
		t.Fatal("missing hint accepted")
	}
	if err := host.Atomic(root, "operation-hints.json", map[string]uint64{"tx:0": 12}); err != nil {
		t.Fatal(err)
	}
	if h, err := locateRuntimeOperation(ctx, root, nil, "tx:0"); err != nil || h != 12 {
		t.Fatal(h, err)
	}
	if err := host.Atomic(root, "operation-hints.json", map[string]uint64{"tx:0": 13}); err != nil {
		t.Fatal(err)
	}
	if h, err := locateRuntimeOperation(ctx, root, nil, "tx:0"); err != nil || h != 13 {
		t.Fatal("stale hint", h, err)
	}
	if h, err := locateRuntimeOperation(ctx, root, map[string]uint64{"tx:0": 14}, "tx:0"); err != nil || h != 14 {
		t.Fatal("pinned hint overridden", h, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := locateRuntimeOperation(cancelled, root, nil, "tx:0"); err == nil {
		t.Fatal("cancelled lookup accepted")
	}
	path := filepath.Join(root, "operation-hints.json")
	for _, raw := range []string{`null`, `{"tx:0":0}`, `{"tx:0":-1}`, `{"tx:0":13,"tx:0":14}`, `{"other":14}`, `{"tx:0":"14"}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := locateRuntimeOperation(ctx, root, nil, "tx:0"); err == nil {
			t.Fatalf("invalid hint accepted: %s", raw)
		}
	}
	if err := os.WriteFile(path, []byte(`{"tx:0":13}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := locateRuntimeOperation(ctx, root, nil, "tx:0"); err == nil {
		t.Fatal("public hint file accepted")
	}
}
