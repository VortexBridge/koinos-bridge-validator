package managed

import (
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
