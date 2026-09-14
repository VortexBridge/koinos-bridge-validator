package worker

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testNetworkBinding() NetworkBinding {
	id := append([]byte{0x12, 0x20}, make([]byte, 32)...)
	return NetworkBinding{1, "31337", base64.URLEncoding.EncodeToString(id), "0x1111111111111111111111111111111111111111", "1111111111111111111114oLvT2"}
}
func TestNetworkBindingCannotRelabelExistingState(t *testing.T) {
	dir := filepath.Join(privateTestDir(t), "control")
	b := testNetworkBinding()
	if err := CheckNetworkBinding(dir, b, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("read-only check created state")
	}
	if err := EnsureNetworkBinding(dir, b, true); err == nil {
		t.Fatal("adopted unbound checkpoint")
	}
	if err := EnsureNetworkBinding(dir, b, false); err != nil {
		t.Fatal(err)
	}
	if err := EnsureNetworkBinding(dir, b, true); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*NetworkBinding){
		func(b *NetworkBinding) { b.EVMNetworkID = "1" },
		func(b *NetworkBinding) {
			b.KoinosNetworkID = base64.URLEncoding.EncodeToString(append([]byte{0x12, 0x20}, []byte(strings.Repeat("x", 32))...))
		},
		func(b *NetworkBinding) { b.EVMContract = "0x2222222222222222222222222222222222222222" },
		func(b *NetworkBinding) { b.KoinosContract = "different" },
		func(b *NetworkBinding) { b.EVMNetworkID = ""; b.KoinosNetworkID = "" },
	} {
		changed := b
		mutate(&changed)
		if err := EnsureNetworkBinding(dir, changed, true); err == nil {
			t.Fatal("accepted route change")
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "network-binding.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureNetworkBinding(dir, b, false); err == nil {
		t.Fatal("replaced invalid marker")
	}
	for _, id := range []string{"0", "01", "+1", "0x1", "-1", strings.Repeat("9", 79)} {
		if ValidNetworkID("evm", id) {
			t.Fatal(id)
		}
	}
	for _, id := range []string{"", "AA==", strings.TrimRight(b.KoinosNetworkID, "=")} {
		if ValidNetworkID("koinos", id) {
			t.Fatal(id)
		}
	}
}

func TestSurvivingTransferDatabasePreventsNewNetworkBinding(t *testing.T) {
	base := privateTestDir(t)
	if err := os.MkdirAll(filepath.Join(base, "bridge", "ethereum_transactions"), 0700); err != nil {
		t.Fatal(err)
	}
	exists, err := HasValidatorData(base)
	if err != nil || !exists {
		t.Fatal("lost metadata hid surviving transfer state")
	}
	if err := EnsureNetworkBinding(filepath.Join(base, "bridge", ".operator"), testNetworkBinding(), exists); err == nil {
		t.Fatal("rebound surviving transfer data")
	}
}
