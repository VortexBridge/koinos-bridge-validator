package keyvault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultNodeInteroperability(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node is required for independent AES-GCM/scrypt interop")
	}
	raw := syntheticKeys(t)
	defer Clear(raw)
	password := []byte("synthetic-interop-passphrase")
	encrypted, err := seal(raw, password)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"raw": hex.EncodeToString(raw), "encrypted": hex.EncodeToString(encrypted), "password": string(password)})
	defer Clear(input)
	cmd := exec.Command("node", "testdata/interoperability.cjs")
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal("independent Node decryption failed", err)
	}
	other, err := hex.DecodeString(string(out))
	if err != nil {
		t.Fatal("invalid Node ciphertext")
	}
	keys, _, err := open(other, password)
	if err != nil {
		t.Fatal("Go could not decrypt independently encrypted bundle", err)
	}
	defer keys.Close()
	if !bytes.Equal(keys.EVM.D.FillBytes(make([]byte, 32)), raw[:32]) || !bytes.Equal(keys.Koinos, raw[32:]) {
		t.Fatal("independent implementation changed keys")
	}
}

func syntheticKeys(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 64)
	for {
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		keys, _, err := decodeKeys(raw)
		if err == nil {
			keys.Close()
			return raw
		}
	}
}

func TestVaultAuthenticatedRoundTrip(t *testing.T) {
	raw := syntheticKeys(t)
	defer Clear(raw)
	password := []byte("synthetic-test-passphrase-only")
	encrypted, err := seal(raw, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) != fileSize || bytes.Contains(encrypted, raw[:32]) || bytes.Contains(encrypted, password) {
		t.Fatal("invalid ciphertext envelope")
	}
	keys, public, err := open(encrypted, password)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	if !bytes.Equal(keys.EVM.D.FillBytes(make([]byte, 32)), raw[:32]) || !bytes.Equal(keys.Koinos, raw[32:]) || public.EVMAddress == "" || public.KoinosAddress == "" || len(public.VaultSHA256) != 64 {
		t.Fatal("identity did not survive encryption")
	}
	second, err := seal(raw, password)
	if err != nil || bytes.Equal(encrypted, second) {
		t.Fatal("salt/nonce were not randomized")
	}
	for _, index := range []int{0, len(magic), len(magic) + 32, len(encrypted) - 1} {
		changed := append([]byte{}, encrypted...)
		changed[index] ^= 1
		if key, _, err := open(changed, password); err == nil || key != nil {
			t.Fatal("accepted tampering at", index)
		}
	}
	if key, _, err := open(encrypted, []byte("incorrect-test-passphrase")); err == nil || key != nil {
		t.Fatal("accepted wrong password")
	}
	for _, data := range [][]byte{nil, encrypted[:len(encrypted)-1], append(encrypted, 0)} {
		if key, _, err := open(data, password); err == nil || key != nil {
			t.Fatal("accepted invalid envelope length")
		}
	}
}

func TestVaultInputBoundsAndPrivateFile(t *testing.T) {
	raw := syntheticKeys(t)
	defer Clear(raw)
	for _, password := range [][]byte{nil, []byte("too short"), bytes.Repeat([]byte{1}, maxPassphrase+1)} {
		if _, err := seal(raw, password); err == nil {
			t.Fatal("accepted weak or oversized password")
		}
	}
	for _, invalid := range [][]byte{nil, make([]byte, 64), bytes.Repeat([]byte{255}, 64)} {
		if _, err := seal(invalid, []byte("synthetic-test-passphrase")); err == nil {
			t.Fatal("accepted invalid private scalar")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, fileSize), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile("relative"); err == nil {
		t.Fatal("accepted relative path")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path); err == nil {
		t.Fatal("accepted public file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(link); err == nil {
		t.Fatal("followed vault symlink")
	}
	if _, err := readFile(dir); err == nil {
		t.Fatal("read a directory")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", fileSize+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path); err == nil {
		t.Fatal("accepted oversized vault")
	}
}
