//go:build !linux
// +build !linux

package keyvault

import (
	"path/filepath"
	"testing"
)

func TestUnsupportedHostDoesNotRequestSecrets(t *testing.T) {
	called := false
	input := func() ([]byte, error) { called = true; return []byte("should never request this"), nil }
	path := filepath.Join(t.TempDir(), "vault")
	if _, err := Create(path, nil, nil, input); err == nil {
		t.Fatal("generated keys without supported host protection")
	}
	if _, _, err := Unlock(path, "", "", input); err == nil {
		t.Fatal("unlocked without supported host protection")
	}
	if called {
		t.Fatal("requested secret on unsupported host")
	}
}
