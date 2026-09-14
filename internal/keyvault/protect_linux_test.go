//go:build linux
// +build linux

package keyvault

import (
	"bytes"
	"strings"
	"testing"
)

func TestSwapAndSecretInputBounds(t *testing.T) {
	header := "Filename\tType\tSize\tUsed\tPriority\n"
	if !noSwap([]byte(header)) {
		t.Fatal("rejected empty swap table")
	}
	for _, data := range []string{"", "Filename", "bad table", header + "/swapfile file 999 0 -2\n", header + "/dev/zram0 partition 999 0 1\n"} {
		if noSwap([]byte(data)) {
			t.Fatal("accepted unsafe or malformed swap table")
		}
	}
	for _, input := range []string{"secret\nignored", "secret"} {
		value, err := readLine(strings.NewReader(input))
		if err != nil || string(value) != "secret" {
			t.Fatal("secret pipe parser failed")
		}
		Clear(value)
	}
	if _, err := readLine(bytes.NewReader(bytes.Repeat([]byte{1}, maxPassphrase+1))); err == nil {
		t.Fatal("accepted oversized input")
	}
	if _, err := readLine(strings.NewReader("")); err == nil {
		t.Fatal("accepted empty EOF")
	}
}
