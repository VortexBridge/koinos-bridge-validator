//go:build linux
// +build linux

package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
)

// A restart requires a new review; copied evidence is not a second host permit.
// This is a local binding, not hardware-backed attestation or defense from root.
func localHostBinding() (string, error) {
	machine, e := os.ReadFile("/etc/machine-id")
	if e != nil {
		return "", errors.New("Linux machine identity unavailable")
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", errors.New("Linux boot identity unavailable")
	}
	m := strings.TrimSpace(string(machine))
	b := strings.ReplaceAll(strings.TrimSpace(string(boot)), "-", "")
	mb, me := hex.DecodeString(m)
	bb, be := hex.DecodeString(b)
	if me != nil || be != nil || len(mb) != 16 || len(bb) != 16 {
		return "", errors.New("invalid Linux machine or boot identity")
	}
	hash := sha256.Sum256([]byte("vortex-host-review-v1\n" + m + "\n" + b + "\n" + strconv.Itoa(os.Geteuid())))
	return hex.EncodeToString(hash[:]), nil
}
