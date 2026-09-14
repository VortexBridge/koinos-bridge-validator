//go:build linux
// +build linux

package keyvault

import (
	"bytes"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func noSwap(data []byte) bool {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	return len(lines) == 1 && len(bytes.Fields(lines[0])) == 5 && string(bytes.Fields(lines[0])[0]) == "Filename"
}

// ProtectProcess covers the full Go heap, including transient crypto-library
// copies. With active swap it must lock all current/future process mappings.
// ONFAULT avoids faulting Go's large reserved address ranges into RAM. The
// service needs an adequate memlock limit; failures never fall back to plaintext.
// This cannot prevent a privileged administrator enabling hibernation later.
func ProtectProcess() error {
	if os.Geteuid() == 0 {
		return errors.New("encrypted signing requires a dedicated non-root service user")
	}
	data, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return errors.New("cannot inspect Linux swap policy; signing vault remains locked")
	}
	if !noSwap(data) && unix.Mlockall(unix.MCL_CURRENT|unix.MCL_FUTURE|unix.MCL_ONFAULT) != nil {
		return errors.New("encrypted signing requires no active swap or successful process memory locking; review the service memlock limit")
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}) != nil || unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return errors.New("cannot disable process crash dumps; signing vault remains locked")
	}
	return nil
}

func terminalMode(fd int) (*unix.Termios, error) { return unix.IoctlGetTermios(fd, unix.TCGETS) }
func setTerminalMode(fd int, mode *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TCSETS, mode)
}
