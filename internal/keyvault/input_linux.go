//go:build linux
// +build linux

package keyvault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReadSecret accepts an inherited pipe/socket (fd >=3) or an echo-disabled local
// terminal (fd=-1). Files, stdin, environment variables and argument secrets are
// deliberately unsupported. Pipe input is one bounded line, or bytes then EOF.
func ReadSecret(fd int, prompt string) ([]byte, error) {
	if err := ProtectProcess(); err != nil {
		return nil, err
	}
	if fd != -1 {
		if fd < 3 {
			return nil, errors.New("secret input requires an inherited pipe descriptor of at least 3")
		}
		f := os.NewFile(uintptr(fd), "secret pipe")
		if f == nil {
			return nil, errors.New("secret pipe unavailable")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
			return nil, errors.New("secret descriptor must be a pipe or socket, never a file")
		}
		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil || (!strings.HasPrefix(target, "pipe:[") && !strings.HasPrefix(target, "socket:[")) {
			return nil, errors.New("secret input requires an anonymous inherited pipe or socket")
		}
		return readLine(f)
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("local terminal unavailable; supply an inherited secret pipe")
	}
	defer tty.Close()
	state, err := terminalMode(int(tty.Fd()))
	if err != nil {
		return nil, errors.New("cannot inspect terminal")
	}
	masked := *state
	masked.Lflag &^= unix.ECHO | unix.ECHONL
	// Catch normal termination to restore echo before returning. SIGKILL cannot
	// be caught; the operator can run stty echo on that terminal after a hard kill.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	if setTerminalMode(int(tty.Fd()), &masked) != nil {
		return nil, errors.New("cannot disable terminal echo")
	}
	defer setTerminalMode(int(tty.Fd()), state)
	fmt.Fprint(tty, prompt+": ")
	defer fmt.Fprintln(tty)
	type result struct {
		value []byte
		err   error
	}
	done := make(chan result)
	cancelled := make(chan struct{})
	defer close(cancelled)
	go func() {
		value, err := readLine(tty)
		select {
		case done <- result{value, err}:
		case <-cancelled:
			Clear(value)
		}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-signals:
		return nil, errors.New("secret entry interrupted")
	}
}

func readLine(r io.Reader) ([]byte, error) {
	b := make([]byte, 0, maxPassphrase)
	one := []byte{0}
	defer Clear(one)
	for {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return b, nil
			}
			if len(b) == maxPassphrase {
				Clear(b)
				return nil, errors.New("secret input exceeds 1024 bytes")
			}
			b = append(b, one[0])
		}
		if err != nil {
			if err == io.EOF && len(b) > 0 {
				return b, nil
			}
			Clear(b)
			return nil, errors.New("secret input unavailable")
		}
	}
}
