//go:build linux
// +build linux

package keyvault

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Exercise the real controlling-terminal path. A signal during manual unlock
// must end the attempt without echoing entered bytes or leaving the terminal
// in no-echo mode for the operator's next shell.
func TestReadSecretInterruptRestoresTerminal(t *testing.T) {
	if os.Getenv("VORTEX_TEST_SECRET_INTERRUPT_CHILD") == "1" {
		value, err := ReadSecret(-1, "Synthetic vault passphrase")
		Clear(value)
		if err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Fatal("terminal secret entry was not interrupted")
		}
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("non-root Linux required")
	}
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	ptyNumber, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptyNumber), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || before.Lflag&unix.ECHO == 0 {
		t.Fatal("test terminal did not start with echo")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestReadSecretInterruptRestoresTerminal$")
	cmd.Env = append(os.Environ(), "VORTEX_TEST_SECRET_INTERRUPT_CHILD=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	chunks := make(chan []byte)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		defer close(chunks)
		for {
			buf := make([]byte, 4096)
			n, readErr := master.Read(buf)
			if n > 0 {
				select {
				case chunks <- buf[:n]:
				case <-stop:
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()
	transcript := []byte{}
	deadline := time.After(5 * time.Second)
	for !bytes.Contains(transcript, []byte("Synthetic vault passphrase:")) {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				t.Fatal("terminal closed before passphrase prompt")
			}
			transcript = append(transcript, chunk...)
		case <-deadline:
			t.Fatal("passphrase prompt timed out")
		}
	}
	partial := []byte("synthetic-partial-secret")
	if _, err := master.Write(partial); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("interrupted secret reader did not exit cleanly", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interrupted secret reader did not exit")
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || after.Lflag&unix.ECHO == 0 {
		t.Fatal("terminal echo was not restored")
	}
	// A later shell on this terminal must not receive a partial passphrase that
	// remained in the line discipline when the reader was interrupted.
	if _, err := master.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	poll := []unix.PollFd{{Fd: int32(slave.Fd()), Events: unix.POLLIN}}
	if ready, err := unix.Poll(poll, 500); err != nil || ready != 1 {
		t.Fatal("terminal did not deliver a line after interruption", err)
	}
	line := make([]byte, len(partial)+2)
	n, err := slave.Read(line)
	if err != nil || !bytes.Equal(line[:n], []byte("\n")) {
		t.Fatal("terminal retained partial secret input after interruption")
	}
	quiet := time.NewTimer(100 * time.Millisecond)
	defer quiet.Stop()
	for {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				if bytes.Contains(transcript, partial) {
					t.Fatal("partial secret was echoed")
				}
				return
			}
			transcript = append(transcript, chunk...)
		case <-quiet.C:
			if bytes.Contains(transcript, partial) {
				t.Fatal("partial secret was echoed")
			}
			return
		}
	}
}
