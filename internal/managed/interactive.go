package managed

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// RunInteractive owns input until return. Secret entry finishes before starting
// the command reader, so it cannot consume passphrase keystrokes concurrently.
// A stopped session is not automatically unlocked again; restart explicitly.
func RunInteractive(ctx context.Context, s *Session, vault string, input io.ReadCloser, output io.Writer, secret func() ([]byte, error)) (result error) {
	if s == nil || input == nil || output == nil || secret == nil {
		return errors.New("interactive session inputs required")
	}
	defer input.Close()
	defer func() {
		if err := s.Close(); result == nil && err != nil {
			result = err
		}
	}()
	if e := s.Activate(ctx, vault, secret); e != nil {
		return e
	}
	encoder := json.NewEncoder(output)
	status := func() error {
		j := s.Status()
		return encoder.Encode(map[string]interface{}{"state": j.State, "retainedOperations": len(j.Operations)})
	}
	if e := status(); e != nil {
		return e
	}
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type line struct {
		text string
		err  error
		end  bool
	}
	lines := make(chan line)
	go func() {
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 256), 256)
		for scanner.Scan() {
			select {
			case lines <- line{text: scanner.Text()}:
			case <-readCtx.Done():
				return
			}
		}
		select {
		case lines <- line{err: scanner.Err(), end: true}:
		case <-readCtx.Done():
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return s.Stop()
		case next := <-lines:
			if next.end {
				if next.err != nil {
					return errors.New("command input failed or exceeded limit")
				}
				return s.Stop()
			}
			words := strings.Fields(next.text)
			if len(words) == 1 && words[0] == "stop" {
				return s.Stop()
			}
			if len(words) == 1 && words[0] == "status" {
				if e := status(); e != nil {
					return e
				}
				continue
			}
			if len(words) == 2 && words[0] == "sign" {
				op, e := s.Sign(ctx, words[1])
				if e != nil {
					if err := encoder.Encode(map[string]string{"error": "operation rejected; inspect current readiness and recovery state"}); err != nil {
						return err
					}
				} else if e = encoder.Encode(op); e != nil {
					return e
				}
				continue
			}
			if e := encoder.Encode(map[string]string{"error": "use status, sign <direction/transaction:operation>, or stop"}); e != nil {
				return e
			}
		}
	}
}
