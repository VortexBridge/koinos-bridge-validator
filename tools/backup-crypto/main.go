// backup-crypto is isolated from the legacy validator dependency graph. It
// implements only age X25519 encryption and local identity-file decryption.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "backup-crypto:", err)
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("backup-crypto", flag.ContinueOnError)
	recipient := flags.String("recipient", "", "age X25519 public recipient")
	identity := flags.String("identity-file", "", "local private recovery identity file")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("commands: keygen, encrypt, decrypt")
	}
	switch flags.Arg(0) {
	case "keygen":
		if *identity == "" {
			return errors.New("identity-file is required")
		}
		parent := filepath.Dir(*identity)
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return errors.New("recovery identity directory must be private (0700) and not a symlink")
		}
		key, err := age.GenerateX25519Identity()
		if err != nil {
			return errors.New("identity generation failed")
		}
		f, err := os.OpenFile(*identity, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("identity file must be new")
		}
		if _, err = f.WriteString(key.String() + "\n"); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		dir, err := os.Open(parent)
		if err != nil {
			return err
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return err
		}
		fmt.Println(key.Recipient().String())
		return nil
	case "encrypt":
		r, err := age.ParseX25519Recipient(*recipient)
		if err != nil {
			return errors.New("invalid age X25519 public recipient")
		}
		out, err := age.Encrypt(os.Stdout, r)
		if err != nil {
			return errors.New("age encryption initialization failed")
		}
		if _, err := io.Copy(out, os.Stdin); err != nil {
			return errors.New("backup encryption stream failed")
		}
		if err := out.Close(); err != nil {
			return errors.New("backup encryption did not finish")
		}
		return nil
	case "decrypt":
		f, err := os.OpenFile(*identity, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errors.New("recovery identity unavailable")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
			return errors.New("recovery identity must be a private bounded regular file")
		}
		b, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(b) > 4096 {
			return errors.New("recovery identity unreadable")
		}
		key, err := age.ParseX25519Identity(strings.TrimSpace(string(b)))
		if err != nil {
			return errors.New("invalid recovery identity")
		}
		plain, err := age.Decrypt(os.Stdin, key)
		if err != nil {
			return errors.New("backup cannot be decrypted with this identity")
		}
		if _, err := io.Copy(os.Stdout, plain); err != nil {
			return errors.New("backup authentication or decryption failed")
		}
		return nil
	default:
		return errors.New("unsupported backup crypto command")
	}
}
