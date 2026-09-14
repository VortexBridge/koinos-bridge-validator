// vortex-keys is a local console tool. It never contacts RPCs or the operator API.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	koinos "github.com/koinos/koinos-util-golang"
)

func run(args []string) error {
	f := flag.NewFlagSet("vortex-keys", flag.ContinueOnError)
	// Flag parsing errors can quote input. Keep all error output sanitized.
	f.SetOutput(io.Discard)
	vault := f.String("vault", "", "absolute path for the encrypted key bundle")
	fd := f.Int("passphrase-fd", -1, "inherited pipe descriptor; omitted for a hidden terminal prompt")
	if err := f.Parse(args); err == flag.ErrHelp {
		fmt.Fprintln(os.Stdout, "vortex-keys --vault /absolute/private/keys.vault [--passphrase-fd 3] generate|import|inspect\nOmit the descriptor for a hidden local terminal prompt. Import reads both keys only from that terminal.")
		return nil
	} else if err != nil {
		return errors.New("invalid key-tool arguments; see --help")
	}
	if len(f.Args()) != 1 || (f.Arg(0) != "generate" && f.Arg(0) != "import" && f.Arg(0) != "inspect") {
		return errors.New("choose generate, import or inspect after the flags")
	}
	if err := keyvault.ProtectProcess(); err != nil {
		return err
	}
	password := func() ([]byte, error) {
		p, err := keyvault.ReadSecret(*fd, "Vault passphrase")
		if err != nil {
			return nil, err
		}
		if *fd == -1 && f.Arg(0) != "inspect" {
			confirmation, err := keyvault.ReadSecret(-1, "Repeat vault passphrase")
			equal := bytes.Equal(p, confirmation)
			keyvault.Clear(confirmation)
			if err != nil || !equal {
				keyvault.Clear(p)
				return nil, errors.New("passphrases did not match")
			}
		}
		return p, nil
	}
	var public keyvault.Public
	var err error
	if f.Arg(0) == "inspect" {
		keys, result, openErr := keyvault.Unlock(*vault, "", "", password)
		if openErr != nil {
			return openErr
		}
		keys.Close()
		public = result
	} else {
		var evm, native []byte
		if f.Arg(0) == "import" {
			// Existing keys can be imported only through the local hidden terminal.
			// There is no plaintext-file or environment import path.
			encoded, readErr := keyvault.ReadSecret(-1, "Existing EVM private key (64 hexadecimal characters)")
			if readErr != nil {
				return readErr
			}
			evm = make([]byte, 32)
			if len(encoded) != 64 {
				keyvault.Clear(encoded)
				return errors.New("invalid EVM signing key")
			}
			n, decodeErr := hex.Decode(evm, encoded)
			keyvault.Clear(encoded)
			defer keyvault.Clear(evm)
			if decodeErr != nil || n != 32 {
				return errors.New("invalid EVM signing key")
			}
			encoded, readErr = keyvault.ReadSecret(-1, "Existing Koinos private key (WIF)")
			if readErr != nil {
				return readErr
			}
			native, err = koinos.DecodeWIF(string(encoded))
			keyvault.Clear(encoded)
			defer keyvault.Clear(native)
			if err != nil || len(native) != 32 {
				return errors.New("invalid Koinos signing key")
			}
		}
		public, err = keyvault.Create(*vault, evm, native, password)
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(public)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
