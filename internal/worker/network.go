package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/mr-tron/base58"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// NetworkBinding pins actual RPC network identities separately from protocol
// chain IDs. It does not attest contract code, finality or an honest RPC server.
type NetworkBinding struct {
	SchemaVersion   int    `json:"schemaVersion"`
	EVMNetworkID    string `json:"evmNetworkId"`
	KoinosNetworkID string `json:"koinosNetworkId"`
	EVMContract     string `json:"evmContract"`
	KoinosContract  string `json:"koinosContract"`
}

// HasValidatorData treats any of the three database paths as existing state.
// Losing just metadata must not permit relabeling surviving transfer records.
func HasValidatorData(base string) (bool, error) {
	for _, name := range []string{"metadata", "ethereum_transactions", "koinos_transactions"} {
		if _, err := os.Lstat(filepath.Join(base, "bridge", name)); err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, errors.New("cannot inspect existing validator data")
		}
	}
	return false, nil
}

func ValidNetworkID(family, id string) bool {
	if family == "evm" {
		if len(id) == 0 || len(id) > 78 || id[0] == '0' {
			return false
		}
		for _, c := range id {
			if c < '0' || c > '9' {
				return false
			}
		}
		n, ok := new(big.Int).SetString(id, 10)
		return ok && n.Sign() > 0 && n.BitLen() <= 256
	}
	if family != "koinos" {
		return false
	}
	b, err := base64.URLEncoding.DecodeString(id)
	return err == nil && len(b) == 34 && b[0] == 0x12 && b[1] == 0x20 && base64.URLEncoding.EncodeToString(b) == id
}
func (b NetworkBinding) Enabled() bool { return b.EVMNetworkID != "" || b.KoinosNetworkID != "" }
func (b NetworkBinding) Validate() error {
	if b.SchemaVersion != 1 || !ValidNetworkID("evm", b.EVMNetworkID) || !ValidNetworkID("koinos", b.KoinosNetworkID) || b.EVMContract == "" || b.KoinosContract == "" {
		return errors.New("network binding requires both canonical network identities and contract addresses")
	}
	if len(b.EVMContract) != 42 || !strings.HasPrefix(b.EVMContract, "0x") || !common.IsHexAddress(b.EVMContract) || common.HexToAddress(b.EVMContract) == (common.Address{}) {
		return errors.New("network binding requires a nonzero EVM contract address")
	}
	address, err := base58.Decode(b.KoinosContract)
	if err != nil || len(address) != 25 || address[0] != 0 {
		return errors.New("network binding requires a valid Koinos contract address")
	}
	h := sha256.Sum256(address[:21])
	h = sha256.Sum256(h[:])
	if !bytes.Equal(address[21:], h[:4]) {
		return errors.New("invalid Koinos contract checksum in network binding")
	}
	return nil
}

// CheckNetworkBinding is read-only. Missing bindings may only be initialized
// for new databases; an existing checkpoint cannot be silently relabeled.
func CheckNetworkBinding(dir string, b NetworkBinding, existingDatabase bool) error {
	path := filepath.Join(dir, "network-binding.json")
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if !b.Enabled() {
			return nil
		} // Legacy data remains explicitly unbound.
		if err := b.Validate(); err != nil {
			return err
		}
		if existingDatabase {
			return errors.New("existing unbound database requires a reviewed network migration; do not relabel or reset it")
		}
		return nil
	}
	if err != nil {
		return errors.New("network binding unavailable")
	}
	if err := b.Validate(); err != nil {
		return err
	}
	raw, err := ReadPrivateFile(path, 4096)
	if err != nil {
		return err
	}
	var saved NetworkBinding
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&saved) != nil || d.Decode(new(interface{})) != io.EOF || saved.Validate() != nil {
		return errors.New("invalid saved network binding")
	}
	saved.EVMContract = strings.ToLower(saved.EVMContract)
	b.EVMContract = strings.ToLower(b.EVMContract)
	if saved != b {
		return errors.New("network identity or contract changed; use a separate route directory or reviewed migration")
	}
	return nil
}

// EnsureNetworkBinding requires exclusive process ownership held by the caller.
func EnsureNetworkBinding(dir string, b NetworkBinding, existingDatabase bool) error {
	if err := CheckNetworkBinding(dir, b, existingDatabase); err != nil {
		return err
	}
	if !b.Enabled() {
		return nil
	}
	path := filepath.Join(dir, "network-binding.json")
	if _, err := os.Lstat(path); err == nil {
		return nil
	}
	if err := PrivateDir(dir); err != nil {
		return err
	}
	raw, _ := json.Marshal(b)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
