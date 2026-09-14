// Package keyvault provides local, passphrase-encrypted custody for the two
// validator signing keys. The operator API never calls its secret-loading path.
package keyvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
	koinos "github.com/koinos/koinos-util-golang"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/scrypt"
)

// Version 1 has a fixed KDF and payload layout: magic, 32-byte random salt,
// 12-byte random GCM nonce, and authenticated encryption of EVM || Koinos scalars.
// Parameters cannot be supplied by the file (including expensive attacker KDFs).
const magic = "VORTEX-KEYS-V1\x00"
const fileSize = len(magic) + 32 + 12 + 64 + 16
const maxPassphrase = 1024

type Public struct {
	EVMAddress    string `json:"evmAddress"`
	KoinosAddress string `json:"koinosAddress"`
	VaultSHA256   string `json:"vaultSha256"`
}

type Keys struct {
	EVM    *ecdsa.PrivateKey
	Koinos []byte
}

// Clear is best effort. The Go runtime and signing libraries can make copies;
// this is why supported commands require no swap or locked process memory.
func Clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func (k *Keys) Close() {
	if k == nil {
		return
	}
	if k.EVM != nil && k.EVM.D != nil {
		words := k.EVM.D.Bits()
		for i := range words {
			words[i] = 0
		}
		k.EVM.D.SetInt64(0)
	}
	Clear(k.Koinos)
}

func decodeKeys(raw []byte) (*Keys, Public, error) {
	if len(raw) != 64 {
		return nil, Public{}, errors.New("invalid signing-key bundle")
	}
	evm, err := crypto.ToECDSA(raw[:32])
	if err != nil {
		return nil, Public{}, errors.New("invalid EVM signing key")
	}
	keys := &Keys{EVM: evm, Koinos: append([]byte{}, raw[32:]...)}
	other, err := crypto.ToECDSA(raw[32:])
	if err != nil {
		keys.Close()
		return nil, Public{}, errors.New("invalid Koinos signing key")
	}
	(&Keys{EVM: other}).Close()
	key, err := koinos.NewKoinosKeysFromBytes(keys.Koinos)
	if err != nil {
		keys.Close()
		return nil, Public{}, errors.New("invalid Koinos signing key")
	}
	return keys, Public{EVMAddress: crypto.PubkeyToAddress(evm.PublicKey).Hex(), KoinosAddress: base58.Encode(key.AddressBytes())}, nil
}

func aead(passphrase, salt []byte) (cipher.AEAD, error) {
	// scrypt N=2^17, r=8, p=1: approximately 128 MiB, with a 256-bit AES key.
	derived, err := scrypt.Key(passphrase, salt, 1<<17, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	defer Clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(raw, passphrase []byte) ([]byte, error) {
	if len(passphrase) < 16 || len(passphrase) > maxPassphrase {
		return nil, errors.New("use a strong passphrase of 16 to 1024 bytes")
	}
	keys, _, err := decodeKeys(raw)
	if err != nil {
		return nil, err
	}
	keys.Close()
	header := make([]byte, len(magic)+32+12)
	copy(header, magic)
	if _, err := io.ReadFull(rand.Reader, header[len(magic):]); err != nil {
		return nil, errors.New("secure randomness unavailable")
	}
	c, err := aead(passphrase, header[len(magic):len(magic)+32])
	if err != nil {
		return nil, errors.New("key encryption unavailable")
	}
	return c.Seal(header, header[len(magic)+32:], raw, header), nil
}

func open(encrypted, passphrase []byte) (*Keys, Public, error) {
	if len(encrypted) != fileSize || !bytes.Equal(encrypted[:len(magic)], []byte(magic)) {
		return nil, Public{}, errors.New("unsupported or damaged signing vault")
	}
	if len(passphrase) < 16 || len(passphrase) > maxPassphrase {
		return nil, Public{}, errors.New("cannot unlock signing vault")
	}
	header := encrypted[:len(magic)+32+12]
	c, err := aead(passphrase, header[len(magic):len(magic)+32])
	if err != nil {
		return nil, Public{}, errors.New("key decryption unavailable")
	}
	raw, err := c.Open(nil, header[len(magic)+32:], encrypted[len(header):], header)
	if err != nil {
		return nil, Public{}, errors.New("cannot unlock signing vault: incorrect passphrase or damaged file")
	}
	defer Clear(raw)
	keys, public, err := decodeKeys(raw)
	hash := sha256.Sum256(encrypted)
	public.VaultSHA256 = hex.EncodeToString(hash[:])
	return keys, public, err
}

func readFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("signing vault needs an absolute path")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("signing vault unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(fileSize) {
		return nil, errors.New("signing vault must be a mode-0600 regular file of the supported size")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(fileSize)+1))
	if err != nil || len(data) != fileSize {
		return nil, errors.New("signing vault unreadable or changed")
	}
	return data, nil
}

// Unlock applies process protections before opening input or requesting a secret.
// Both expected addresses come from the locally reviewed validator configuration.
func Unlock(path, expectedEVM, expectedKoinos string, passphrase func() ([]byte, error)) (*Keys, Public, error) {
	if err := ProtectProcess(); err != nil {
		return nil, Public{}, err
	}
	data, err := readFile(path)
	if err != nil {
		return nil, Public{}, err
	}
	password, err := passphrase()
	if err != nil {
		return nil, Public{}, err
	}
	defer Clear(password)
	keys, public, err := open(data, password)
	if err != nil {
		return nil, Public{}, err
	}
	if (expectedEVM != "" && !strings.EqualFold(public.EVMAddress, expectedEVM)) || (expectedKoinos != "" && public.KoinosAddress != expectedKoinos) {
		keys.Close()
		return nil, Public{}, errors.New("signing vault identities differ from the reviewed configuration")
	}
	return keys, public, nil
}

// Create never replaces an existing file. The caller owns its private directory.
// It verifies decryption of the exact bytes before publishing the ciphertext.
func Create(path string, importedEVM, importedKoinos []byte, passphrase func() ([]byte, error)) (Public, error) {
	if err := ProtectProcess(); err != nil {
		return Public{}, err
	}
	if !filepath.IsAbs(path) {
		return Public{}, errors.New("signing vault needs an absolute path")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return Public{}, errors.New("create a private mode-0700 parent directory first")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return Public{}, errors.New("signing vault already exists or cannot be checked")
	}
	raw := make([]byte, 64)
	defer Clear(raw)
	if importedEVM == nil && importedKoinos == nil {
		for offset := 0; offset < 64; offset += 32 {
			key, err := crypto.GenerateKey()
			if err != nil {
				return Public{}, errors.New("key generation failed")
			}
			key.D.FillBytes(raw[offset : offset+32])
			(&Keys{EVM: key}).Close()
		}
	} else {
		if len(importedEVM) != 32 || len(importedKoinos) != 32 {
			return Public{}, errors.New("import requires both 32-byte signing keys")
		}
		copy(raw, importedEVM)
		copy(raw[32:], importedKoinos)
	}
	password, err := passphrase()
	if err != nil {
		return Public{}, err
	}
	defer Clear(password)
	encrypted, err := seal(raw, password)
	if err != nil {
		return Public{}, err
	}
	keys, public, err := open(encrypted, password)
	if err != nil {
		return Public{}, errors.New("new signing vault failed decryption verification")
	}
	keys.Close()
	tmp, err := os.CreateTemp(parent, ".signing-vault-*")
	if err != nil {
		return Public{}, errors.New("cannot create private signing vault")
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(encrypted); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		return Public{}, errors.New("cannot persist encrypted signing vault")
	}
	persisted, err := readFile(tmp.Name())
	if err != nil || !bytes.Equal(persisted, encrypted) {
		return Public{}, errors.New("persisted signing vault differs from verified ciphertext")
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		return Public{}, errors.New("cannot publish signing vault without replacing a file")
	}
	dir, err := os.Open(parent)
	if err != nil {
		return Public{}, errors.New("vault created; directory durability is unverified, inspect locally")
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return Public{}, errors.New("vault created; directory durability is unverified, inspect locally")
	}
	return public, nil
}
