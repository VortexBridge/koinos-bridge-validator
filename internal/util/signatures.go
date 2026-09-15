package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	bridge "github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/mr-tron/base58"
)

func RecoverEthereumAddressFromSignature(signature string, hash []byte) (string, error) {
	if len(hash) != 32 || len(signature) != 132 || !strings.HasPrefix(signature, "0x") {
		return "", errors.New("invalid Ethereum signature or digest length")
	}
	raw, err := hex.DecodeString(signature[2:])
	if err != nil {
		return "", errors.New("invalid Ethereum signature encoding")
	}
	// Match Bridge.sol recoverSigner: recovery IDs 0/1 and 27/28.
	if raw[64] < 27 {
		raw[64] += 27
	}
	if raw[64] != 27 && raw[64] != 28 {
		return "", errors.New("invalid Ethereum recovery ID")
	}
	raw[64] -= 27
	// The reviewed contract uses ecrecover and accepts both high and low S.
	// Deduplicate by recovered identity, not by signature byte representation.
	if !crypto.ValidateSignatureValues(raw[64], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:64]), false) {
		return "", errors.New("invalid Ethereum signature values")
	}
	key, err := crypto.SigToPub(hash, raw)
	if err != nil {
		return "", errors.New("cannot recover Ethereum signer")
	}
	return crypto.PubkeyToAddress(*key).Hex(), nil
}
func RecoverKoinosAddressFromSignature(signature string, hash []byte) (string, error) {
	if len(hash) != 32 || len(signature) != 88 {
		return "", errors.New("invalid Koinos signature or digest length")
	}
	raw, err := base64.URLEncoding.Strict().DecodeString(signature)
	if err != nil || len(raw) != 65 || base64.URLEncoding.EncodeToString(raw) != signature || raw[0] < 27 || raw[0] > 34 {
		return "", errors.New("invalid Koinos compact signature encoding")
	}
	key, _, err := btcec.RecoverCompact(btcec.S256(), raw, hash)
	if err != nil {
		return "", errors.New("cannot recover Koinos signer")
	}
	address, err := KoinosPublicKeyToAddress(key)
	if err != nil {
		return "", errors.New("cannot derive Koinos signer address")
	}
	return base58.Encode(address), nil
}

// TransferSignatureDigest parses the already computed destination signing hash.
// It does not establish that the hash matches source events, finality or the
// destination contract's encoding. Those checks remain the caller's responsibility.
func TransferSignatureDigest(tx *bridge.Transaction) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("missing transfer")
	}
	if tx.Type == bridge.TransactionType_koinos {
		if len(tx.Hash) != 66 || !strings.HasPrefix(tx.Hash, "0x") {
			return nil, errors.New("invalid EVM transfer digest")
		}
		raw, err := hex.DecodeString(tx.Hash[2:])
		if err != nil {
			return nil, errors.New("invalid EVM transfer digest")
		}
		return raw, nil
	}
	if tx.Type == bridge.TransactionType_ethereum {
		if len(tx.Hash) != 44 {
			return nil, errors.New("invalid Koinos transfer digest")
		}
		raw, err := base64.URLEncoding.Strict().DecodeString(tx.Hash)
		if err != nil || len(raw) != 32 || base64.URLEncoding.EncodeToString(raw) != tx.Hash {
			return nil, errors.New("invalid Koinos transfer digest")
		}
		return raw, nil
	}
	return nil, errors.New("unknown transfer direction")
}
func transferValidatorAddress(kind bridge.TransactionType, v ValidatorConfig) string {
	if kind == bridge.TransactionType_koinos {
		if !common.IsHexAddress(v.EthereumAddress) || common.HexToAddress(v.EthereumAddress) == (common.Address{}) {
			return ""
		}
		return common.HexToAddress(v.EthereumAddress).Hex()
	}
	b, err := validKoinosAddress(v.KoinosAddress)
	if err != nil {
		return ""
	}
	return base58.Encode(b)
}

func validKoinosAddress(address string) ([]byte, error) {
	b, err := base58.Decode(address)
	if err != nil || len(b) != 25 || b[0] != 0 {
		return nil, errors.New("invalid Koinos address")
	}
	one := sha256.Sum256(b[:21])
	two := sha256.Sum256(one[:])
	if !bytes.Equal(two[:4], b[21:]) {
		return nil, errors.New("invalid Koinos address checksum")
	}
	return b, nil
}

// TransferQuorum returns the distinct configured destination identities and the
// threshold enforced by the reviewed bridge contracts. The configuration map
// contains aliases for both chain identities, so len(validators) is not the
// validator count. Invalid non-empty identities fail closed rather than
// silently lowering the threshold.
func TransferQuorum(kind bridge.TransactionType, validators map[string]ValidatorConfig) (int, int, error) {
	if kind != bridge.TransactionType_koinos && kind != bridge.TransactionType_ethereum {
		return 0, 0, errors.New("unknown transfer direction")
	}
	identities := map[string]struct{}{}
	for _, validator := range validators {
		if kind == bridge.TransactionType_koinos {
			if validator.EthereumAddress == "" {
				continue
			}
			if !common.IsHexAddress(validator.EthereumAddress) || common.HexToAddress(validator.EthereumAddress) == (common.Address{}) {
				return 0, 0, errors.New("invalid configured Ethereum validator identity")
			}
			identities[common.HexToAddress(validator.EthereumAddress).Hex()] = struct{}{}
			continue
		}
		if validator.KoinosAddress == "" {
			continue
		}
		address, err := validKoinosAddress(validator.KoinosAddress)
		if err != nil {
			return 0, 0, errors.New("invalid configured Koinos validator identity")
		}
		identities[base58.Encode(address)] = struct{}{}
	}
	count := len(identities)
	if count == 0 {
		return 0, 0, errors.New("no configured validator identities for transfer direction")
	}
	return count, (count*5 + 10) / 9, nil
}

// HasTransferQuorum verifies the signatures and applies the same threshold as
// the destination contract. It never substitutes peer availability or a
// frontend setting for current contract membership.
func HasTransferQuorum(tx *bridge.Transaction, validators map[string]ValidatorConfig) (bool, error) {
	verified, err := VerifyTransferSignatures(tx, validators)
	if err != nil {
		return false, err
	}
	_, required, err := TransferQuorum(tx.Type, validators)
	if err != nil {
		return false, err
	}
	return len(verified) >= required, nil
}
func recoverTransferSigner(kind bridge.TransactionType, signature string, hash []byte) (string, error) {
	if kind == bridge.TransactionType_koinos {
		return RecoverEthereumAddressFromSignature(signature, hash)
	}
	return RecoverKoinosAddressFromSignature(signature, hash)
}

// VerifyTransferSignatures verifies distinct configured identities over tx.Hash.
// Configuration is not fresh on-chain membership; the result is not a quorum or
// rollout permit. Empty local completion records may have no signature digest.
func VerifyTransferSignatures(tx *bridge.Transaction, validators map[string]ValidatorConfig) (map[string]string, error) {
	if tx == nil || (tx.Type != bridge.TransactionType_koinos && tx.Type != bridge.TransactionType_ethereum) || len(tx.Validators) != len(tx.Signatures) {
		return nil, errors.New("invalid transfer signature arrays")
	}
	result := map[string]string{}
	if len(tx.Signatures) == 0 {
		return result, nil
	}
	hash, err := TransferSignatureDigest(tx)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, v := range validators {
		if address := transferValidatorAddress(tx.Type, v); address != "" {
			allowed[address] = true
		}
	}
	if len(tx.Signatures) > len(allowed) {
		return nil, errors.New("more signatures than distinct configured validators")
	}
	for i, signature := range tx.Signatures {
		address := tx.Validators[i]
		if tx.Type == bridge.TransactionType_koinos {
			if !common.IsHexAddress(address) {
				return nil, errors.New("invalid Ethereum validator address")
			}
			address = common.HexToAddress(address).Hex()
		}
		if !allowed[address] || result[address] != "" {
			return nil, errors.New("unknown or duplicate transfer validator")
		}
		recovered, err := recoverTransferSigner(tx.Type, signature, hash)
		if err != nil || recovered != address {
			return nil, errors.New("transfer signature does not match configured validator and digest")
		}
		result[address] = signature
	}
	return result, nil
}
