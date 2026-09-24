package operator

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/encoding/protowire"
)

type Action struct {
	Kind       string `json:"kind"`
	Address    string `json:"address,omitempty"`
	Wallet     string `json:"wallet,omitempty"`
	Fee        string `json:"fee,omitempty"`
	Pause      *bool  `json:"pause,omitempty"`
	Nonce      string `json:"nonce"`
	Expiration string `json:"expiration"` // milliseconds, matching both contracts
}

type Payload struct {
	ProfileDigest string `json:"profileDigest"`
	Action        Action `json:"action"`
	Preimage      string `json:"preimage"` // hex before contract hash/prefix
	Digest        string `json:"digest"`   // 32-byte signing digest, hex
}

var actionIDs = map[string]uint64{
	"add_validator": 1, "remove_validator": 2, "add_token": 3, "remove_token": 4,
	"add_wrapped_token": 5, "remove_wrapped_token": 6, "set_pause": 7,
	"set_fee_token": 9, "set_fee_wrapped_token": 10, "claim_fee_token": 11, "claim_fee_wrapped_token": 12,
}

// EncodeAction is a pure codec, not authorization to sign. The network identity
// is checked independently: legacy contracts bind only their internal chain ID.
func EncodeAction(p Profile, a Action) (Payload, error) {
	if err := p.Validate(); err != nil {
		return Payload{}, err
	}
	id, ok := actionIDs[a.Kind]
	if !ok {
		return Payload{}, errors.New("unsupported governance action")
	}
	if p.Family == "koinos" && a.Kind == "claim_fee_wrapped_token" {
		return Payload{}, errors.New("wrapped fee claims disabled: reviewed Koinos verifier reuses action 11; requires security review and a new compatible release")
	}
	bits := 256
	if p.Family == "koinos" {
		bits = 64
	}
	nonce, err := unsigned(a.Nonce, bits)
	if err != nil {
		return Payload{}, fmt.Errorf("nonce: %w", err)
	}
	expiry, err := unsigned(a.Expiration, 64)
	if err != nil || expiry.Sign() == 0 {
		return Payload{}, errors.New("invalid expiration milliseconds")
	}
	feeAction := id == 9 || id == 10 || (p.Family == "evm" && (id == 3 || id == 5))
	claim := id == 11 || id == 12
	var target, wallet []byte
	var fee *big.Int
	if id == 7 {
		if a.Pause == nil || a.Address != "" {
			return Payload{}, errors.New("set_pause requires a boolean and no address")
		}
	} else {
		if a.Pause != nil {
			return Payload{}, errors.New("pause is only valid for set_pause")
		}
		target, err = addressBytes(p.Family, a.Address)
		if err != nil {
			return Payload{}, err
		}
	}
	if feeAction {
		fee, err = unsigned(a.Fee, bits)
		if err != nil {
			return Payload{}, fmt.Errorf("fee: %w", err)
		}
	} else if a.Fee != "" {
		return Payload{}, errors.New("fee is not part of this action; Koinos token registration and fee changes are separate proposals")
	}
	if claim {
		wallet, err = addressBytes(p.Family, a.Wallet)
		if err != nil {
			return Payload{}, err
		}
	} else if a.Wallet != "" {
		return Payload{}, errors.New("wallet is only valid for fee claims")
	}
	contract, _ := addressBytes(p.Family, p.Contract)
	var raw, digest []byte
	if p.Family == "evm" {
		raw = append(raw, word(new(big.Int).SetUint64(id))...)
		if id == 7 {
			if *a.Pause {
				raw = append(raw, 1)
			} else {
				raw = append(raw, 0)
			}
		} else {
			raw = append(raw, target...)
		}
		if feeAction {
			raw = append(raw, word(fee)...)
		}
		if claim {
			raw = append(raw, wallet...)
		}
		raw = append(raw, word(nonce)...)
		raw = append(raw, contract...)
		raw = append(raw, word(expiry)...)
		chain := make([]byte, 4)
		binary.BigEndian.PutUint32(chain, p.BridgeChainID)
		raw = append(raw, chain...)
		digest = crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), crypto.Keccak256(raw))
	} else {
		raw = fieldUint(raw, 1, id)
		if id == 7 {
			if *a.Pause {
				raw = fieldUint(raw, 2, 1)
			}
		} else {
			raw = fieldBytes(raw, 2, target)
		}
		field := protowire.Number(3)
		if feeAction {
			raw = fieldUint(raw, field, fee.Uint64())
			field++
		}
		if claim {
			raw = fieldBytes(raw, field, wallet)
			field++
		}
		raw = fieldUint(raw, field, nonce.Uint64())
		raw = fieldBytes(raw, field+1, contract)
		raw = fieldUint(raw, field+2, expiry.Uint64())
		raw = fieldUint(raw, field+3, uint64(p.BridgeChainID))
		h := sha256.Sum256(raw)
		digest = h[:]
	}
	return Payload{p.Digest(), a, hex.EncodeToString(raw), hex.EncodeToString(digest)}, nil
}

func word(n *big.Int) []byte { b := make([]byte, 32); n.FillBytes(b); return b }
func fieldUint(b []byte, n protowire.Number, v uint64) []byte {
	if v == 0 {
		return b
	}
	return protowire.AppendVarint(protowire.AppendTag(b, n, protowire.VarintType), v)
}
func fieldBytes(b []byte, n protowire.Number, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	return protowire.AppendBytes(protowire.AppendTag(b, n, protowire.BytesType), v)
}

func RecoverSigner(p Profile, payload Payload, signature string) (string, error) {
	expected, err := EncodeAction(p, payload.Action)
	if err != nil {
		return "", err
	}
	if expected != payload {
		return "", errors.New("payload does not match local profile and canonical encoding")
	}
	hash, _ := hex.DecodeString(payload.Digest)
	if p.Family == "evm" {
		if len(signature) != 132 || !strings.HasPrefix(signature, "0x") {
			return "", errors.New("expected 65-byte hex signature")
		}
		sig, err := hex.DecodeString(signature[2:])
		if err != nil || (sig[64] != 27 && sig[64] != 28) {
			return "", errors.New("invalid EVM signature")
		}
		sig[64] -= 27
		if !crypto.ValidateSignatureValues(sig[64], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), true) {
			return "", errors.New("noncanonical EVM signature")
		}
		pub, err := crypto.SigToPub(hash, sig)
		if err != nil {
			return "", errors.New("invalid EVM signature")
		}
		return crypto.PubkeyToAddress(*pub).Hex(), nil
	}
	sig, err := base64.URLEncoding.DecodeString(signature)
	if err != nil || len(sig) != 65 || sig[0] < 31 || sig[0] > 34 {
		return "", errors.New("expected compressed compact Koinos signature in padded base64url")
	}
	pub, _, err := btcec.RecoverCompact(btcec.S256(), sig, hash)
	if err != nil {
		return "", errors.New("invalid Koinos signature")
	}
	addr, err := util.KoinosPublicKeyToAddress(pub)
	if err != nil {
		return "", err
	}
	return base58.Encode(addr), nil
}

// ValidateApprovals takes a fresh membership/nonce snapshot from the local
// chain adapter, never the membership list embedded by a proposal coordinator.
func ValidateApprovals(p Profile, payload Payload, signatures []string, members []string, nonce string, now time.Time) ([]string, error) {
	signers, ready, err := CheckApprovals(p, payload, signatures, members, nonce, now)
	if err != nil {
		return nil, err
	}
	if !ready {
		return signers, errors.New("quorum not met")
	}
	return signers, nil
}

// CheckApprovals validates every supplied signature against a fresh caller-
// supplied membership and nonce. It reports a structurally valid partial set
// without upgrading it to quorum authority.
func CheckApprovals(p Profile, payload Payload, signatures []string, members []string, nonce string, now time.Time) ([]string, bool, error) {
	if payload.Action.Nonce != nonce {
		return nil, false, errors.New("stale nonce")
	}
	expiry, err := unsigned(payload.Action.Expiration, 64)
	if err != nil || now.UnixMilli() < 0 || expiry.Cmp(big.NewInt(now.UnixMilli())) < 0 {
		return nil, false, errors.New("expired proposal")
	}
	if len(members) == 0 {
		return nil, false, errors.New("no active validators")
	}
	normalize := func(s string) string {
		if p.Family == "evm" {
			return strings.ToLower(s)
		}
		return s
	}
	allowed := map[string]bool{}
	for _, member := range members {
		if _, err := addressBytes(p.Family, member); err != nil {
			return nil, false, err
		}
		key := normalize(member)
		if allowed[key] {
			return nil, false, errors.New("duplicate membership entry")
		}
		allowed[key] = true
	}
	seen := map[string]bool{}
	signers := []string{}
	for _, sig := range signatures {
		signer, err := RecoverSigner(p, payload, sig)
		if err != nil {
			return nil, false, err
		}
		key := normalize(signer)
		if !allowed[key] {
			return nil, false, errors.New("signature is not from an active validator")
		}
		if seen[key] {
			return nil, false, errors.New("duplicate signer")
		}
		seen[key] = true
		signers = append(signers, signer)
	}
	return signers, len(signers) >= Quorum(len(members)), nil
}
