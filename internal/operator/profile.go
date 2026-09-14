// Package operator implements the private operator control plane. It does not
// import signing keys or grant authority based on a dashboard's cached state.
package operator

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/mr-tron/base58"
)

const EVMCodec = "evm-1e82614-v1"
const KoinosCodec = "koinos-f7a499e-v1"
const EVMSource = "1e82614bdb61a36aa3309e97001666cf1e14f7d1"
const KoinosSource = "f7a499e51fe54406deb30788df526b39caead1c4"

var slug = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var decimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// Profile contains no endpoints or secrets and can be exported for review.
// CodeHash is lower-case hex: Keccak256(runtime) for EVM, SHA256(Wasm) for Koinos.
// Reviewed describes a local decision, never remotely discovered authority.
type Profile struct {
	SchemaVersion  int    `json:"schemaVersion"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	Family         string `json:"family"`
	Environment    string `json:"environment"`
	NetworkID      string `json:"networkId"`
	BridgeChainID  uint32 `json:"bridgeChainId"`
	Contract       string `json:"contract"`
	Codec          string `json:"codec"`
	SourceCommit   string `json:"sourceCommit"`
	CodeHash       string `json:"codeHash"`
	ReviewEvidence string `json:"reviewEvidence"`
	Reviewed       bool   `json:"reviewed"`
}

func (p Profile) Validate() error {
	if p.SchemaVersion != 1 || !slug.MatchString(p.ID) || strings.TrimSpace(p.Name) == "" || len(p.Name) > 100 {
		return errors.New("profile requires schemaVersion 1, a lowercase slug id and a name")
	}
	if p.Environment != "local" && p.Environment != "testnet" && p.Environment != "mainnet" {
		return errors.New("invalid environment")
	}
	if p.BridgeChainID == 0 {
		return errors.New("bridgeChainId must be nonzero")
	}
	if _, err := addressBytes(p.Family, p.Contract); err != nil {
		return fmt.Errorf("contract: %w", err)
	}
	switch p.Family {
	case "evm":
		n, err := unsigned(p.NetworkID, 256)
		if err != nil || n.Sign() == 0 {
			return errors.New("EVM networkId must be a positive decimal chain ID")
		}
		if p.Codec != EVMCodec || p.SourceCommit != EVMSource {
			return errors.New("unsupported EVM source/codec pair")
		}
	case "koinos":
		identity, err := base64.URLEncoding.DecodeString(p.NetworkID)
		if err != nil || len(identity) != 34 || identity[0] != 0x12 || identity[1] != 0x20 {
			return errors.New("invalid Koinos networkId")
		}
		if p.Codec != KoinosCodec || p.SourceCommit != KoinosSource {
			return errors.New("unsupported Koinos source/codec pair")
		}
	default:
		return errors.New("unsupported chain family")
	}
	if p.CodeHash != "" && !hexHash.MatchString(p.CodeHash) {
		return errors.New("codeHash must be 64 lowercase hex characters")
	}
	if p.Reviewed && (p.CodeHash == "" || strings.TrimSpace(p.ReviewEvidence) == "") {
		return errors.New("reviewed profile requires a code hash and review evidence")
	}
	if len(p.ReviewEvidence) > 2048 {
		return errors.New("review evidence reference too long")
	}
	return nil
}

func (p Profile) Digest() string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func unsigned(s string, bits int) (*big.Int, error) {
	if !decimal.MatchString(s) {
		return nil, errors.New("expected canonical unsigned decimal integer")
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.BitLen() > bits {
		return nil, fmt.Errorf("integer exceeds uint%d", bits)
	}
	return n, nil
}

func addressBytes(family, s string) ([]byte, error) {
	if family == "evm" {
		if !common.IsHexAddress(s) || !strings.HasPrefix(s, "0x") || len(s) != 42 || common.HexToAddress(s) == (common.Address{}) {
			return nil, errors.New("invalid nonzero EVM address")
		}
		return common.HexToAddress(s).Bytes(), nil
	}
	if family != "koinos" {
		return nil, errors.New("unsupported address family")
	}
	b, err := base58.Decode(s)
	if err != nil || len(b) != 25 || b[0] != 0 {
		return nil, errors.New("invalid Koinos address")
	}
	h := sha256.Sum256(b[:21])
	h = sha256.Sum256(h[:])
	if !bytes.Equal(h[:4], b[21:]) {
		return nil, errors.New("invalid Koinos address checksum")
	}
	return b, nil
}

// ValidateEndpoint is applied to private configuration, never a remotely
// supplied proxy destination. Plain HTTP is allowed only on loopback.
func ValidateEndpoint(raw string) error {
	if len(raw) > 8192 {
		return errors.New("RPC URL too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return errors.New("invalid RPC URL; use no embedded user credentials or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("RPC URL requires HTTPS or a literal loopback HTTP address")
}

func Quorum(n int) int { return (n*5 + 10) / 9 }
