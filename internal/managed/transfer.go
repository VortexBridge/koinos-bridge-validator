package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	bridge "github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

// Transfer is reconstructed by a chain reader, never accepted as a dashboard
// signing request. Amounts are canonical unsigned bridge units (8 decimals),
// before destination-token conversion. Current source contracts limit to uint64.
type Transfer struct {
	TransactionID string `json:"transactionId"` // lower-case hex, no prefix
	OperationID   string `json:"operationId"`
	Token         string `json:"token"`
	Recipient     string `json:"recipient"`
	Relayer       string `json:"relayer"`
	Amount        string `json:"amount"`
	Payment       string `json:"payment"`
	Metadata      string `json:"metadata"`
	Expiration    string `json:"expiration"` // milliseconds
}

func uint64Value(s string) (*big.Int, error) {
	if s == "" || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
		return nil, errors.New("noncanonical unsigned value")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, errors.New("noncanonical unsigned value")
		}
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.BitLen() > 64 {
		return nil, errors.New("value exceeds reviewed uint64 source range")
	}
	return n, nil
}
func transferAddress(p operator.Profile, s string, optional bool) ([]byte, error) {
	if optional && s == "" {
		if p.Family == "evm" {
			return make([]byte, 20), nil
		}
		return nil, nil
	}
	if p.Family == "evm" && optional && s == "0x0000000000000000000000000000000000000000" {
		return make([]byte, 20), nil
	}
	check := p
	check.Contract = s
	if check.Validate() != nil {
		return nil, errors.New("invalid transfer address")
	}
	if p.Family == "evm" {
		return common.HexToAddress(s).Bytes(), nil
	}
	return base58.Decode(s)
}

// TransferDigest creates the exact destination-contract signing digest. This
// pure codec does not establish source inclusion, finality, membership or funds.
func TransferDigest(p operator.Profile, t Transfer) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if !utf8.ValidString(t.Metadata) || len(t.Metadata) > 1024 {
		return "", errors.New("metadata is invalid or too large")
	}
	tx, err := hex.DecodeString(t.TransactionID)
	if err != nil || hex.EncodeToString(tx) != t.TransactionID {
		return "", errors.New("noncanonical transaction identity")
	}
	if p.Family == "koinos" {
		if len(tx) != 32 {
			return "", errors.New("EVM source transaction hash must be 32 bytes")
		}
	} else if len(tx) != 32 && (len(tx) != 34 || tx[0] != 0x12 || tx[1] != 0x20) {
		return "", errors.New("invalid Koinos source transaction identity")
	}
	amount, err := uint64Value(t.Amount)
	if err != nil || amount.Sign() == 0 {
		return "", errors.New("invalid transfer amount")
	}
	payment, err := uint64Value(t.Payment)
	if err != nil || payment.Cmp(amount) > 0 {
		return "", errors.New("invalid relayer payment")
	}
	expiry, err := uint64Value(t.Expiration)
	if err != nil || expiry.Sign() == 0 {
		return "", errors.New("invalid expiration")
	}
	operation, err := uint64Value(t.OperationID)
	if err != nil {
		return "", err
	}
	// Reviewed Koinos verifier binds only tx hash. Until the contract is changed,
	// a reader must reject multiple bridge events in one EVM transaction.
	if p.Family == "koinos" && operation.Sign() != 0 {
		return "", errors.New("Koinos transfer codec does not bind an operation index")
	}
	token, err := transferAddress(p, t.Token, false)
	if err != nil {
		return "", err
	}
	recipient, err := transferAddress(p, t.Recipient, false)
	if err != nil {
		return "", err
	}
	relayer, err := transferAddress(p, t.Relayer, true)
	if err != nil {
		return "", err
	}
	contract, err := transferAddress(p, p.Contract, false)
	if err != nil {
		return "", err
	}
	if p.Family == "koinos" {
		preimage, err := proto.Marshal(&bridge.CompleteTransferHash{Action: bridge.ActionId_complete_transfer, TransactionId: tx, Token: token, Recipient: recipient, Relayer: relayer, Amount: amount.Uint64(), Payment: payment.Uint64(), Metadata: t.Metadata, ContractId: contract, Expiration: expiry.Uint64(), Chain: p.BridgeChainID})
		if err != nil {
			return "", errors.New("transfer encoding failed")
		}
		digest := sha256.Sum256(preimage)
		return hex.EncodeToString(digest[:]), nil
	}
	word := func(n *big.Int) []byte { return common.LeftPadBytes(n.Bytes(), 32) }
	preimage := []byte{}
	for _, part := range [][]byte{word(big.NewInt(int64(bridge.ActionId_complete_transfer))), tx, word(operation), token, relayer, recipient, word(amount), word(payment), []byte(t.Metadata), contract, word(expiry), common.LeftPadBytes(new(big.Int).SetUint64(uint64(p.BridgeChainID)).Bytes(), 4)} {
		preimage = append(preimage, part...)
	}
	hash := crypto.Keccak256(preimage)
	digest := crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), hash)
	return strings.ToLower(hex.EncodeToString(digest)), nil
}
