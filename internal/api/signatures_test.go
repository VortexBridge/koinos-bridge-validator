package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	bridge "github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type apiSignatureFixture struct {
	api     *Api
	keys    []*ecdsa.PrivateKey
	members []util.ValidatorConfig
	tx      *bridge.Transaction
	hash    []byte
	db      *store.TransactionsStore
	id      string
}

func newSignatureFixture(t *testing.T, kind bridge.TransactionType) apiSignatureFixture {
	t.Helper()
	f := apiSignatureFixture{}
	validators := map[string]util.ValidatorConfig{}
	for i := 0; i < 3; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := btcec.PrivKeyFromBytes(btcec.S256(), crypto.FromECDSA(key))
		a, _ := util.KoinosPublicKeyToAddress(pub.PubKey())
		member := util.ValidatorConfig{EthereumAddress: crypto.PubkeyToAddress(key.PublicKey).Hex(), KoinosAddress: base58.Encode(a)}
		f.keys = append(f.keys, key)
		f.members = append(f.members, member)
		validators[member.KoinosAddress] = member
		validators[member.EthereumAddress] = member
	}
	eth, koinos := store.NewTransactionsStore(store.NewMapBackend()), store.NewTransactionsStore(store.NewMapBackend())
	f.api = NewApi(eth, koinos, f.members[0].KoinosAddress, "0x1111111111111111111111111111111111111111", validators, f.members[0].KoinosAddress, strings.ToLower(f.members[0].EthereumAddress))
	f.tx = &bridge.Transaction{Type: kind, Id: "0x" + strings.Repeat("ab", 32), Amount: "10", Payment: "1", Expiration: uint64(time.Now().Add(time.Minute).UnixMilli()), ToChain: "1", KoinosToken: f.members[0].KoinosAddress, EthToken: "0x2222222222222222222222222222222222222222"}
	if kind == bridge.TransactionType_ethereum {
		f.tx.Recipient = f.members[1].KoinosAddress
		token, _ := base58.Decode(f.tx.KoinosToken)
		recipient, _ := base58.Decode(f.tx.Recipient)
		raw, _ := proto.Marshal(&bridge.CompleteTransferHash{Action: bridge.ActionId_complete_transfer, TransactionId: common.FromHex(f.tx.Id), Token: token, Recipient: recipient, Amount: 10, Payment: 1, ContractId: f.api.koinosContractAddress, Expiration: f.tx.Expiration, Chain: 1})
		hash := sha256.Sum256(raw)
		f.hash = hash[:]
		f.tx.Hash = base64.URLEncoding.EncodeToString(hash[:])
		f.db = eth
		f.id = f.tx.Id
	} else {
		f.tx.Id = "0x1220" + strings.Repeat("ab", 32)
		f.tx.OpId = "1"
		f.tx.Recipient = f.members[1].EthereumAddress
		f.tx.Relayer = f.members[2].EthereumAddress
		_, hash := util.GenerateEthereumCompleteTransferHash(common.FromHex(f.tx.Id), 1, common.FromHex(f.tx.EthToken), common.FromHex(f.tx.Recipient), common.FromHex(f.tx.Relayer), "1", "10", f.api.ethContractAddress, "", f.tx.Expiration, 1)
		f.hash = hash.Bytes()
		f.tx.Hash = hash.Hex()
		f.db = koinos
		f.id = f.tx.Id + "-1"
	}
	return f
}
func (f apiSignatureFixture) signature(i int) (string, string) {
	if f.tx.Type == bridge.TransactionType_ethereum {
		return f.members[i].KoinosAddress, base64.URLEncoding.EncodeToString(util.SignKoinosHash(crypto.FromECDSA(f.keys[i]), f.hash))
	}
	return f.members[i].EthereumAddress, "0x" + hex.EncodeToString(util.SignEthereumHash(f.keys[i], f.hash))
}
func (f apiSignatureFixture) signed(count int) *bridge.Transaction {
	tx := proto.Clone(f.tx).(*bridge.Transaction)
	for i := 0; i < count; i++ {
		a, s := f.signature(i)
		tx.Validators = append(tx.Validators, a)
		tx.Signatures = append(tx.Signatures, s)
	}
	return tx
}
func (f apiSignatureFixture) submit(tx *bridge.Transaction, expiry int64) *httptest.ResponseRecorder {
	raw, _ := proto.Marshal(tx)
	digest := sha256.Sum256(append(raw, []byte(strconv.FormatInt(expiry, 10))...))
	wrapper := &bridge.SubmittedSignature{Transaction: tx, Expiration: expiry, Signature: base64.URLEncoding.EncodeToString(util.SignKoinosHash(crypto.FromECDSA(f.keys[0]), digest[:]))}
	body, _ := protojson.Marshal(wrapper)
	w := httptest.NewRecorder()
	f.api.SubmitSignature(w, httptest.NewRequest("POST", "/SubmitSignature", bytes.NewReader(body)))
	return w
}
func TestSignatureAPIRequiresDistinctVerifiedSignaturesAndOwnCompletion(t *testing.T) {
	for _, kind := range []bridge.TransactionType{bridge.TransactionType_ethereum, bridge.TransactionType_koinos} {
		t.Run(kind.String(), func(t *testing.T) {
			f := newSignatureFixture(t, kind)
			tx := f.signed(1)
			tx.Status = bridge.TransactionStatus_completed
			tx.CompletionTransactionId = "peer-asserted-completion"
			w := f.submit(tx, time.Now().Add(time.Minute).UnixMilli())
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			saved, _ := f.db.Get(f.id)
			if saved.Status != bridge.TransactionStatus_gathering_signatures || saved.CompletionTransactionId != "" {
				t.Fatal("peer asserted completion accepted", saved)
			}
			w = f.submit(f.signed(3), time.Now().Add(time.Minute).UnixMilli())
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			saved, _ = f.db.Get(f.id)
			if len(saved.Signatures) != 3 || saved.Status != bridge.TransactionStatus_signed {
				t.Fatal("valid configured threshold did not progress", saved)
			}
			// Actual locally retained completion remains authoritative over peer status.
			saved.Status = bridge.TransactionStatus_completed
			saved.CompletionTransactionId = "locally-observed"
			if kind == bridge.TransactionType_koinos {
				for i := range saved.Validators {
					saved.Validators[i] = strings.ToLower(saved.Validators[i])
				}
			}
			f.db.Put(f.id, saved)
			w = f.submit(f.signed(1), time.Now().Add(time.Minute).UnixMilli())
			if w.Code != 200 {
				t.Fatal(w.Code)
			}
			_, ownSignature := f.signature(0)
			if w.Body.String() != ownSignature {
				t.Fatal("completed record failed canonical signer lookup")
			}
			saved, _ = f.db.Get(f.id)
			if saved.CompletionTransactionId != "locally-observed" || saved.Status != bridge.TransactionStatus_completed {
				t.Fatal("local completion overwritten")
			}
		})
	}
}
func TestSignatureAPIRejectsMalformedAuthenticatedInputs(t *testing.T) {
	for _, kind := range []bridge.TransactionType{bridge.TransactionType_ethereum, bridge.TransactionType_koinos} {
		for _, name := range []string{"duplicate", "malformed-signature", "wrong-digest-signature", "unknown-member", "mismatched-arrays", "bad-payment", "expired-transfer", "expired-envelope", "future-envelope", "nil-transfer", "corrupt-stored-arrays"} {
			t.Run(kind.String()+"/"+name, func(t *testing.T) {
				f := newSignatureFixture(t, kind)
				tx := f.signed(1)
				expiry := time.Now().Add(time.Minute).UnixMilli()
				status := 400
				switch name {
				case "duplicate":
					tx.Validators = append(tx.Validators, tx.Validators[0])
					tx.Signatures = append(tx.Signatures, tx.Signatures[0])
				case "malformed-signature":
					tx.Signatures[0] = "0x00"
				case "wrong-digest-signature":
					other := f
					different := sha256.Sum256([]byte("different digest, same signer"))
					other.hash = different[:]
					_, tx.Signatures[0] = other.signature(0)
				case "unknown-member":
					other := newSignatureFixture(t, kind)
					tx.Validators[0], tx.Signatures[0] = other.signature(0)
				case "mismatched-arrays":
					tx.Signatures = nil
				case "bad-payment":
					tx.Payment = "not-a-number"
				case "expired-transfer":
					tx.Expiration = 1
				case "expired-envelope":
					expiry = 1
				case "future-envelope":
					expiry = time.Now().Add(3 * time.Minute).UnixMilli()
				case "nil-transfer":
					tx = nil
				case "corrupt-stored-arrays":
					bad := f.signed(1)
					bad.Signatures = nil
					f.db.Put(f.id, bad)
					status = 409
				}
				w := f.submit(tx, expiry)
				if w.Code != status {
					t.Fatal(w.Code, w.Body.String())
				}
				saved, _ := f.db.Get(f.id)
				if name != "corrupt-stored-arrays" && saved != nil {
					t.Fatal("rejected input modified storage")
				}
			})
		}
	}
	f := newSignatureFixture(t, bridge.TransactionType_ethereum)
	w := httptest.NewRecorder()
	f.api.SubmitSignature(w, httptest.NewRequest("POST", "/SubmitSignature", strings.NewReader(strings.Repeat("x", (1<<20)+2))))
	if w.Code != 400 {
		t.Fatal("oversized body accepted")
	}
}

// Exercise the actual broadcaster and SubmitSignature handler over loopback,
// using freshly generated keys and an independently retained peer signature.
func TestSignaturePeerHTTPInteroperability(t *testing.T) {
	for _, kind := range []bridge.TransactionType{bridge.TransactionType_ethereum, bridge.TransactionType_koinos} {
		t.Run(kind.String(), func(t *testing.T) {
			f := newSignatureFixture(t, kind)
			local := f.signed(1)
			if err := f.db.Put(f.id, local); err != nil {
				t.Fatal(err)
			}
			peer := httptest.NewServer(http.HandlerFunc(f.api.SubmitSignature))
			defer peer.Close()
			offline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer offline.Close()
			members := map[string]util.ValidatorConfig{}
			for i, m := range f.members {
				if i == 0 {
					m.ApiUrl = peer.URL
				}
				if i == 2 {
					m.ApiUrl = offline.URL
				}
				members[m.KoinosAddress] = m
				members[m.EthereumAddress] = m
			}
			// The sender is member 1; member 0's existing signature is returned by the API.
			tx := f.signed(0)
			a, s := f.signature(1)
			tx.Validators = []string{a}
			tx.Signatures = []string{s}
			// Keep member 2 in the configured three-member set but make its peer
			// endpoint unavailable. Two signatures must still satisfy 2-of-3.
			replies, err := util.BroadcastTransaction(tx, crypto.FromECDSA(f.keys[1]), f.members[1].KoinosAddress, members)
			_, want := f.signature(0)
			if err != nil || len(replies) != 1 || replies[f.members[0].KoinosAddress] != want {
				t.Fatal("valid peer interoperability failed", err)
			}
			saved, err := f.db.Get(f.id)
			if err != nil || saved == nil || len(saved.Signatures) != 2 || saved.Status != bridge.TransactionStatus_signed {
				t.Fatal("incorrect merged evidence", err, saved)
			}
		})
	}
}
