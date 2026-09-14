package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	bridge "github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/mr-tron/base58"
)

func TestBroadcastRejectsInvalidPeerSignature(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	kkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), crypto.FromECDSA(key))
	address, _ := KoinosPublicKeyToAddress(kkey.PubKey())
	hash := sha256.Sum256([]byte("synthetic transfer"))
	for _, family := range []bridge.TransactionType{bridge.TransactionType_ethereum, bridge.TransactionType_koinos} {
		t.Run(family.String(), func(t *testing.T) {
			hashText := base64.URLEncoding.EncodeToString(hash[:])
			if family == bridge.TransactionType_koinos {
				hashText = "0x" + hex.EncodeToString(hash[:])
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not a signature")) }))
			defer server.Close()
			cfg := ValidatorConfig{EthereumAddress: crypto.PubkeyToAddress(key.PublicKey).Hex(), KoinosAddress: base58.Encode(address), ApiUrl: server.URL}
			tx := &bridge.Transaction{Type: family, Id: "synthetic", Hash: hashText, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())}
			got, err := BroadcastTransaction(tx, crypto.FromECDSA(key), "a-different-local-identity", map[string]ValidatorConfig{"peer": cfg})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Fatal("unverified peer response accepted")
			}
		})
	}
}
func TestEthereumRecoveryRejectsMalformedWithoutPanic(t *testing.T) {
	hash := sha256.Sum256([]byte("fixture"))
	for _, signature := range []string{"", "x", "0x", "0x00", "zz" + strings.Repeat("0", 130), "0x" + strings.Repeat("g", 130), "0x" + strings.Repeat("0", 130)} {
		func() {
			defer func() {
				if recover() != nil {
					t.Error("malformed signature caused panic")
				}
			}()
			if _, err := RecoverEthereumAddressFromSignature(signature, hash[:]); err == nil {
				t.Error("malformed signature accepted")
			}
		}()
	}
}

func TestSignatureRecoveryAndPeerTransport(t *testing.T) {
	key, _ := crypto.GenerateKey()
	wrongKey, _ := crypto.GenerateKey()
	kkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), crypto.FromECDSA(key))
	address, _ := KoinosPublicKeyToAddress(kkey.PubKey())
	cfg := ValidatorConfig{EthereumAddress: crypto.PubkeyToAddress(key.PublicKey).Hex(), KoinosAddress: base58.Encode(address)}
	hash := sha256.Sum256([]byte("synthetic transport transfer"))
	wrongHash := sha256.Sum256([]byte("different transfer"))
	for _, kind := range []bridge.TransactionType{bridge.TransactionType_ethereum, bridge.TransactionType_koinos} {
		t.Run(kind.String(), func(t *testing.T) {
			sign := func(otherKey bool, digest []byte) string {
				selected := key
				if otherKey {
					selected = wrongKey
				}
				if kind == bridge.TransactionType_ethereum {
					return base64.URLEncoding.EncodeToString(SignKoinosHash(crypto.FromECDSA(selected), digest))
				}
				return "0x" + hex.EncodeToString(SignEthereumHash(selected, digest))
			}
			valid := sign(false, hash[:])
			recovered, err := recoverTransferSigner(kind, valid, hash[:])
			if err != nil || recovered != transferValidatorAddress(kind, cfg) {
				t.Fatal("valid signature failed", err)
			}
			if _, err := recoverTransferSigner(kind, valid, hash[:31]); err == nil {
				t.Fatal("short digest accepted")
			}
			for _, name := range []string{"valid", "wrong-signer", "wrong-digest", "oversized", "redirect", "error-status", "empty"} {
				t.Run(name, func(t *testing.T) {
					var calls, redirected int32
					destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&redirected, 1); w.Write([]byte(valid)) }))
					defer destination.Close()
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						atomic.AddInt32(&calls, 1)
						switch name {
						case "valid":
							w.Write([]byte(valid + "\n"))
						case "wrong-signer":
							w.Write([]byte(sign(true, hash[:])))
						case "wrong-digest":
							w.Write([]byte(sign(false, wrongHash[:])))
						case "oversized":
							w.Write([]byte(valid + strings.Repeat(" ", 257)))
						case "redirect":
							http.Redirect(w, r, destination.URL, 302)
						case "error-status":
							w.WriteHeader(503)
							w.Write([]byte(valid))
						}
					}))
					defer server.Close()
					member := cfg
					member.ApiUrl = server.URL
					digest := base64.URLEncoding.EncodeToString(hash[:])
					if kind == bridge.TransactionType_koinos {
						digest = "0x" + hex.EncodeToString(hash[:])
					}
					tx := &bridge.Transaction{Type: kind, Hash: digest, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())}
					got, err := BroadcastTransaction(tx, crypto.FromECDSA(key), "separate-local-identity", map[string]ValidatorConfig{"alias1": member, "alias2": member})
					if err != nil {
						t.Fatal(err)
					}
					if name == "valid" {
						if got[cfg.KoinosAddress] != valid || len(got) != 1 {
							t.Fatal("valid peer response lost")
						}
					} else if len(got) != 0 {
						t.Fatal("unverified peer response accepted")
					}
					if atomic.LoadInt32(&calls) != 1 || atomic.LoadInt32(&redirected) != 0 {
						t.Fatal("duplicate request or followed redirect")
					}
				})
			}
		})
	}
}

func TestEthereumRejectsInvalidSignatureValues(t *testing.T) {
	key, _ := crypto.GenerateKey()
	hash := sha256.Sum256([]byte("synthetic malleability test"))
	signature := SignEthereumHash(key, hash[:])
	for _, name := range []string{"recovery-2", "recovery-29", "zero-r", "zero-s"} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), signature...)
			switch name {
			case "recovery-2":
				raw[64] = 2
			case "recovery-29":
				raw[64] = 29
			case "zero-r":
				copy(raw[:32], make([]byte, 32))
			case "zero-s":
				copy(raw[32:64], make([]byte, 32))
			}
			if _, err := RecoverEthereumAddressFromSignature("0x"+hex.EncodeToString(raw), hash[:]); err == nil {
				t.Fatal("invalid signature accepted")
			}
		})
	}
}

func TestKoinosRejectsMalformedSignatures(t *testing.T) {
	hash := sha256.Sum256([]byte("synthetic Koinos test"))
	for _, signature := range []string{"", "x", strings.Repeat("A", 88), strings.Repeat("!", 88), base64.URLEncoding.EncodeToString(make([]byte, 65)), strings.Repeat("A", 86) + "=="} {
		if _, err := RecoverKoinosAddressFromSignature(signature, hash[:]); err == nil {
			t.Fatal("invalid Koinos signature accepted")
		}
	}
}

func TestTransferVerificationDistinctCanonicalConfiguredMembers(t *testing.T) {
	key, _ := crypto.GenerateKey()
	hash := sha256.Sum256([]byte("distinct members test"))
	member := ValidatorConfig{EthereumAddress: crypto.PubkeyToAddress(key.PublicKey).Hex()}
	sig := "0x" + hex.EncodeToString(SignEthereumHash(key, hash[:]))
	tx := &bridge.Transaction{Type: bridge.TransactionType_koinos, Hash: "0x" + hex.EncodeToString(hash[:]), Validators: []string{strings.ToLower(member.EthereumAddress)}, Signatures: []string{sig}}
	members := map[string]ValidatorConfig{"arbitrary-key": member, "duplicate-config-alias": member}
	verified, err := VerifyTransferSignatures(tx, members)
	if err != nil || verified[member.EthereumAddress] != sig || len(verified) != 1 {
		t.Fatal("canonical identity not retained", err)
	}
	tx.Validators = append(tx.Validators, member.EthereumAddress)
	tx.Signatures = append(tx.Signatures, sig)
	if _, err := VerifyTransferSignatures(tx, members); err == nil {
		t.Fatal("case alias counted twice")
	}
	tx.Validators = tx.Validators[:1]
	tx.Signatures = tx.Signatures[:1]
	if _, err := VerifyTransferSignatures(tx, map[string]ValidatorConfig{member.EthereumAddress: {}}); err == nil {
		t.Fatal("map key trusted instead of configured identity")
	}
	tx.Signatures = nil
	if _, err := VerifyTransferSignatures(tx, members); err == nil {
		t.Fatal("mismatched arrays accepted")
	}
}

func TestBroadcastRejectsInvalidTransferBeforeContactingPeers(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&calls, 1) }))
	defer server.Close()
	key, _ := crypto.GenerateKey()
	members := map[string]ValidatorConfig{"peer": {ApiUrl: server.URL, KoinosAddress: "different"}}
	for _, tx := range []*bridge.Transaction{nil, {Type: bridge.TransactionType_koinos, Hash: "0x"}, {Type: bridge.TransactionType_ethereum, Hash: base64.URLEncoding.EncodeToString(make([]byte, 32)), Expiration: 1}, {Type: bridge.TransactionType_koinos, Hash: "0x" + strings.Repeat("0", 64), Expiration: uint64(time.Now().Add(time.Minute).UnixMilli()), Validators: []string{"unmatched"}}} {
		if _, err := BroadcastTransaction(tx, crypto.FromECDSA(key), "local", members); err == nil {
			t.Fatal("invalid transfer accepted")
		}
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatal("invalid transfer contacted peers")
	}
}

func TestEthereumContractAcceptedVariantsRecoverOneIdentity(t *testing.T) {
	key, _ := crypto.GenerateKey()
	hash := sha256.Sum256([]byte("Bridge.sol recoverSigner compatibility"))
	raw := SignEthereumHash(key, hash[:])
	address := crypto.PubkeyToAddress(key.PublicKey).Hex()
	canonical := "0x" + hex.EncodeToString(raw)
	for _, name := range []string{"zero-based-v", "high-s", "high-s-zero-based-v"} {
		t.Run(name, func(t *testing.T) {
			variant := append([]byte(nil), raw...)
			if strings.HasPrefix(name, "high-s") {
				highS := new(big.Int).Sub(crypto.S256().Params().N, new(big.Int).SetBytes(variant[32:64]))
				copy(variant[32:64], common.LeftPadBytes(highS.Bytes(), 32))
				variant[64] = 27 + (1 - (variant[64] - 27))
			}
			if strings.HasSuffix(name, "zero-based-v") {
				variant[64] -= 27
			}
			signature := "0x" + hex.EncodeToString(variant)
			recovered, err := RecoverEthereumAddressFromSignature(signature, hash[:])
			if err != nil || recovered != address {
				t.Fatal("contract-accepted variant rejected", err)
			}
			tx := &bridge.Transaction{Type: bridge.TransactionType_koinos, Hash: "0x" + hex.EncodeToString(hash[:]), Validators: []string{address, strings.ToLower(address)}, Signatures: []string{canonical, signature}}
			if _, err := VerifyTransferSignatures(tx, map[string]ValidatorConfig{"member": {EthereumAddress: address}, "other-member": {EthereumAddress: "0x1111111111111111111111111111111111111111"}}); err == nil {
				t.Fatal("same signer counted twice using signature variant")
			}
		})
	}
}
