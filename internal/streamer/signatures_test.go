package streamer

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	bridge "github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/koinos/koinos-proto-golang/koinos/protocol"
	"github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func signatureMember(t *testing.T) (*ecdsa.PrivateKey, util.ValidatorConfig) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	kkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), crypto.FromECDSA(key))
	address, err := util.KoinosPublicKeyToAddress(kkey.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	return key, util.ValidatorConfig{EthereumAddress: crypto.PubkeyToAddress(key.PublicKey).Hex(), KoinosAddress: base58.Encode(address)}
}
func signTransfer(t *testing.T, tx *bridge.Transaction, key *ecdsa.PrivateKey) string {
	t.Helper()
	digest, err := util.TransferSignatureDigest(tx)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type == bridge.TransactionType_ethereum {
		return base64.URLEncoding.EncodeToString(util.SignKoinosHash(crypto.FromECDSA(key), digest))
	}
	return "0x" + hex.EncodeToString(util.SignEthereumHash(key, digest))
}
func signatureAddress(kind bridge.TransactionType, member util.ValidatorConfig) string {
	if kind == bridge.TransactionType_ethereum {
		return member.KoinosAddress
	}
	return member.EthereumAddress
}

// The peer changes the stored record while the streamer is unlocked for HTTP.
// Its reply is valid for the request, but must never enter a renewed record.
func TestStreamersVerifyPeerRepliesAgainstCurrentStoredTransfer(t *testing.T) {
	for _, kind := range []bridge.TransactionType{bridge.TransactionType_ethereum, bridge.TransactionType_koinos} {
		for _, scenario := range []string{"valid", "renewed-during-broadcast", "corrupt-during-broadcast"} {
			t.Run(kind.String()+"/"+scenario, func(t *testing.T) {
				localKey, local := signatureMember(t)
				peerKey, peer := signatureMember(t)
				db := store.NewTransactionsStore(store.NewMapBackend())
				var changed *bridge.Transaction
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					var request bridge.SubmittedSignature
					if err := protojson.Unmarshal(raw, &request); err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					reply := signTransfer(t, request.Transaction, peerKey)
					if scenario != "valid" {
						id := request.Transaction.Id
						if kind == bridge.TransactionType_koinos {
							id += "-" + request.Transaction.OpId
						}
						db.Lock()
						current, err := db.Get(id)
						if err != nil || current == nil {
							db.Unlock()
							t.Error("missing stored transfer")
							w.WriteHeader(500)
							return
						}
						if scenario == "renewed-during-broadcast" {
							digest := sha256.Sum256([]byte("new signing domain from concurrent renewal"))
							current.Hash = base64.URLEncoding.EncodeToString(digest[:])
							if kind == bridge.TransactionType_koinos {
								current.Hash = "0x" + hex.EncodeToString(digest[:])
							}
							current.Expiration += 60000
							current.Validators = []string{signatureAddress(kind, local)}
							current.Signatures = []string{signTransfer(t, current, localKey)}
						} else {
							current.Signatures = nil
						}
						current.Status = bridge.TransactionStatus_gathering_signatures
						if err := db.Put(id, current); err != nil {
							t.Error(err)
						}
						changed = proto.Clone(current).(*bridge.Transaction)
						db.Unlock()
					}
					w.Write([]byte(reply))
				}))
				defer server.Close()
				peer.ApiUrl = server.URL
				members := map[string]util.ValidatorConfig{local.KoinosAddress: local, local.EthereumAddress: local, peer.KoinosAddress: peer, peer.EthereumAddress: peer}
				token := common.HexToAddress("0x1111111111111111111111111111111111111111")
				tokens := map[string]util.TokenConfig{token.Hex(): {KoinosAddress: local.KoinosAddress}, local.KoinosAddress: {EthereumAddress: token.Hex()}}
				now := uint64(time.Now().UnixMilli())
				id := ""
				if kind == bridge.TransactionType_ethereum {
					eventABI, err := abi.JSON(strings.NewReader(`[{"type":"event","name":"TokensLockedEvent","inputs":[{"name":"from","type":"address"},{"name":"token","type":"address"},{"name":"amount","type":"uint256"},{"name":"payment","type":"uint256"},{"name":"relayer","type":"string"},{"name":"recipient","type":"string"},{"name":"metadata","type":"string"},{"name":"blocktime","type":"uint256"},{"name":"chain","type":"uint32"}]}]`))
					if err != nil {
						t.Fatal(err)
					}
					data, err := eventABI.Events["TokensLockedEvent"].Inputs.Pack(token, token, big.NewInt(50), big.NewInt(1), local.KoinosAddress, peer.KoinosAddress, "", new(big.Int).SetUint64(now), uint32(1))
					if err != nil {
						t.Fatal(err)
					}
					event := types.Log{Data: data, TxHash: common.HexToHash("0x01"), BlockNumber: 9}
					id = event.TxHash.Hex()
					processEthereumTokensLockedEvent(crypto.FromECDSA(localKey), local.KoinosAddress, []byte{1}, tokens, db, 60000, members, event, eventABI)
				} else {
					tokenAddress, _ := base58.Decode(local.KoinosAddress)
					payload, err := proto.Marshal(&bridge.TokensLockedEvent{From: []byte{1}, Token: tokenAddress, Amount: "50", Payment: "1", Recipient: peer.EthereumAddress, Relayer: local.EthereumAddress, ChainId: 1})
					if err != nil {
						t.Fatal(err)
					}
					block := &block_store.BlockItem{BlockHeight: 9, Block: &protocol.Block{Header: &protocol.BlockHeader{Timestamp: now, Height: 9}}}
					receipt := &protocol.TransactionReceipt{Id: []byte{2}}
					id = "0x02-1"
					processKoinosTokensLockedEvent(localKey, local.EthereumAddress, crypto.FromECDSA(localKey), local.KoinosAddress, token, tokens, db, 60000, members, block, receipt, &protocol.EventData{Data: payload, Sequence: 1})
				}
				saved, err := db.Get(id)
				if err != nil || saved == nil {
					t.Fatal("missing transfer", err)
				}
				if scenario == "valid" {
					verified, err := util.VerifyTransferSignatures(saved, members)
					if err != nil || len(verified) != 2 || saved.Status != bridge.TransactionStatus_signed {
						t.Fatal("valid peer signatures did not progress", err)
					}
				} else if changed == nil || !proto.Equal(saved, changed) {
					t.Fatal("stale reply or corrupt retained evidence changed stored transfer")
				}
				// Unlock was not leaked by a failed merge.
				db.Lock()
				db.Unlock()
			})
		}
	}
}

func TestMergePeerSignaturesRejectsCorruptAndUnknownWithoutMutation(t *testing.T) {
	for _, kind := range []bridge.TransactionType{bridge.TransactionType_ethereum, bridge.TransactionType_koinos} {
		key, member := signatureMember(t)
		digest := sha256.Sum256([]byte("retained evidence"))
		tx := &bridge.Transaction{Type: kind, Hash: base64.URLEncoding.EncodeToString(digest[:])}
		if kind == bridge.TransactionType_koinos {
			tx.Hash = "0x" + hex.EncodeToString(digest[:])
		}
		tx.Validators = []string{signatureAddress(kind, member)}
		tx.Signatures = []string{signTransfer(t, tx, key)}
		members := map[string]util.ValidatorConfig{"arbitrary-config-key": member}
		before := proto.Clone(tx)
		if err := mergePeerSignatures(tx, map[string]string{member.KoinosAddress: tx.Signatures[0]}, members); err != nil || len(tx.Signatures) != 1 {
			t.Fatal("valid deduplicated merge failed", err)
		}
		for _, replies := range []map[string]string{{"unconfigured": tx.Signatures[0]}, {member.KoinosAddress: "invalid"}} {
			if err := mergePeerSignatures(tx, replies, members); err == nil || !proto.Equal(tx, before) {
				t.Fatal("invalid merge accepted or mutated record")
			}
		}
		tx.Signatures = nil
		before = proto.Clone(tx)
		if err := mergePeerSignatures(tx, nil, members); err == nil || !proto.Equal(tx, before) {
			t.Fatal("corrupt retained evidence accepted")
		}
	}
}

func TestRenewalValidatesRetainedEvidenceBeforeSigning(t *testing.T) {
	for _, kind := range []bridge.TransactionType{bridge.TransactionType_ethereum, bridge.TransactionType_koinos} {
		for _, scenario := range []string{"valid", "mismatched-arrays", "unknown-signer", "duplicate-signer"} {
			t.Run(kind.String()+"/"+scenario, func(t *testing.T) {
				localKey, local := signatureMember(t)
				peerKey, peer := signatureMember(t)
				db := store.NewTransactionsStore(store.NewMapBackend())
				var calls int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&calls, 1)
					raw, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					var request bridge.SubmittedSignature
					if err := protojson.Unmarshal(raw, &request); err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					w.Write([]byte(signTransfer(t, request.Transaction, peerKey)))
				}))
				defer server.Close()
				peer.ApiUrl = server.URL
				members := map[string]util.ValidatorConfig{local.KoinosAddress: local, local.EthereumAddress: local, peer.KoinosAddress: peer, peer.EthereumAddress: peer}
				token := common.HexToAddress("0x1111111111111111111111111111111111111111")
				contract, _ := base58.Decode(local.KoinosAddress)
				now := uint64(time.Now().UnixMilli())
				tx := &bridge.Transaction{Type: kind, Id: "0x" + strings.Repeat("ab", 32), OpId: "1", KoinosToken: local.KoinosAddress, EthToken: token.Hex(), Amount: "50", Payment: "1", ToChain: "1", Expiration: now - 180000, Status: bridge.TransactionStatus_gathering_signatures}
				id := tx.Id
				if kind == bridge.TransactionType_ethereum {
					tx.Recipient = peer.KoinosAddress
					recipient, _ := base58.Decode(tx.Recipient)
					payload, err := proto.Marshal(&bridge.CompleteTransferHash{Action: bridge.ActionId_complete_transfer, TransactionId: common.FromHex(tx.Id), Token: contract, Recipient: recipient, Amount: 50, Payment: 1, ContractId: contract, Expiration: tx.Expiration, Chain: 1})
					if err != nil {
						t.Fatal(err)
					}
					hash := sha256.Sum256(payload)
					tx.Hash = base64.URLEncoding.EncodeToString(hash[:])
				} else {
					tx.Id = "0x1220" + strings.Repeat("ab", 32)
					id = tx.Id + "-1"
					tx.Recipient = peer.EthereumAddress
					tx.Relayer = local.EthereumAddress
					_, hash := util.GenerateEthereumCompleteTransferHash(common.FromHex(tx.Id), 1, token.Bytes(), common.FromHex(tx.Recipient), common.FromHex(tx.Relayer), tx.Payment, tx.Amount, token, "", tx.Expiration, 1)
					tx.Hash = hash.Hex()
				}
				tx.Validators = []string{signatureAddress(kind, local)}
				tx.Signatures = []string{signTransfer(t, tx, localKey)}
				switch scenario {
				case "mismatched-arrays":
					tx.Signatures = nil
				case "unknown-signer":
					unknownKey, unknown := signatureMember(t)
					tx.Validators = []string{signatureAddress(kind, unknown)}
					tx.Signatures = []string{signTransfer(t, tx, unknownKey)}
				case "duplicate-signer":
					tx.Validators = append(tx.Validators, tx.Validators[0])
					tx.Signatures = append(tx.Signatures, tx.Signatures[0])
				}
				if err := db.Put(id, tx); err != nil {
					t.Fatal(err)
				}
				before := proto.Clone(tx)
				if kind == bridge.TransactionType_ethereum {
					eventABI, err := abi.JSON(strings.NewReader(`[{"type":"event","name":"RequestNewSignaturesEvent","inputs":[{"name":"txId","type":"bytes"},{"name":"blocktime","type":"uint256"}]}]`))
					if err != nil {
						t.Fatal(err)
					}
					data, err := eventABI.Events["RequestNewSignaturesEvent"].Inputs.Pack(common.FromHex(tx.Id), new(big.Int).SetUint64(now))
					if err != nil {
						t.Fatal(err)
					}
					processEthereumRequestNewSignaturesEvent(crypto.FromECDSA(localKey), local.KoinosAddress, contract, nil, db, 60000, members, types.Log{Data: data, BlockNumber: 10}, eventABI)
				} else {
					data, err := proto.Marshal(&bridge.RequestNewSignaturesEvent{TransactionId: tx.Id, OperationId: "1"})
					if err != nil {
						t.Fatal(err)
					}
					block := &block_store.BlockItem{BlockHeight: 10, Block: &protocol.Block{Header: &protocol.BlockHeader{Timestamp: now, Height: 10}}}
					processRequestNewSignaturesEvent(db, block, &protocol.TransactionReceipt{}, &protocol.EventData{Data: data}, 60000, localKey, local.EthereumAddress, crypto.FromECDSA(localKey), local.KoinosAddress, token, members)
				}
				saved, err := db.Get(id)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "valid" {
					verified, err := util.VerifyTransferSignatures(saved, members)
					if err != nil || len(verified) != 2 || saved.Hash == tx.Hash || saved.Expiration != now+60000 || atomic.LoadInt32(&calls) != 1 {
						t.Fatal("valid renewal failed", err)
					}
				} else if !proto.Equal(saved, before) || atomic.LoadInt32(&calls) != 0 {
					t.Fatal("invalid retained record renewed or broadcast")
				}
				db.Lock()
				db.Unlock()
			})
		}
	}
}
