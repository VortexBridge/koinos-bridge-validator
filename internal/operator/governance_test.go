package operator

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/mr-tron/base58"
)

type vector struct {
	Profile  Profile `json:"profile"`
	Action   Action  `json:"action"`
	Preimage string  `json:"preimage"`
	Digest   string  `json:"digest"`
}

func vectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile("testdata/governance.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	return data.Vectors
}

func TestIndependentGovernanceVectors(t *testing.T) {
	vs := vectors(t)
	if len(vs) != 23 {
		t.Fatalf("expected 23 vectors, got %d", len(vs))
	}
	for _, v := range vs {
		t.Run(v.Profile.Family+"/"+v.Action.Kind+"/"+v.Digest[:8], func(t *testing.T) {
			got, err := EncodeAction(v.Profile, v.Action)
			if err != nil {
				t.Fatal(err)
			}
			if got.Preimage != v.Preimage || got.Digest != v.Digest {
				t.Fatalf("codec differs from ethers/protobufjs\ngot %+v\nwant %s %s", got, v.Preimage, v.Digest)
			}
		})
	}
}

func TestApprovalsRejectTamperingReplayAndRemovedSigners(t *testing.T) {
	for _, v := range []vector{vectors(t)[0], vectors(t)[12]} {
		t.Run(v.Profile.Family, func(t *testing.T) {
			payload, err := EncodeAction(v.Profile, v.Action)
			if err != nil {
				t.Fatal(err)
			}
			hash, _ := hex.DecodeString(payload.Digest)
			var members, sigs []string
			for i := byte(1); i <= 3; i++ {
				seed := make([]byte, 32)
				seed[31] = i // public synthetic fixtures, never funded
				if v.Profile.Family == "evm" {
					key, _ := crypto.ToECDSA(seed)
					members = append(members, crypto.PubkeyToAddress(key.PublicKey).Hex())
					sig, _ := crypto.Sign(hash, key)
					sig[64] += 27
					sigs = append(sigs, "0x"+hex.EncodeToString(sig))
				} else {
					key, pub := btcec.PrivKeyFromBytes(btcec.S256(), seed)
					addr, _ := util.KoinosPublicKeyToAddress(pub)
					members = append(members, base58.Encode(addr))
					sig, _ := btcec.SignCompact(btcec.S256(), key, hash, true)
					sigs = append(sigs, base64.URLEncoding.EncodeToString(sig))
				}
			}
			now := time.UnixMilli(1900000000000)
			if _, err := ValidateApprovals(v.Profile, payload, sigs[:2], members, v.Action.Nonce, now); err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				name          string
				payload       Payload
				sigs, members []string
				nonce         string
				now           time.Time
			}{
				{"below quorum", payload, sigs[:1], members, v.Action.Nonce, now},
				{"duplicate", payload, []string{sigs[0], sigs[0]}, members, v.Action.Nonce, now},
				{"removed signer", payload, sigs[:2], members[1:], v.Action.Nonce, now},
				{"nonce changed", payload, sigs[:2], members, "2", now},
				{"expired", payload, sigs[:2], members, v.Action.Nonce, time.UnixMilli(2000000000001)},
			}
			tampered := payload
			tampered.Preimage = "00"
			cases = append(cases, struct {
				name          string
				payload       Payload
				sigs, members []string
				nonce         string
				now           time.Time
			}{"tampered bytes", tampered, sigs[:2], members, v.Action.Nonce, now})
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					if _, err := ValidateApprovals(v.Profile, c.payload, c.sigs, c.members, c.nonce, c.now); err == nil {
						t.Fatal("accepted invalid approvals")
					}
				})
			}
			wrongNetwork := v.Profile
			wrongNetwork.NetworkID += "1"
			if _, err := RecoverSigner(wrongNetwork, payload, sigs[0]); err == nil {
				t.Fatal("accepted other profile/network")
			}
			for _, sig := range []string{"", "0x", "0x12", strings.Repeat("0", 132), "AAAA"} {
				if _, err := RecoverSigner(v.Profile, payload, sig); err == nil {
					t.Fatal("accepted malformed signature")
				}
			}
		})
	}
}

func TestAmbiguousActionsAndValuesRejected(t *testing.T) {
	for _, v := range vectors(t) {
		a := v.Action
		a.Nonce = "01"
		if _, err := EncodeAction(v.Profile, a); err == nil {
			t.Fatal("accepted noncanonical integer")
		}
		a = v.Action
		a.Expiration = "-1"
		if _, err := EncodeAction(v.Profile, a); err == nil {
			t.Fatal("accepted negative expiry")
		}
	}
	v := vectors(t)[12]
	v.Action.Kind = "claim_fee_wrapped_token"
	if _, err := EncodeAction(v.Profile, v.Action); err == nil {
		t.Fatal("enabled colliding legacy Koinos action")
	}
}
