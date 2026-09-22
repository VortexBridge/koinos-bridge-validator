package managed

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

type transferVector struct {
	Profile  operator.Profile `json:"profile"`
	Transfer Transfer         `json:"transfer"`
	Digest   string           `json:"digest"`
}

func transferVectors(t *testing.T) []transferVector {
	t.Helper()
	raw, e := os.ReadFile("testdata/transfers.json")
	if e != nil {
		t.Fatal(e)
	}
	var data struct {
		Vectors []transferVector `json:"vectors"`
	}
	if json.Unmarshal(raw, &data) != nil || len(data.Vectors) != 6 {
		t.Fatal("missing independent vectors")
	}
	return data.Vectors
}
func TestIndependentTransferCodecsIncludeUnsignedBoundaries(t *testing.T) {
	for _, v := range transferVectors(t) {
		t.Run(v.Profile.Family+"/"+v.Transfer.Amount, func(t *testing.T) {
			got, e := TransferDigest(v.Profile, v.Transfer)
			if e != nil || got != v.Digest {
				t.Fatalf("digest mismatch %s %v", got, e)
			}
		})
	}
}
func TestTransferCodecRejectsAmbiguityAndMalformedValues(t *testing.T) {
	for _, v := range transferVectors(t) {
		for _, bad := range []string{"-1", "01", "0x10", "18446744073709551616", "1.0", ""} {
			x := v.Transfer
			x.Amount = bad
			if _, e := TransferDigest(v.Profile, x); e == nil {
				t.Fatal("invalid amount accepted", bad)
			}
		}
		x := v.Transfer
		x.Payment = "18446744073709551616"
		if _, e := TransferDigest(v.Profile, x); e == nil {
			t.Fatal("overflow payment")
		}
		x = v.Transfer
		x.TransactionID = "abcd"
		if _, e := TransferDigest(v.Profile, x); e == nil {
			t.Fatal("short identity")
		}
		x = v.Transfer
		x.Recipient = "not-an-address"
		if _, e := TransferDigest(v.Profile, x); e == nil {
			t.Fatal("bad address")
		}
		x = v.Transfer
		x.Metadata = string([]byte{0xff})
		if _, e := TransferDigest(v.Profile, x); e == nil {
			t.Fatal("invalid metadata")
		}
		if v.Profile.Family == "koinos" {
			x = v.Transfer
			x.OperationID = "1"
			if _, e := TransferDigest(v.Profile, x); e == nil {
				t.Fatal("unsigned operation index accepted")
			}
		}
	}
}
