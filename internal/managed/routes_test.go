package managed

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func routeFixture(t *testing.T) (*BidirectionalVerifier, *receiptFixture, *receiptFixture, Policy) {
	t.Helper()
	vectors := transferVectors(t)
	evm, koinos := vectors[0].Profile, vectors[3].Profile
	for _, p := range []*operator.Profile{&evm, &koinos} {
		p.Reviewed = true
		p.CodeHash = strings.Repeat("a", 64)
		p.ReviewEvidence = "synthetic bidirectional test"
	}
	reader := func(source, destination operator.Profile, transfer Transfer) *receiptFixture {
		return &receiptFixture{TransferObservation{ID: transfer.TransactionID + ":" + transfer.OperationID, SourceProfileDigest: source.Digest(), DestinationProfileDigest: destination.Digest(), ObservedAt: time.Now(), SourceBlockHash: strings.Repeat("b", 64), DestinationBlockHash: strings.Repeat("c", 64), SourceFinality: "finalized", DestinationFinality: "finalized", BridgeEventsInTransaction: 1, Transfer: transfer}}
	}
	forward := reader(evm, koinos, vectors[3].Transfer)
	reverseTransfer := vectors[0].Transfer
	// Deliberately collide the unqualified ID on both chains. Direction must keep
	// the operations distinct without changing destination signature encoding.
	reverseTransfer.TransactionID = forward.observation.Transfer.TransactionID
	reverseTransfer.OperationID = "0"
	reverse := reader(koinos, evm, reverseTransfer)
	v, e := NewBidirectionalVerifier(&fixtureVerifier{}, evm, koinos, forward, reverse)
	if e != nil {
		t.Fatal(e)
	}
	return v, forward, reverse, policy()
}
func TestBidirectionalRecoveryKeepsCollidingTransactionsDistinct(t *testing.T) {
	v, forward, reverse, p := routeFixture(t)
	ctx := context.Background()
	id := forward.observation.ID
	forwardID, reverseID := EVMToKoinos+"/"+id, KoinosToEVM+"/"+id
	a, e := v.Operation(ctx, p, forwardID)
	if e != nil {
		t.Fatal(e)
	}
	b, e := v.Operation(ctx, p, reverseID)
	if e != nil {
		t.Fatal(e)
	}
	if a.ID == b.ID || a.Family != "koinos" || b.Family != "evm" || a.Digest == b.Digest {
		t.Fatal("route identities conflated")
	}
	j := Journal{Schema: 1, PolicySHA256: Digest(p), Operations: map[string]Operation{a.ID: a, b.ID: b}}
	before, e := v.Reconcile(ctx, p, j)
	if e != nil {
		t.Fatal(e)
	}
	if j.Operations[a.ID].ID != a.ID || j.Operations[b.ID].ID != b.ID {
		t.Fatal("reconciliation mutated input journal")
	}
	forward.observation.Completed = true
	after, e := v.Reconcile(ctx, p, j)
	if e != nil || before == after {
		t.Fatal("forward completion absent from checkpoint", e)
	}
	reverse.observation.Transfer.Amount = "2"
	if _, e = v.Reconcile(ctx, p, j); e == nil {
		t.Fatal("reverse mismatch was ignored")
	}
}
func TestBidirectionalRecoveryRejectsUnqualifiedOrMisroutedJournal(t *testing.T) {
	for _, kind := range []string{"unqualified", "unknown-direction", "nested", "wrong-family", "record-id", "reverse-regression"} {
		t.Run(kind, func(t *testing.T) {
			v, forward, reverse, p := routeFixture(t)
			id := EVMToKoinos + "/" + forward.observation.ID
			op, e := v.Operation(context.Background(), p, id)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "unqualified":
				id = forward.observation.ID
				op.ID = id
			case "unknown-direction":
				id = "other/" + forward.observation.ID
				op.ID = id
			case "nested":
				id = "evm-to-koinos/extra/" + forward.observation.ID
				op.ID = id
			case "wrong-family":
				op.Family = "evm"
			case "record-id":
				op.ID = "another"
			case "reverse-regression":
				id = KoinosToEVM + "/" + reverse.observation.ID
				op, e = v.Operation(context.Background(), p, id)
				if e != nil {
					t.Fatal(e)
				}
				op.State = "completed"
			}
			if _, e = v.Reconcile(context.Background(), p, Journal{Operations: map[string]Operation{id: op}}); e == nil {
				t.Fatal("invalid journal accepted")
			}
		})
	}
}
