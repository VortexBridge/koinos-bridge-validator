package managed

import (
	"context"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"strings"
	"testing"
	"time"
)

type receiptFixture struct{ observation TransferObservation }

func (r *receiptFixture) ReadTransfer(ctx context.Context, id string) (TransferObservation, error) {
	return r.observation, nil
}
func operationFixture(t *testing.T) (*OperationVerifier, *receiptFixture, Policy, Operation) {
	t.Helper()
	vectors := transferVectors(t)
	source := vectors[0].Profile
	destination := vectors[3].Profile
	for _, p := range []*operator.Profile{&source, &destination} {
		p.Reviewed = true
		p.CodeHash = strings.Repeat("a", 64)
		p.ReviewEvidence = "synthetic source fixture"
	}
	transfer := vectors[3].Transfer
	id := transfer.TransactionID + ":" + transfer.OperationID
	reader := &receiptFixture{TransferObservation{ID: id, SourceProfileDigest: source.Digest(), DestinationProfileDigest: destination.Digest(), ObservedAt: time.Now(), SourceBlockHash: strings.Repeat("b", 64), DestinationBlockHash: strings.Repeat("c", 64), SourceFinality: "finalized", DestinationFinality: "finalized", BridgeEventsInTransaction: 1, Transfer: transfer}}
	v, e := NewOperationVerifier(&fixtureVerifier{}, reader, source, destination)
	if e != nil {
		t.Fatal(e)
	}
	return v, reader, policy(), Operation{ID: id, Family: "koinos", Digest: vectors[3].Digest, State: "signed"}
}
func TestTransferReconstructionAndCompleteJournalReconciliation(t *testing.T) {
	v, r, p, retained := operationFixture(t)
	ctx := context.Background()
	op, e := v.Operation(ctx, p, retained.ID)
	if e != nil || op.Digest != retained.Digest {
		t.Fatal("receipt reconstruction", e)
	}
	j := Journal{Schema: 1, PolicySHA256: Digest(p), Operations: map[string]Operation{retained.ID: retained}}
	first, e := v.Reconcile(ctx, p, j)
	if e != nil || !validHash(first) {
		t.Fatal("pending reconciliation", e)
	}
	r.observation.Completed = true
	second, e := v.Reconcile(ctx, p, j)
	if e != nil || first == second {
		t.Fatal("completion not bound to checkpoint", e)
	}
	r.observation.Transfer.Amount = "2"
	if _, e = v.Reconcile(ctx, p, j); e == nil {
		t.Fatal("changed transfer approved")
	}
}
func TestUnfinalizedAmbiguousStaleAndWrongRouteTransfersReject(t *testing.T) {
	cases := map[string]func(*TransferObservation){"source-head": func(r *TransferObservation) { r.SourceFinality = "head" }, "destination-head": func(r *TransferObservation) { r.DestinationFinality = "head" }, "wrong-route": func(r *TransferObservation) { r.SourceProfileDigest = strings.Repeat("0", 64) }, "stale": func(r *TransferObservation) { r.ObservedAt = time.Now().Add(-time.Minute) }, "multiple-events": func(r *TransferObservation) { r.BridgeEventsInTransaction = 2 }, "no-event": func(r *TransferObservation) { r.BridgeEventsInTransaction = 0 }, "expired": func(r *TransferObservation) { r.Transfer.Expiration = "1" }, "missing-root": func(r *TransferObservation) { r.SourceBlockHash = "" }, "identifier-alias": func(r *TransferObservation) { r.ID = "alias" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v, r, p, op := operationFixture(t)
			mutate(&r.observation)
			if _, e := v.Operation(context.Background(), p, op.ID); e == nil {
				t.Fatal("invalid receipt evidence accepted")
			}
		})
	}
}
func TestCompletedTransferCannotBecomePendingDuringRecovery(t *testing.T) {
	v, _, p, op := operationFixture(t)
	op.State = "completed"
	j := Journal{Schema: 1, PolicySHA256: Digest(p), Operations: map[string]Operation{op.ID: op}}
	if _, e := v.Reconcile(context.Background(), p, j); e == nil {
		t.Fatal("completed transfer reopened")
	}
}
