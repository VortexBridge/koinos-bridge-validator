package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

// TransferObservation is built by an independent chain reader from source
// receipts, configured token mapping and finalized destination status. It never
// accepts a digest supplied by a peer. Public RPC adapters remain separate work.
type TransferObservation struct {
	ID                        string
	SourceProfileDigest       string
	DestinationProfileDigest  string
	ObservedAt                time.Time
	SourceBlockHash           string
	DestinationBlockHash      string
	SourceFinality            string
	DestinationFinality       string
	BridgeEventsInTransaction uint32
	Completed                 bool
	Transfer                  Transfer
}
type TransferReader interface {
	ReadTransfer(context.Context, string) (TransferObservation, error)
}

// OperationVerifier replaces a verifier's opaque operation callback with typed,
// independently reconstructed transfer encoding and full-journal reconciliation.
type OperationVerifier struct {
	base        Verifier
	reader      TransferReader
	source      operator.Profile
	destination operator.Profile
}

func NewOperationVerifier(base Verifier, reader TransferReader, source, destination operator.Profile) (*OperationVerifier, error) {
	if base == nil || reader == nil || source.Validate() != nil || destination.Validate() != nil || source.Environment != "local" || destination.Environment != "local" || !source.Reviewed || !destination.Reviewed || source.Family == destination.Family {
		return nil, errors.New("two reviewed local profiles and independent transfer reader required")
	}
	return &OperationVerifier{base, reader, source, destination}, nil
}
func (v *OperationVerifier) Inspect(ctx context.Context, p Policy) (Evidence, error) {
	return v.base.Inspect(ctx, p)
}
func (v *OperationVerifier) read(ctx context.Context, id string) (Operation, TransferObservation, error) {
	r, e := v.reader.ReadTransfer(ctx, id)
	if e != nil || ctx.Err() != nil {
		return Operation{}, r, errors.New("transfer receipt evidence unavailable")
	}
	now := time.Now()
	if r.ID != id || id != r.Transfer.TransactionID+":"+r.Transfer.OperationID || r.SourceProfileDigest != v.source.Digest() || r.DestinationProfileDigest != v.destination.Digest() || r.ObservedAt.After(now) || now.Sub(r.ObservedAt) > 15*time.Second || r.SourceFinality != "finalized" || r.DestinationFinality != "finalized" || !validHash(r.SourceBlockHash) || !validHash(r.DestinationBlockHash) {
		return Operation{}, r, errors.New("transfer evidence is stale, unfinalized or from another route")
	}
	if r.BridgeEventsInTransaction == 0 || (v.destination.Family == "koinos" && r.BridgeEventsInTransaction != 1) {
		return Operation{}, r, errors.New("ambiguous source transaction event identity")
	}
	digest, e := TransferDigest(v.destination, r.Transfer)
	if e != nil {
		return Operation{}, r, e
	}
	expiry, _ := uint64Value(r.Transfer.Expiration)
	if !r.Completed && expiry.Uint64() <= uint64(now.UnixMilli()) {
		return Operation{}, r, errors.New("pending transfer signature deadline expired")
	}
	state := "pending"
	if r.Completed {
		state = "completed"
	}
	return Operation{ID: id, Family: v.destination.Family, Digest: digest, State: state, ObservedAt: r.ObservedAt, SourceBlockHash: r.SourceBlockHash, DestinationBlockHash: r.DestinationBlockHash, SourceFinality: r.SourceFinality, DestinationFinality: r.DestinationFinality, ExpiresAt: r.Transfer.Expiration}, r, nil
}
func (v *OperationVerifier) Operation(ctx context.Context, p Policy, id string) (Operation, error) {
	op, _, err := v.read(ctx, id)
	return op, err
}
func (v *OperationVerifier) Reconcile(ctx context.Context, p Policy, j Journal) (string, error) {
	// This layer owns complete retained-operation verification below. The base
	// certifies only the route/chain anchor, never unexamined operation records.
	anchorJournal := clone(j)
	anchorJournal.Operations = nil
	checkpoint, e := v.base.Reconcile(ctx, p, anchorJournal)
	if e != nil || !validHash(checkpoint) {
		return "", errors.New("source checkpoints are not reconciled")
	}
	ids := make([]string, 0, len(j.Operations))
	for id := range j.Operations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// Bind the new checkpoint to every retained operation and both finalized roots.
	entries := []struct{ ID, Digest, State, Source, Destination string }{}
	for _, id := range ids {
		old := j.Operations[id]
		current, r, e := v.read(ctx, id)
		if e != nil {
			return "", e
		}
		if current.Digest != old.Digest || current.Family != old.Family || (old.State == "completed" && current.State != "completed") {
			return "", errors.New("retained operation conflicts with finalized receipts")
		}
		entries = append(entries, struct{ ID, Digest, State, Source, Destination string }{id, current.Digest, current.State, r.SourceBlockHash, r.DestinationBlockHash})
	}
	raw, _ := jsonBytes(struct {
		Checkpoint string
		Entries    interface{}
	}{checkpoint, entries})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
