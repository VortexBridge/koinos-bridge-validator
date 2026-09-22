package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

const EVMToKoinos = "evm-to-koinos"
const KoinosToEVM = "koinos-to-evm"

// BidirectionalVerifier routes identifiers, never user-supplied transfer bodies.
// Direction is part of the journal identity; destination contract codecs remain
// unchanged. Existing unqualified journals require explicit reviewed migration.
type BidirectionalVerifier struct {
	base   Verifier
	routes map[string]*OperationVerifier
}

func NewBidirectionalVerifier(base Verifier, evm, koinos operator.Profile, toKoinos, toEVM TransferReader) (*BidirectionalVerifier, error) {
	if evm.Family != "evm" || koinos.Family != "koinos" {
		return nil, errors.New("EVM and Koinos profiles required")
	}
	forward, e := NewOperationVerifier(base, toKoinos, evm, koinos)
	if e != nil {
		return nil, e
	}
	reverse, e := NewOperationVerifier(base, toEVM, koinos, evm)
	if e != nil {
		return nil, e
	}
	return &BidirectionalVerifier{base, map[string]*OperationVerifier{EVMToKoinos: forward, KoinosToEVM: reverse}}, nil
}
func (v *BidirectionalVerifier) split(id string) (string, string, *OperationVerifier, error) {
	if len(id) > 128 {
		return "", "", nil, errors.New("operation identifier too long")
	}
	parts := strings.Split(id, "/")
	if len(parts) != 2 || parts[1] == "" {
		return "", "", nil, errors.New("direction-qualified operation identifier required")
	}
	reader, ok := v.routes[parts[0]]
	if !ok {
		return "", "", nil, errors.New("unknown bridge direction")
	}
	return parts[0], parts[1], reader, nil
}
func (v *BidirectionalVerifier) Inspect(ctx context.Context, p Policy) (Evidence, error) {
	return v.base.Inspect(ctx, p)
}
func (v *BidirectionalVerifier) Operation(ctx context.Context, p Policy, id string) (Operation, error) {
	_, local, route, e := v.split(id)
	if e != nil {
		return Operation{}, e
	}
	op, e := route.Operation(ctx, p, local)
	if e != nil {
		return Operation{}, e
	}
	op.ID = id
	return op, nil
}
func (v *BidirectionalVerifier) Reconcile(ctx context.Context, p Policy, j Journal) (string, error) {
	grouped := map[string]Journal{}
	for _, direction := range []string{EVMToKoinos, KoinosToEVM} {
		copy := j
		copy.Operations = map[string]Operation{}
		grouped[direction] = copy
	}
	for id, op := range j.Operations {
		direction, local, route, e := v.split(id)
		if e != nil {
			return "", e
		}
		if op.ID != id || op.Family != route.destination.Family {
			return "", errors.New("retained operation identity or direction mismatch")
		}
		op.ID = local
		grouped[direction].Operations[local] = op
	}
	// Both directions must reconcile successfully, including the empty side. A
	// changed/failing route never permits recovery using only the healthy side.
	checkpoints := []struct{ Direction, Checkpoint string }{}
	for _, direction := range []string{EVMToKoinos, KoinosToEVM} {
		checkpoint, e := v.routes[direction].Reconcile(ctx, p, grouped[direction])
		if e != nil {
			return "", e
		}
		checkpoints = append(checkpoints, struct{ Direction, Checkpoint string }{direction, checkpoint})
	}
	raw, _ := jsonBytes(checkpoints)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}
