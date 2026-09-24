package managed

import (
	"context"
	"fmt"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

// GovernanceObservationProvider upgrades reviewed local Koinos bindings to a
// snapshot pinned to the live irreversible block. EVM bindings continue through
// the default finalized-block observer. Replica endpoints remain private local
// process configuration and never appear in returned observations.
func GovernanceObservationProvider(replica, membershipSeed string) operator.ObservationProvider {
	return func(ctx context.Context, binding operator.Binding) operator.Observation {
		if binding.Profile.Family != "koinos" {
			return operator.Observe(ctx, binding)
		}
		out := operator.Observation{ProfileID: binding.Profile.ID, Status: "unavailable", Finality: "unknown", Validators: []string{}}
		snapshot, err := NewKoinosSnapshot(binding, replica)
		if err != nil {
			out.Message = err.Error()
			return out
		}
		state, err := snapshot.Read(ctx, membershipSeed, nil)
		if err != nil {
			out.Message = err.Error()
			return out
		}
		paused := state.Paused
		out.Complete = true
		out.ObservedAt = state.ObservedAt.UTC()
		out.Status = "observed"
		out.Message = "Finalized Koinos state verified against the live irreversible block and a separately pinned replica."
		out.NetworkID = binding.Profile.NetworkID
		out.Block = fmt.Sprint(state.Height)
		out.BlockHash = state.BlockHash
		out.Finality = "finalized"
		out.CodeHash = state.CodeHash
		out.Nonce = fmt.Sprint(state.Nonce)
		out.BridgeChainID = binding.Profile.BridgeChainID
		out.Paused = &paused
		out.Validators = append([]string{}, state.Validators...)
		out.Quorum = operator.Quorum(len(state.Validators))
		out.GovernanceReady = state.ProfileDigest == binding.Profile.Digest() && len(state.Validators) > 0
		return out
	}
}
