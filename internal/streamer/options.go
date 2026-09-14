package streamer

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
	"google.golang.org/protobuf/proto"
	"time"
)

type Options struct {
	ObserveOnly       bool
	ExpectedNetworkID string
	OnIdentityProblem func()
	OnProgress        func(uint64)
	OnProblem         func()
}

func (o Options) identity(ctx context.Context, read func(context.Context) (string, error)) bool {
	if o.ExpectedNetworkID == "" {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, err := read(ctx)
	if err != nil || id != o.ExpectedNetworkID {
		if o.OnIdentityProblem != nil {
			o.OnIdentityProblem()
		} else {
			o.problem()
		}
		return false
	}
	return true
}

func selectedOptions(options []Options) Options {
	if len(options) > 0 {
		return options[0]
	}
	return Options{}
}
func (o Options) progress(height uint64) {
	if o.OnProgress != nil {
		o.OnProgress(height)
	}
}
func (o Options) problem() {
	if o.OnProblem != nil {
		o.OnProblem()
	}
}
func checkpoint(s *store.MetadataStore, evm bool, height uint64) error {
	s.Lock()
	defer s.Unlock()
	meta, err := s.Get()
	if err != nil {
		return err
	}
	if evm {
		meta.LastEthereumBlockParsed = height
	} else {
		meta.LastKoinosBlockParsed = height
	}
	return s.Put(meta)
}

// Replaying an uncheckpointed batch must not duplicate our own approval.
func addLocalSignature(tx *bridge_pb.Transaction, address, signature string) {
	for i, v := range tx.Validators {
		if v == address {
			if i < len(tx.Signatures) {
				tx.Signatures[i] = signature
			}
			return
		}
	}
	tx.Validators = append(tx.Validators, address)
	tx.Signatures = append(tx.Signatures, signature)
}
func validateBlockBatch(batch *block_store.GetBlocksByHeightResponse, from, count uint64) error {
	if batch == nil || uint64(len(batch.BlockItems)) != count {
		return fmt.Errorf("incomplete irreversible block batch")
	}
	for i, b := range batch.BlockItems {
		if b == nil || b.Block == nil || b.Block.Header == nil || b.Receipt == nil || b.BlockHeight != from+uint64(i) || b.Block.Header.Height != b.BlockHeight {
			return fmt.Errorf("invalid or non-contiguous irreversible block batch")
		}
		for _, r := range b.Receipt.TransactionReceipts {
			if r == nil {
				return fmt.Errorf("missing transaction receipt")
			}
			for _, e := range r.Events {
				if e == nil {
					return fmt.Errorf("missing event")
				}
			}
		}
	}
	return nil
}

func validateEthereumLogs(logs []types.Log, from, to uint64, address common.Address) error {
	for i, l := range logs {
		if l.Removed || len(l.Topics) == 0 || l.Address != address || l.BlockNumber < from || l.BlockNumber > to {
			return fmt.Errorf("invalid or removed log in confirmed block range")
		}
		if i > 0 {
			prev := logs[i-1]
			if l.BlockNumber < prev.BlockNumber || (l.BlockNumber == prev.BlockNumber && l.Index <= prev.Index) {
				return fmt.Errorf("unordered or duplicate log in confirmed block range")
			}
		}
	}
	return nil
}

// mergePeerSignatures rechecks replies against the current stored transfer after
// the network round trip. A renewal may have changed its digest while unlocked.
// It also refuses corrupt retained evidence; failure leaves the record intact.
// Replies are keyed by the peer's Koinos identity in both directions.
func mergePeerSignatures(tx *bridge_pb.Transaction, replies map[string]string, validators map[string]util.ValidatorConfig) error {
	retained, err := util.VerifyTransferSignatures(tx, validators)
	if err != nil {
		return err
	}
	candidate := proto.Clone(tx).(*bridge_pb.Transaction)
	candidate.Validators, candidate.Signatures = nil, nil
	for peer, signature := range replies {
		address := ""
		for _, member := range validators {
			if member.KoinosAddress == peer {
				address = member.KoinosAddress
				if tx.Type == bridge_pb.TransactionType_koinos {
					address = member.EthereumAddress
				}
				break
			}
		}
		if address == "" {
			return fmt.Errorf("unconfigured signature peer")
		}
		candidate.Validators = append(candidate.Validators, address)
		candidate.Signatures = append(candidate.Signatures, signature)
	}
	incoming, err := util.VerifyTransferSignatures(candidate, validators)
	if err != nil {
		return err
	}
	for address, signature := range incoming {
		retained[address] = signature
	}
	tx.Validators, tx.Signatures = nil, nil
	for address, signature := range retained {
		tx.Validators = append(tx.Validators, address)
		tx.Signatures = append(tx.Signatures, signature)
	}
	return nil
}
