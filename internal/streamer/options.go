package streamer

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"github.com/koinos/koinos-proto-golang/koinos/rpc/block_store"
)

type Options struct {
	ObserveOnly bool
	OnProgress  func(uint64)
	OnProblem   func()
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
