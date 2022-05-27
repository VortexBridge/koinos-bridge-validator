package store

import (
	"fmt"
	"sync"

	"github.com/roaminroe/koinos-bridge-validator/proto/build/github.com/roaminroe/koinos-bridge-validator/bridge_pb"
	"google.golang.org/protobuf/proto"
)

// KoinosTransactionsStore contains a backend object and handles requests
type KoinosTransactionsStore struct {
	backend Backend
	rwmutex sync.RWMutex
}

// NewKoinosTransactionsStore creates a new KoinosTransactionsStore wrapping the provided backend
func NewKoinosTransactionsStore(backend Backend) *KoinosTransactionsStore {
	return &KoinosTransactionsStore{backend: backend}
}

func (handler *KoinosTransactionsStore) Put(key string, transaction *bridge_pb.KoinosTransaction) error {
	handler.rwmutex.Lock()
	defer handler.rwmutex.Unlock()

	itemBytes, err := proto.Marshal(transaction)
	if err != nil {
		return fmt.Errorf("%w, %v", ErrSerialization, err)
	}

	err = handler.backend.Put([]byte(key), itemBytes)
	if err != nil {
		return fmt.Errorf("%w, %v", ErrBackend, err)
	}

	return nil
}

func (handler *KoinosTransactionsStore) Get(key string) (*bridge_pb.KoinosTransaction, error) {
	handler.rwmutex.RLock()
	defer handler.rwmutex.RUnlock()

	itemBytes, err := handler.backend.Get([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("%w, %v", ErrBackend, err)
	}

	if len(itemBytes) != 0 {
		item := &bridge_pb.KoinosTransaction{}
		if err := proto.Unmarshal(itemBytes, item); err != nil {
			return nil, fmt.Errorf("%w, %v", ErrDeserialization, err)
		}

		return item, nil
	}

	return nil, nil
}