package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
)

func TestActivityTracksCommittedTransitionsWithoutReplayInflation(t *testing.T) {
	backend := NewMapBackend()
	s := NewTransactionsStore(backend)
	old := &bridge_pb.Transaction{Id: "old", Validators: []string{"local"}, Signatures: []string{"prior"}}
	if err := s.Put("old", old); err != nil {
		t.Fatal(err)
	}
	s.EnableActivity("local")
	started := s.Activity().StartedAt
	if err := s.Put("old", old); err != nil {
		t.Fatal(err)
	}
	tx := &bridge_pb.Transaction{Id: "new", Validators: []string{"local", "peer"}, Signatures: []string{"local-sig", "peer-sig"}}
	if err := s.Put("new", tx); err != nil {
		t.Fatal(err)
	}
	// Reordering signatures or writing identical content is not new activity.
	tx.Validators = []string{"peer", "local"}
	tx.Signatures = []string{"peer-sig", "local-sig"}
	s.Put("new", tx)
	tx.Signatures[1] = "renewed-local"
	s.Put("new", tx)
	tx.Status = bridge_pb.TransactionStatus_completed
	s.Put("new", tx)
	s.Put("new", tx)
	a := s.Activity()
	if !a.Enabled || !a.Complete || a.Writes != 6 || a.NewRecords != 1 || a.LocalSignatureChanges != 2 || a.OtherSignatureChanges != 1 || a.CompletionTransitions != 1 || a.LastWriteAt.Before(a.StartedAt) {
		t.Fatalf("bad activity: %+v", a)
	}
	s.EnableActivity("someone-else")
	if s.Activity() != a || s.Activity().StartedAt != started {
		t.Fatal("running counters reset")
	}
	// A new process starts new counters but recognizes existing durable records.
	reopened := NewTransactionsStore(backend)
	reopened.EnableActivity("local")
	reopened.Put("new", tx)
	after := reopened.Activity()
	if after.NewRecords != 0 || after.LocalSignatureChanges != 0 || after.CompletionTransitions != 0 || after.Writes != 1 {
		t.Fatal("restart mislabeled existing records as new")
	}
	raw, _ := json.Marshal(a)
	if !strings.Contains(string(raw), `"writes":"6"`) || strings.Contains(string(raw), "local-sig") {
		t.Fatal("counter encoding lost precision or leaked payload")
	}
}

type activityFailBackend struct {
	*MapBackend
	failGet, failPut bool
}

func (b *activityFailBackend) Get(key []byte) ([]byte, error) {
	if b.failGet {
		return nil, errors.New("SYNTHETIC-PRIVATE-DIAGNOSTIC")
	}
	return b.MapBackend.Get(key)
}
func (b *activityFailBackend) Put(key, value []byte) error {
	if b.failPut {
		return errors.New("write failed")
	}
	return b.MapBackend.Put(key, value)
}
func TestActivityDoesNotClaimFailedWritesOrVetoCommittedWrites(t *testing.T) {
	b := &activityFailBackend{MapBackend: NewMapBackend()}
	s := NewTransactionsStore(b)
	s.EnableActivity("")
	tx := &bridge_pb.Transaction{Id: "test"}
	b.failPut = true
	if s.Put("test", tx) == nil || s.Activity().Writes != 0 || !s.Activity().LastWriteAt.IsZero() {
		t.Fatal("failed write counted")
	}
	b.failPut = false
	b.failGet = true
	if err := s.Put("test", tx); err != nil {
		t.Fatal("telemetry read vetoed legacy write", err)
	}
	a := s.Activity()
	if a.Complete || a.Writes != 1 || a.NewRecords != 0 || a.Problem != "prior-record-unreadable" {
		t.Fatal(a)
	}
	b.failGet = false
	tx.Id = "next"
	s.Put("next", tx)
	if s.Activity().Complete {
		t.Fatal("incomplete evidence silently became complete")
	}
}
func TestActivityRejectsAmbiguousSignatureShapeAndSaturates(t *testing.T) {
	s := NewTransactionsStore(NewMapBackend())
	s.EnableActivity("local")
	tx := &bridge_pb.Transaction{Id: "test", Validators: []string{"local", "local"}, Signatures: []string{"one", "two"}}
	if err := s.Put("test", tx); err != nil {
		t.Fatal(err)
	}
	if s.Activity().Complete || s.Activity().LocalSignatureChanges != 0 {
		t.Fatal("duplicate signer inflated activity")
	}
	s.activity.summary.Writes = math.MaxUint64
	s.Put("other", &bridge_pb.Transaction{Id: "other"})
	if s.Activity().Writes != math.MaxUint64 {
		t.Fatal("counter wrapped")
	}
}
func TestActivityConcurrentWritersAndSnapshots(t *testing.T) {
	s := NewTransactionsStore(NewMapBackend())
	s.EnableActivity("0xABC")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx := &bridge_pb.Transaction{Id: fmt.Sprint(i), Validators: []string{"0xabc"}, Signatures: []string{"persisted-test-bytes"}}
			if err := s.Put(tx.Id, tx); err != nil {
				t.Error(err)
			}
			s.Activity()
		}(i)
	}
	wg.Wait()
	a := s.Activity()
	if a.Writes != 20 || a.NewRecords != 20 || a.LocalSignatureChanges != 20 || !a.Complete {
		t.Fatal(a)
	}
}

type activityMutationBackend struct {
	*MapBackend
	mutate func()
}

func (b *activityMutationBackend) Put(key, value []byte) error {
	if err := b.MapBackend.Put(key, value); err != nil {
		return err
	}
	b.mutate()
	return nil
}
func TestActivityUsesSerializedCommittedBytes(t *testing.T) {
	tx := &bridge_pb.Transaction{Id: "serialized", Validators: []string{"local"}, Signatures: []string{"persisted-value"}}
	b := &activityMutationBackend{MapBackend: NewMapBackend(), mutate: func() { tx.Id = ""; tx.Validators = nil; tx.Signatures = nil }}
	s := NewTransactionsStore(b)
	s.EnableActivity("local")
	if err := s.Put("serialized", tx); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Get("serialized")
	if err != nil || stored.Id != "serialized" {
		t.Fatal("bad fixture persistence")
	}
	a := s.Activity()
	if !a.Complete || a.NewRecords != 1 || a.LocalSignatureChanges != 1 {
		t.Fatal("activity read caller object instead of committed bytes", a)
	}
}
