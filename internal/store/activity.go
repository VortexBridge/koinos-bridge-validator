package store

import (
	"math"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"google.golang.org/protobuf/proto"
)

// TransactionActivity describes successful writes since tracking was enabled in
// this process. It is not a database census, signature verification or finality
// proof. Counters are decimal JSON strings to avoid browser integer rounding.
type TransactionActivity struct {
	Enabled               bool      `json:"enabled"`
	Complete              bool      `json:"complete"`
	StartedAt             time.Time `json:"startedAt"`
	LastWriteAt           time.Time `json:"lastWriteAt"`
	Writes                uint64    `json:"writes,string"`
	NewRecords            uint64    `json:"newRecords,string"`
	LocalSignatureChanges uint64    `json:"localSignatureChanges,string"`
	OtherSignatureChanges uint64    `json:"otherSignatureChanges,string"`
	CompletionTransitions uint64    `json:"completionTransitions,string"`
	Problem               string    `json:"problem,omitempty"`
}
type activityTracker struct {
	summary      TransactionActivity
	localAddress string
}

// EnableActivity is idempotent and cannot reset a running process's counters or
// change the identity attributed as local. Call before starting writers.
func (s *TransactionsStore) EnableActivity(localAddress string) {
	s.rwmutex.Lock()
	defer s.rwmutex.Unlock()
	if s.activity != nil {
		return
	}
	s.activity = &activityTracker{summary: TransactionActivity{Enabled: true, Complete: true, StartedAt: time.Now().UTC()}, localAddress: localAddress}
}
func (s *TransactionsStore) Activity() TransactionActivity {
	s.rwmutex.RLock()
	defer s.rwmutex.RUnlock()
	if s.activity == nil {
		return TransactionActivity{}
	}
	return s.activity.summary
}
func (a *activityTracker) incomplete(problem string) {
	a.summary.Complete = false
	if a.summary.Problem == "" {
		a.summary.Problem = problem
	}
}
func (a *activityTracker) increment(counter *uint64) {
	if *counter == math.MaxUint64 {
		a.incomplete("counter-overflow")
		return
	}
	(*counter)++
}
func activityAddress(value string) string {
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return strings.ToLower(value)
	}
	return value
}
func activitySignatures(tx *bridge_pb.Transaction) (map[string]string, bool) {
	result := map[string]string{}
	if tx == nil {
		return result, true
	}
	if len(tx.Validators) != len(tx.Signatures) {
		return result, false
	}
	for i, address := range tx.Validators {
		address = activityAddress(address)
		if address == "" || tx.Signatures[i] == "" {
			return result, false
		}
		if _, exists := result[address]; exists {
			return result, false
		}
		result[address] = tx.Signatures[i]
	}
	return result, true
}

// Called only after backend.Put succeeds, while the transaction-store mutex is
// held. A failed prior read makes derived counters incomplete, not a write veto.
func (a *activityTracker) committed(previous []byte, readErr error, current []byte) {
	a.increment(&a.summary.Writes)
	a.summary.LastWriteAt = time.Now().UTC()
	if readErr != nil {
		a.incomplete("prior-record-unreadable")
		return
	}
	var old *bridge_pb.Transaction
	if len(previous) > 0 {
		old = &bridge_pb.Transaction{}
		if proto.Unmarshal(previous, old) != nil {
			a.incomplete("prior-record-unreadable")
			return
		}
	}
	tx := &bridge_pb.Transaction{}
	if proto.Unmarshal(current, tx) != nil || tx.Id == "" {
		a.incomplete("record-shape-unknown")
		return
	}
	before, oldOK := activitySignatures(old)
	after, newOK := activitySignatures(tx)
	if !oldOK || !newOK {
		a.incomplete("signature-shape-unknown")
		return
	}
	if old == nil {
		a.increment(&a.summary.NewRecords)
	}
	for address, signature := range after {
		if before[address] == signature {
			continue
		}
		if a.localAddress != "" && address == activityAddress(a.localAddress) {
			a.increment(&a.summary.LocalSignatureChanges)
		} else {
			a.increment(&a.summary.OtherSignatureChanges)
		}
	}
	if tx.Status == bridge_pb.TransactionStatus_completed && (old == nil || old.Status != bridge_pb.TransactionStatus_completed) {
		a.increment(&a.summary.CompletionTransitions)
	}
}
