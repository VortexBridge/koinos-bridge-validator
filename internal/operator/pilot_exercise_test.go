package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func pilotExerciseFixture(t *testing.T) ([]*Store, []SignedPilotAcceptance, []SignedPilotExercise, time.Time) {
	t.Helper()
	acceptedAt := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	stores, acceptances := pilotStores(t, acceptedAt)
	observedAt := acceptedAt.Add(time.Minute)
	receipts := make([]SignedPilotExercise, 0, len(stores)*len(pilotExercisePhases))
	for operatorIndex, store := range stores {
		for phaseIndex, phase := range pilotExercisePhases {
			evidence := sha256.Sum256([]byte(fmt.Sprintf("operator-%d-phase-%s", operatorIndex, phase)))
			request := PilotExerciseRequest{
				SchemaVersion:    1,
				ID:               fmt.Sprintf("receipt-%d-%d", operatorIndex, phaseIndex),
				SessionID:        "synthetic-pilot-session",
				AcceptanceDigest: PilotAcceptanceDigest(acceptances[operatorIndex]),
				Phase:            phase,
				Result:           "passed",
				ObservedAt:       observedAt,
				DurationMillis:   uint64(1000 + phaseIndex),
				EvidenceDigests:  []string{hex.EncodeToString(evidence[:])},
			}
			receipt, err := store.RecordPilotExercise(request, observedAt)
			if err != nil {
				t.Fatal(err)
			}
			repeated, err := store.RecordPilotExercise(request, observedAt)
			if err != nil || maintenanceDigest(repeated) != maintenanceDigest(receipt) {
				t.Fatal("pilot receipt retry was not idempotent", err)
			}
			receipts = append(receipts, receipt)
		}
	}
	return stores, acceptances, receipts, observedAt
}

func TestPilotExerciseRequiresEveryOperatorAndPhase(t *testing.T) {
	stores, acceptances, receipts, observedAt := pilotExerciseFixture(t)
	report, err := VerifyPilotExercise(acceptances, receipts, strings.Repeat("f", 64), observedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "exercise-evidence-complete" || report.ActivationReady || report.ReceiptCount != len(pilotExercisePhases)*3 || len(report.PhaseReceipts) != len(pilotExercisePhases) {
		t.Fatal("complete exercise evidence was not reported safely", report)
	}
	state := stores[0].PilotState(observedAt.Add(time.Minute))
	local, ok := state["exerciseReceipts"].([]SignedPilotExercise)
	if !ok || len(local) != len(pilotExercisePhases) || state["exerciseProblem"] != "" {
		t.Fatal("local pilot receipt inventory is incomplete", state)
	}
}

func TestPilotExerciseFailsClosed(t *testing.T) {
	_, acceptances, receipts, observedAt := pilotExerciseFixture(t)
	copyReceipts := func() []SignedPilotExercise {
		var copied []SignedPilotExercise
		raw, _ := json.Marshal(receipts)
		json.Unmarshal(raw, &copied)
		return copied
	}
	for _, test := range []struct {
		name   string
		change func([]SignedPilotExercise) []SignedPilotExercise
	}{
		{"missing-phase", func(values []SignedPilotExercise) []SignedPilotExercise { return values[:len(values)-1] }},
		{"duplicate-receipt", func(values []SignedPilotExercise) []SignedPilotExercise { values[1] = values[0]; return values }},
		{"tampered-result", func(values []SignedPilotExercise) []SignedPilotExercise {
			values[0].Claim.Result = "failed"
			values[0].Claim.ProblemCode = "test-failure"
			return values
		}},
		{"wrong-session", func(values []SignedPilotExercise) []SignedPilotExercise {
			values[0].Claim.SessionID = "other-session"
			return values
		}},
		{"wrong-acceptance", func(values []SignedPilotExercise) []SignedPilotExercise {
			values[0].Claim.AcceptanceDigest = strings.Repeat("e", 64)
			return values
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyPilotExercise(acceptances, test.change(copyReceipts()), strings.Repeat("f", 64), observedAt.Add(time.Minute)); err == nil {
				t.Fatal("unsafe or incomplete pilot exercise verified")
			}
		})
	}
}

func TestPilotExerciseIDCannotBeRebound(t *testing.T) {
	stores, acceptances, _, observedAt := pilotExerciseFixture(t)
	evidence := sha256.Sum256([]byte("changed-evidence"))
	request := PilotExerciseRequest{
		SchemaVersion:    1,
		ID:               "receipt-0-0",
		SessionID:        "synthetic-pilot-session",
		AcceptanceDigest: PilotAcceptanceDigest(acceptances[0]),
		Phase:            pilotExercisePhases[0],
		Result:           "passed",
		ObservedAt:       observedAt,
		DurationMillis:   9999,
		EvidenceDigests:  []string{hex.EncodeToString(evidence[:])},
	}
	if _, err := stores[0].RecordPilotExercise(request, observedAt); err == nil {
		t.Fatal("existing pilot receipt ID was rebound to changed evidence")
	}
}

func TestPilotExerciseSurvivesReopen(t *testing.T) {
	stores, _, _, observedAt := pilotExerciseFixture(t)
	path := stores[0].dir
	if err := stores[0].Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	state := reopened.PilotState(observedAt.Add(time.Minute))
	receipts, ok := state["exerciseReceipts"].([]SignedPilotExercise)
	if state["state"] != "locally-accepted" || !ok || len(receipts) != len(pilotExercisePhases) || state["exerciseProblem"] != "" {
		t.Fatal("pilot acceptance or receipts did not survive reopen", state)
	}
}
