package managed

import (
	"context"
	"strings"
	"testing"
)

func TestRetiredJournalImportRechecksOperationsAndDoesNotReuseSignatures(t *testing.T) {
	for _, kind := range []string{"pending", "completed", "old-active", "only-evm-retired", "only-koinos-retired", "late-retirement-change", "wrong-source", "tamper", "changed-digest", "completion-regression", "checkpoint-failure"} {
		t.Run(kind, func(t *testing.T) {
			previous := policy()
			previous.KoinosAddress = "1CAtc7wPVn9JUAcbV8jo8UfyzMoAHRaTPC"
			p := policy()
			p.EVMAddress = "new-evm"
			p.KoinosAddress = "new-koinos"
			p.PreviousEVM = previous.EVMAddress
			p.PreviousKoinos = previous.KoinosAddress
			op := Operation{ID: "evm-to-koinos/a69784eddaa3aceb5afac7d93e9d01454dd73e7ade5b11d59e41a96241823486:0", Family: "koinos", Digest: "c88a0106baf4428f10c4816de12f70a92871999c84bc2c5186d995fada8fb167", State: "signed", Signature: "1fc777e0def2d6f7005c57e779d3e6825566629e7c2bf551d5603240cd6e4add465f37d3762ea78f5401ea17489dc27f1d0ad22358f5e0957dea06377c2c4cde5d"}
			source := Journal{Schema: 1, PolicySHA256: Digest(previous), State: "active", Operations: map[string]Operation{op.ID: op}}
			current := op
			current.Signature = ""
			current.State = "pending"
			v := &fixtureVerifier{operation: current}
			switch kind {
			case "completed":
				v.operation.State = "completed"
			case "old-active":
				v.edit = func(e *Evidence) { e.RotationFinal = false }
			case "only-evm-retired":
				v.edit = func(e *Evidence) { e.RemovedKoinos = "" }
			case "only-koinos-retired":
				v.edit = func(e *Evidence) { e.RemovedEVM = "" }
			case "late-retirement-change":
				checks := 0
				v.edit = func(e *Evidence) {
					checks++
					if checks > 1 {
						e.RotationFinal = false
					}
				}
			case "wrong-source":
				previous.KoinosAddress = "other"
			case "tamper":
				op.Signature = strings.Repeat("0", 130)
				source.Operations[op.ID] = op
			case "changed-digest":
				v.operation.Digest = strings.Repeat("f", 64)
			case "completion-regression":
				op.State = "completed"
				source.Operations[op.ID] = op
			case "checkpoint-failure":
				v.reconcileErr = true
			}
			root := dir(t)
			s, e := Open(root, p, v)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			e = s.ImportRetiredJournal(context.Background(), previous, source)
			if kind != "pending" && kind != "completed" {
				if e == nil || len(s.Status().Operations) != 0 {
					t.Fatal("unsafe import accepted or target changed")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			got := s.Status()
			if got.State != "locked" || got.Operations[op.ID].Signature != "" || got.Operations[op.ID].State != v.operation.State {
				t.Fatal("retired signature reused or lifecycle changed")
			}
			if source.Operations[op.ID].Signature == "" {
				t.Fatal("source mutated")
			}
			if e = s.ImportRetiredJournal(context.Background(), previous, source); e == nil {
				t.Fatal("nonempty target overwritten")
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(root, p, v)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if len(reopened.Status().Operations) != 1 {
				t.Fatal("import not persisted")
			}
		})
	}
}
