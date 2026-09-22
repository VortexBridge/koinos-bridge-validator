package managed

import (
	"bytes"
	"context"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

func TestInstalledCandidateEvidenceMustBindExactBytesAndApproval(t *testing.T) {
	for _, kind := range []string{"missing", "readable-by-others", "wrong-validator", "wrong-checker", "wrong-platform", "wrong-release", "unsigned-release", "weak-report", "omitted-check", "future", "after-approval", "before-release", "wrong-isolation", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			v, p := installedFixture(t)
			raw, e := worker.ReadPrivateFile(v.candidate, 128<<10)
			if e != nil {
				t.Fatal(e)
			}
			var q CandidateQualification
			if host.JSON(raw, &q) != nil {
				t.Fatal("fixture decode")
			}
			switch kind {
			case "wrong-validator":
				q.Result.ArtifactSHA256 = strings.Repeat("f", 64)
			case "wrong-checker":
				q.Result.CheckerSHA256 = strings.Repeat("f", 64)
			case "wrong-platform":
				q.Result.Platform = "linux-other"
			case "wrong-release":
				q.Result.ReleaseDigest = strings.Repeat("f", 64)
			case "unsigned-release":
				q.ValidatorRelease.Signatures = nil
			case "weak-report":
				q.Result.Report.SchemaVersion = 1
			case "omitted-check":
				q.Result.Report.Checks = q.Result.Report.Checks[:7]
			case "future":
				q.Result.FinishedAt = time.Now().Add(time.Hour)
			case "after-approval":
				i, e := host.Read(v.root)
				if e != nil {
					t.Fatal(e)
				}
				i.Approval.ApprovedAt = q.Result.StartedAt
				if e = host.Atomic(v.root, "installation.json", i); e != nil {
					t.Fatal(e)
				}
			case "before-release":
				q.Result.StartedAt = time.Now().Add(-time.Hour)
			case "wrong-isolation":
				q.Result.Isolation = "network enabled"
			}
			if e = host.Atomic(v.root, "candidate.json", q); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "missing":
				if e = os.Remove(v.candidate); e != nil {
					t.Fatal(e)
				}
			case "readable-by-others":
				if e = os.Chmod(v.candidate, 0644); e != nil {
					t.Fatal(e)
				}
			case "unknown-field":
				if e = os.WriteFile(v.candidate, []byte(`{"schemaVersion":1,"override":true}`), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = v.Inspect(context.Background(), p); e == nil {
				t.Fatal("unqualified installation accepted")
			}
		})
	}
}

func TestCandidateImportIsIdempotentAndPreservesExistingEvidence(t *testing.T) {
	v, p := installedFixture(t)
	raw, e := worker.ReadPrivateFile(v.candidate, 128<<10)
	if e != nil {
		t.Fatal(e)
	}
	var q CandidateQualification
	if host.JSON(raw, &q) != nil {
		t.Fatal("fixture decode")
	}
	trustRaw, e := worker.ReadPrivateFile(v.trust, 65536)
	if e != nil {
		t.Fatal(e)
	}
	var trust operator.ReleaseTrust
	if host.JSON(trustRaw, &trust) != nil {
		t.Fatal("trust decode")
	}
	if e = os.Remove(v.candidate); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		path, e := ImportCandidate(v.root, p.Instance, trust, q.ValidatorRelease, q.Result, time.Now())
		if e != nil || path != v.candidate {
			t.Fatal("import failed", e)
		}
	}
	before, e := worker.ReadPrivateFile(v.candidate, 128<<10)
	if e != nil {
		t.Fatal(e)
	}
	invalid := q.Result
	invalid.CheckerSHA256 = strings.Repeat("f", 64)
	if _, e = ImportCandidate(v.root, p.Instance, trust, q.ValidatorRelease, invalid, time.Now()); e == nil {
		t.Fatal("bad qualification imported")
	}
	after, e := worker.ReadPrivateFile(v.candidate, 128<<10)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid import changed existing evidence")
	}
	lease, e := worker.Acquire(v.root, "host.lock")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ImportCandidate(v.root, p.Instance, trust, q.ValidatorRelease, q.Result, time.Now()); e == nil {
		t.Fatal("import raced active host service")
	}
	lease.Close()
	if _, e = v.Inspect(context.Background(), p); e != nil {
		t.Fatal("imported qualification unusable", e)
	}
}
