package managed

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// CandidateQualification is local evidence, written only after the operator's
// isolated candidate runner succeeds. The validator release differs from the
// enclosing operator bundle release; their executable hashes must agree.
// Private-file ownership is the local trust boundary, not remote attestation.
type CandidateQualification struct {
	Schema           int                      `json:"schemaVersion"`
	ValidatorRelease operator.SignedRelease   `json:"validatorRelease"`
	Result           operator.CandidateResult `json:"result"`
}

func checkCandidate(path string, root string, i host.Installation, trust operator.ReleaseTrust, now time.Time) (time.Time, error) {
	raw, e := worker.ReadPrivateFile(path, 128<<10)
	if e != nil {
		return time.Time{}, errors.New("private local candidate evidence unavailable")
	}
	var q CandidateQualification
	if host.JSON(raw, &q) != nil || q.Schema != 1 {
		return time.Time{}, errors.New("invalid local candidate evidence")
	}
	release, e := operator.VerifyRelease(q.ValidatorRelease, trust, now)
	if e != nil || release.Manifest.Component != "validator" {
		return time.Time{}, errors.New("candidate validator release is not trusted")
	}
	r := q.Result
	if r.ReleaseDigest != release.Digest || r.Platform != i.Platform || r.ArtifactSHA256 != i.Files["koinos-bridge-validator"] || r.CheckerSHA256 != i.Files["vortex-candidate-check"] || r.Isolation != "local-docker-network-none-readonly-no-host-mounts-uid65532" {
		return time.Time{}, errors.New("candidate does not qualify the installed validator and checker")
	}
	if r.StartedAt.IsZero() || !r.FinishedAt.After(r.StartedAt) || r.FinishedAt.After(now) || r.FinishedAt.After(i.Approval.ApprovedAt) {
		return time.Time{}, errors.New("candidate tests must finish before local activation approval")
	}
	created, e := time.Parse(time.RFC3339, release.Manifest.CreatedAt)
	if e != nil || r.StartedAt.Before(created) {
		return time.Time{}, errors.New("candidate predates its signed release")
	}
	info, e := os.Stat(filepath.Join(root, "releases", i.Artifact, "koinos-bridge-validator"))
	if e != nil {
		return time.Time{}, errors.New("installed candidate executable unavailable")
	}
	bound := false
	for _, artifact := range release.Manifest.Artifacts {
		if artifact.Platform == i.Platform && artifact.SHA256 == r.ArtifactSHA256 && artifact.Size == uint64(info.Size()) {
			bound = true
		}
	}
	if !bound {
		return time.Time{}, errors.New("candidate release does not bind installed executable bytes")
	}
	if err := operator.ValidateCandidateObservation(r.Report, r.ArtifactSHA256); err != nil {
		return time.Time{}, err
	}
	expiry, _ := time.Parse(time.RFC3339, release.Manifest.ExpiresAt)
	return expiry, nil
}
