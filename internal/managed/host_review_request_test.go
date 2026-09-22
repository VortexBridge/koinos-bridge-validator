package managed

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/host"
)

func TestHostReviewDraftBindsExistingRecordsButCannotAuthorize(t *testing.T) {
	v, p, r, _ := reviewedHostFixture(t)
	draft, e := draftHostReview(p, v.evidence, "standard", r.HostBinding, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	canonical, _ := CanonicalHostReview(draft.Review)
	decoded, e := hex.DecodeString(draft.CanonicalHex)
	if e != nil || !bytes.Equal(canonical, decoded) {
		t.Fatal("signing bytes differ from displayed review")
	}
	for control, digest := range r.Evidence {
		if draft.Review.Evidence[control] != digest {
			t.Fatal("control record not bound")
		}
	}
	raw, _ := jsonBytes(draft)
	var approval SignedHostReview
	if host.JSON(raw, &approval) == nil {
		t.Fatal("unsigned request accepted as signed approval")
	}
	if _, e = draftHostReview(p, v.evidence, "restricted", r.HostBinding, time.Now()); e == nil {
		t.Fatal("missing restricted evidence accepted")
	}
	if e = os.Remove(filepath.Join(v.evidence, hostControls[0]+".txt")); e != nil {
		t.Fatal(e)
	}
	if _, e = draftHostReview(p, v.evidence, "standard", r.HostBinding, time.Now()); e == nil {
		t.Fatal("missing control record filled automatically")
	}
}
