//go:build linux
// +build linux

package managed

import (
	"context"
	"os"
	"testing"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"golang.org/x/sys/unix"
)

func TestLinuxReviewedHostAppliesRealProcessProtection(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root Linux acceptance required")
	}
	v, p, r, key := reviewedHostFixture(t)
	// Host identity and human control reviews are synthetic. Process enforcement
	// below is real and must not be supplied by the evidence document.
	v.protect = keyvault.ProtectProcess
	writeHostReview(t, v, r, key)
	out, e := v.Inspect(context.Background(), p)
	if e != nil || !out.HostSecure {
		t.Fatal("live process enforcement failed", e)
	}
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_CORE, &limit) != nil || limit.Cur != 0 || limit.Max != 0 {
		t.Fatal("core limits not enforced")
	}
	dumpable, e := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if e != nil || dumpable != 0 {
		t.Fatal("process remained dumpable", e)
	}
}
