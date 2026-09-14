package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
)

func privateTestDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "vw-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestLongControlPathsUseDistinctPrivateSockets(t *testing.T) {
	base := privateTestDir(t)
	paths := []string{}
	for _, id := range []string{"first", "second"} {
		dir := filepath.Join(base, strings.Repeat("nested-", 18), id, "bridge", ".operator")
		if err := PrivateDir(dir); err != nil {
			t.Fatal(err)
		}
		lease, err := Acquire(dir, "process.lock")
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		control, err := StartControl(dir, NewMonitor(id, true, "", ""), func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		path, err := controlSocket(dir, false)
		if err != nil || len(path) >= 100 {
			t.Fatal("socket still exceeds limit", path, err)
		}
		paths = append(paths, path)
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("socket permissions")
		}
		var health Health
		if err := Call(context.Background(), dir, "GET", "/health", &health); err != nil || health.InstanceID != id {
			t.Fatal("wrong control scope", err, health)
		}
		if _, err := os.Lstat(filepath.Join(dir, "control.sock")); !os.IsNotExist(err) {
			t.Fatal("long-path socket still created")
		}
	}
	if paths[0] == paths[1] {
		t.Fatal("two data directories share a socket")
	}
}
func TestKeyFileBoundary(t *testing.T) {
	d := privateTestDir(t)
	p := filepath.Join(d, "key")
	if err := os.WriteFile(p, []byte(" synthetic-key \n"), 0600); err != nil {
		t.Fatal(err)
	}
	if key, err := LoadKey("", p, false); err != nil || key != "synthetic-key" {
		t.Fatalf("valid file: %q %v", key, err)
	}
	for _, v := range []struct{ inline, path string }{{"conflict", p}, {"", filepath.Join(d, "missing")}, {"", ""}} {
		if _, err := LoadKey(v.inline, v.path, false); err == nil {
			t.Fatal("accepted invalid signing configuration")
		}
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey("", p, false); err == nil {
		t.Fatal("read public key file")
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey("", link, false); err == nil {
		t.Fatal("followed symlink")
	}
	// Conflicting inline values, absent files and bad permissions are not touched.
	for _, path := range []string{p, link, filepath.Join(d, "missing")} {
		if key, err := LoadKey("invalid-secret", path, true); err != nil || key != "" {
			t.Fatal("observation mode loaded a key")
		}
	}
}
func TestLeaseAndMode(t *testing.T) {
	d := privateTestDir(t)
	a, err := Acquire(d, "process.lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(d, "process.lock"); err == nil {
		t.Fatal("duplicate process admitted")
	}
	if err := EnsureMode(d, true, false); err != nil {
		t.Fatal(err)
	}
	if err := EnsureMode(d, true, true); err != nil {
		t.Fatal(err)
	}
	if err := EnsureMode(d, false, true); err == nil {
		t.Fatal("silent transition into signing")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := Acquire(d, "process.lock")
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	if err := EnsureMode(privateTestDir(t), true, true); err == nil {
		t.Fatal("adopted old signing data for observation")
	}
	if _, err := Acquire(d, "../escape"); err == nil {
		t.Fatal("path escaped lease directory")
	}
}
func TestPrivateControl(t *testing.T) {
	d := privateTestDir(t)
	lease, err := Acquire(d, "process.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMonitor("synthetic-a", true, "", "")
	m.Progress("evm", 9)
	txStore := store.NewTransactionsStore(store.NewMapBackend())
	txStore.EnableActivity("")
	if err := txStore.Put("fixture", &bridge_pb.Transaction{Id: "fixture"}); err != nil {
		t.Fatal(err)
	}
	m.SetActivitySource(func() map[string]store.TransactionActivity {
		return map[string]store.TransactionActivity{"evm-to-koinos": txStore.Activity()}
	})
	c, err := StartControl(d, m, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var health Health
	if err := Call(ctx, d, "GET", "/health", &health); err != nil {
		t.Fatal(err)
	}
	if health.Mode != "observation-only" || health.EVMAddress != "" || health.Chains["evm"].Height != 9 {
		t.Fatalf("wrong health: %+v", health)
	}
	if health.Activity["evm-to-koinos"].NewRecords != 1 || !health.Activity["evm-to-koinos"].Complete {
		t.Fatal("private health omitted committed transaction activity")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(d, "control.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	token, err := Token(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ auth, origin, host string }{{"", "", "localhost"}, {"Bearer " + token, "https://untrusted.invalid", "localhost"}, {"Bearer " + token, "", "untrusted.invalid"}} {
		req, _ := http.NewRequest("POST", "http://localhost/stop", nil)
		req.Host = test.host
		req.Header.Set("Authorization", test.auth)
		req.Header.Set("Origin", test.origin)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatal("unauthorized request accepted")
		}
		select {
		case <-ctx.Done():
			t.Fatal("unauthorized stop executed")
		default:
		}
	}
	raw, _ := json.Marshal(health)
	if strings.Contains(string(raw), token) {
		t.Fatal("health leaked credential")
	}
	var result map[string]bool
	stale := health
	stale.StartedAt = stale.StartedAt.Add(-time.Second)
	if err := Call(context.Background(), d, "POST", "/stop", &result, stale); err == nil {
		t.Fatal("stale worker identity accepted")
	}
	select {
	case <-ctx.Done():
		t.Fatal("stale stop executed")
	default:
	}
	if err := Call(context.Background(), d, "POST", "/stop", &result, health); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("stop was not delivered")
	}
}
func TestStaleHealthIsNotHealthy(t *testing.T) {
	m := NewMonitor("a", false, "a", "b")
	m.health.Chains["evm"] = ChainHealth{1, time.Now().Add(-time.Minute), "observed"}
	if m.Snapshot().Chains["evm"].Status != "stale" {
		t.Fatal("stale chain reported observed")
	}
	m.Problem("evm")
	if m.Snapshot().Chains["evm"].Status != "unavailable" {
		t.Fatal("failure not visible")
	}
}

func TestPrivateSigningProofIsDomainBoundAndUnavailableInObservationMode(t *testing.T) {
	probeDigest := strings.Repeat("a", 64)
	signingDir := privateTestDir(t)
	signing := NewMonitor("signing-worker", false, "0x1111111111111111111111111111111111111111", "1aqHtNRDkiAZeFtuM8fRFuurcje6eHqF8")
	expected := signing.Snapshot()
	challenge := SigningProofChallenge{1, probeDigest, expected.InstanceID, expected.PID, expected.StartedAt, expected.EVMAddress, expected.KoinosAddress}
	expectedDigest, err := SigningProofDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	signing.SetSigningProofSource(func(digest []byte) (string, string, error) {
		received <- append([]byte(nil), digest...)
		return "synthetic-evm-proof", "synthetic-koinos-proof", nil
	})
	control, err := StartControl(signingDir, signing, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	proof, err := CallSigningProof(context.Background(), signingDir, probeDigest, expected)
	if err != nil || proof.Challenge != challenge || proof.EVMSignature != "synthetic-evm-proof" || proof.KoinosSignature != "synthetic-koinos-proof" {
		t.Fatal(proof, err)
	}
	if got := <-received; !bytes.Equal(got, expectedDigest) {
		t.Fatal("worker signer received a digest outside the fixed proof domain")
	}
	if _, err := CallSigningProof(context.Background(), signingDir, strings.Repeat("A", 64), expected); err == nil {
		t.Fatal("accepted noncanonical proof digest")
	}
	stale := expected
	stale.StartedAt = stale.StartedAt.Add(-time.Second)
	if _, err := CallSigningProof(context.Background(), signingDir, probeDigest, stale); err == nil {
		t.Fatal("changed worker identity received a signing proof")
	}

	observationDir := privateTestDir(t)
	observationMonitor := NewMonitor("observation-worker", true, "", "")
	observation, err := StartControl(observationDir, observationMonitor, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer observation.Close()
	if _, err := CallSigningProof(context.Background(), observationDir, probeDigest, observationMonitor.Snapshot()); err == nil {
		t.Fatal("observation-only worker created a signing proof")
	}
}
