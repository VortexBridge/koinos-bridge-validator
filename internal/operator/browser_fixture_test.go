package operator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestOperatorBrowserFixture serves the real operator HTTP handler with a
// synthetic managed installation for manual browser and accessibility checks.
// It is skipped in ordinary test runs and never accepts real keys or RPCs.
func TestOperatorBrowserFixture(t *testing.T) {
	if os.Getenv("VORTEX_OPERATOR_BROWSER_FIXTURE") != "1" {
		t.Skip("set VORTEX_OPERATOR_BROWSER_FIXTURE=1 for a bounded local browser fixture")
	}
	addr := os.Getenv("VORTEX_OPERATOR_FIXTURE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:3031"
	}
	tokenFile := os.Getenv("VORTEX_OPERATOR_FIXTURE_TOKEN_FILE")
	if tokenFile == "" {
		t.Fatal("VORTEX_OPERATOR_FIXTURE_TOKEN_FILE is required")
	}
	store, _ := managedViewFixture(t, "active")
	defer store.Close()
	now := time.Now().UTC()
	governanceFixture := newGovernanceFixture(t, store)
	governanceFixture.now = now
	for id, observation := range governanceFixture.observations {
		observation.ObservedAt = now
		governanceFixture.observations[id] = observation
	}
	proposal, err := store.CreateGovernance(t.Context(), CreateGovernanceProposal{ID: "partial-pause-fixture", ProfileIDs: []string{"fixture-evm", "fixture-koinos"}, Pause: true, Expiration: fmt.Sprint(now.Add(time.Hour).UnixMilli())}, governanceFixture.observe, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range proposal.Routes {
		for index := 0; index < 2; index++ {
			proposal, err = store.AddGovernanceSignature(t.Context(), GovernanceSignatureEnvelope{SchemaVersion: 1, ProposalID: proposal.ID, ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Signature: governanceSignature(t, route, governanceFixture.keys[route.Profile.ID][index])}, governanceFixture.observe, now.Add(time.Duration(index+1)*time.Second))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	governanceExecutor := &syntheticGovernanceExecutor{}
	proposal, err = store.SubmitGovernance(t.Context(), proposal.ID, "fixture-evm", governanceFixture.observe, governanceExecutor, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if proposal, err = store.ReconcileGovernance(t.Context(), proposal.ID, governanceExecutor, now.Add(4*time.Second)); err != nil || proposal.State != "partially-finalized" {
		t.Fatal("synthetic partial governance fixture failed", err)
	}
	categories := []string{"rpc-disagreement", "wrong-network", "stalled-chain", "disk-pressure", "invalid-peer-data", "failed-persistence", "duplicate-signer-risk"}
	history := make([]Incident, 0, len(categories))
	for index, category := range categories {
		history = append(history, incidentFor(category, "critical", "Synthetic "+category+" evidence for narrow-screen review.", "Keep authority-changing actions disabled and resolve the reviewed evidence.", now, index))
	}
	if err := atomicFile(store.dir, "incident-history.json", mustJSON(t, incidentDisk{SchemaVersion: 1, CheckedAt: now, History: history})); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	tokenHandle, err := os.OpenFile(tokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokenHandle.WriteString(token); err != nil {
		tokenHandle.Close()
		t.Fatal(err)
	}
	if err := tokenHandle.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tokenFile)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	api := NewServer(store, token, listener.Addr().String(), []string{"http://127.0.0.1:5174"})
	api.observe = func(ctx context.Context, binding Binding) Observation {
		observation := governanceFixture.observe(ctx, binding)
		observation.ObservedAt = time.Now().UTC()
		return observation
	}
	api.governance = governanceExecutor
	server := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Logf("synthetic operator browser fixture listening on http://%s", listener.Addr())
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Minute):
		_ = server.Close()
	}
}
