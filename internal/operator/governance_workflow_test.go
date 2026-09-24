package operator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/mr-tron/base58"
)

type governanceFixture struct {
	now          time.Time
	observations map[string]Observation
	keys         map[string][][]byte
}

func newGovernanceFixture(t *testing.T, store *Store) governanceFixture {
	t.Helper()
	now := time.UnixMilli(1900000000000).UTC()
	profiles := []Profile{vectors(t)[0].Profile, vectors(t)[12].Profile}
	fixture := governanceFixture{now: now, observations: map[string]Observation{}, keys: map[string][][]byte{}}
	for index, profile := range profiles {
		profile.CodeHash = strings.Repeat(fmt.Sprint(index+1), 64)
		profile.Reviewed = true
		profile.ReviewEvidence = "synthetic local governance fixture"
		if _, err := store.Apply(ApplyConfig{ExpectedRevision: uint64(index), IdempotencyKey: "governance-profile-" + profile.Family, Binding: Binding{Profile: profile, RPC: "http://127.0.0.1:1"}}); err != nil {
			t.Fatal(err)
		}
		members := []string{}
		for keyIndex := byte(1); keyIndex <= 3; keyIndex++ {
			seed := make([]byte, 32)
			seed[30] = byte(index + 1)
			seed[31] = keyIndex
			fixture.keys[profile.ID] = append(fixture.keys[profile.ID], seed)
			if profile.Family == "evm" {
				key, _ := crypto.ToECDSA(seed)
				members = append(members, crypto.PubkeyToAddress(key.PublicKey).Hex())
			} else {
				_, public := btcec.PrivKeyFromBytes(btcec.S256(), seed)
				address, _ := util.KoinosPublicKeyToAddress(public)
				members = append(members, base58.Encode(address))
			}
		}
		paused := false
		fixture.observations[profile.ID] = Observation{Complete: true, ProfileID: profile.ID, ObservedAt: now, Status: "observed", NetworkID: profile.NetworkID, Block: "16", BlockHash: "0x" + strings.Repeat(fmt.Sprint(index+3), 64), Finality: "finalized", CodeHash: profile.CodeHash, Nonce: "4", BridgeChainID: profile.BridgeChainID, Paused: &paused, Validators: members, Quorum: 2, GovernanceReady: true}
	}
	return fixture
}

func (f governanceFixture) observe(_ context.Context, binding Binding) Observation {
	return f.observations[binding.Profile.ID]
}

func governanceSignature(t *testing.T, route GovernanceRoute, seed []byte) string {
	t.Helper()
	digest, _ := hex.DecodeString(route.Payload.Digest)
	if route.Profile.Family == "evm" {
		key, _ := crypto.ToECDSA(seed)
		signature, err := crypto.Sign(digest, key)
		if err != nil {
			t.Fatal(err)
		}
		signature[64] += 27
		return "0x" + hex.EncodeToString(signature)
	}
	key, _ := btcec.PrivKeyFromBytes(btcec.S256(), seed)
	signature, err := btcec.SignCompact(btcec.S256(), key, digest, true)
	if err != nil {
		t.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(signature)
}

type syntheticGovernanceExecutor struct{ sequence int }

func (s *syntheticGovernanceExecutor) Submit(_ context.Context, _ Binding, proposal GovernanceProposal, route GovernanceRoute) (GovernanceReceipt, error) {
	s.sequence++
	return GovernanceReceipt{TransactionID: fmt.Sprintf("synthetic-%s-%d", route.Profile.Family, s.sequence), State: "submitted", SubmittedAt: proposal.CreatedAt.Add(time.Duration(s.sequence) * time.Second), Message: "Synthetic isolated-chain submission accepted."}, nil
}

func (s *syntheticGovernanceExecutor) Reconcile(_ context.Context, _ Binding, _ GovernanceProposal, _ GovernanceRoute, receipt GovernanceReceipt) (GovernanceReceipt, error) {
	receipt.State = "finalized"
	receipt.FinalizedAt = receipt.SubmittedAt.Add(time.Second)
	receipt.Block = "17"
	receipt.BlockHash = "0x" + strings.Repeat("f", 64)
	receipt.Message = "Synthetic isolated-chain receipt finalized."
	return receipt, nil
}

func TestGovernancePortableQuorumPartialCompletionAndRestart(t *testing.T) {
	dir := privateDir(t)
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newGovernanceFixture(t, store)
	expires := fmt.Sprint(fixture.now.Add(time.Hour).UnixMilli())
	proposal, err := store.CreateGovernance(context.Background(), CreateGovernanceProposal{ID: "pause-both", ProfileIDs: []string{"fixture-evm", "fixture-koinos"}, Pause: true, Expiration: expires}, fixture.observe, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.State != "collecting" || len(proposal.Routes) != 2 || proposalDigest(proposal) == "" {
		t.Fatalf("unexpected proposal %+v", proposal)
	}
	for _, route := range proposal.Routes {
		for i := 0; i < 2; i++ {
			envelope := GovernanceSignatureEnvelope{SchemaVersion: 1, ProposalID: proposal.ID, ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Signature: governanceSignature(t, route, fixture.keys[route.Profile.ID][i])}
			proposal, err = store.AddGovernanceSignature(context.Background(), envelope, fixture.observe, fixture.now.Add(time.Duration(i+1)*time.Second))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if proposal.State != "ready" {
		t.Fatalf("proposal did not reach independent route quorum: %+v", proposal)
	}
	for _, route := range proposal.Routes {
		reviewed, err := store.reviewGovernanceSigning(context.Background(), proposal, route.Profile.ID, route.Anchor.Validators[0], fixture.observe, fixture.now.Add(3*time.Second))
		if err != nil || reviewed.Payload.Digest != route.Payload.Digest {
			t.Fatalf("protected signing preflight did not reconstruct the exact route: %+v %v", reviewed, err)
		}
	}
	journalPath := filepath.Join(dir, governanceJournalFile)
	info, err := os.Stat(journalPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("portable journal is not private mode 0600")
	}
	executor := &syntheticGovernanceExecutor{}
	proposal, err = store.SubmitGovernance(context.Background(), proposal.ID, "fixture-evm", fixture.observe, executor, fixture.now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	proposal, err = store.ReconcileGovernance(context.Background(), proposal.ID, executor, fixture.now.Add(5*time.Second))
	if err != nil || proposal.State != "partially-finalized" {
		t.Fatalf("partial completion was hidden: state=%s err=%v", proposal.State, err)
	}
	store.Close()
	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	proposal, err = store.SubmitGovernance(context.Background(), proposal.ID, "fixture-koinos", fixture.observe, executor, fixture.now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	proposal, err = store.ReconcileGovernance(context.Background(), proposal.ID, executor, fixture.now.Add(7*time.Second))
	if err != nil || proposal.State != "finalized" {
		t.Fatalf("restart recovery did not finalize both chains: state=%s err=%v", proposal.State, err)
	}
	if len(proposal.History) < 7 {
		t.Fatal("public audit history is incomplete")
	}
}

func TestGovernanceRejectsChangedWrongDuplicateRemovedStaleAndExpired(t *testing.T) {
	store, err := OpenStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fixture := newGovernanceFixture(t, store)
	proposal, err := store.CreateGovernance(context.Background(), CreateGovernanceProposal{ID: "review-failures", ProfileIDs: []string{"fixture-koinos", "fixture-evm"}, Pause: true, Expiration: fmt.Sprint(fixture.now.Add(time.Hour).UnixMilli())}, fixture.observe, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	route := proposal.Routes[0]
	valid := GovernanceSignatureEnvelope{SchemaVersion: 1, ProposalID: proposal.ID, ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Signature: governanceSignature(t, route, fixture.keys[route.Profile.ID][0])}
	changed := valid
	changed.PayloadDigest = strings.Repeat("0", 64)
	if _, err := store.AddGovernanceSignature(context.Background(), changed, fixture.observe, fixture.now); err == nil {
		t.Fatal("accepted changed payload")
	}
	wrong := valid
	wrong.ProfileDigest = proposal.Routes[1].Profile.Digest()
	if _, err := store.AddGovernanceSignature(context.Background(), wrong, fixture.observe, fixture.now); err == nil {
		t.Fatal("accepted wrong route")
	}
	if _, err := store.AddGovernanceSignature(context.Background(), valid, fixture.observe, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddGovernanceSignature(context.Background(), valid, fixture.observe, fixture.now); err == nil {
		t.Fatal("accepted duplicate signer")
	}
	removed := fixture
	o := removed.observations[route.Profile.ID]
	o.Validators = o.Validators[1:]
	o.Quorum = Quorum(len(o.Validators))
	removed.observations[route.Profile.ID] = o
	second := valid
	second.Signature = governanceSignature(t, route, fixture.keys[route.Profile.ID][1])
	if _, err := store.AddGovernanceSignature(context.Background(), second, removed.observe, fixture.now); err == nil {
		t.Fatal("accepted approvals after signer removal")
	}
	stale := fixture
	o = stale.observations[route.Profile.ID]
	o.Nonce = "5"
	stale.observations[route.Profile.ID] = o
	if _, err := store.AddGovernanceSignature(context.Background(), second, stale.observe, fixture.now); err == nil {
		t.Fatal("accepted stale nonce")
	}
	if _, err := store.AddGovernanceSignature(context.Background(), second, fixture.observe, fixture.now.Add(2*time.Hour)); err == nil {
		t.Fatal("accepted expired proposal")
	}
}

func TestGovernancePortableImportRevalidatesLocalAuthority(t *testing.T) {
	first, _ := OpenStore(privateDir(t))
	defer first.Close()
	fixture := newGovernanceFixture(t, first)
	proposal, err := first.CreateGovernance(context.Background(), CreateGovernanceProposal{ID: "portable-pause", ProfileIDs: []string{"fixture-evm", "fixture-koinos"}, Pause: true, Expiration: fmt.Sprint(fixture.now.Add(time.Hour).UnixMilli())}, fixture.observe, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	route := proposal.Routes[0]
	proposal, err = first.AddGovernanceSignature(context.Background(), GovernanceSignatureEnvelope{SchemaVersion: 1, ProposalID: proposal.ID, ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Signature: governanceSignature(t, route, fixture.keys[route.Profile.ID][0])}, fixture.observe, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if len(proposal.Routes[0].Approvals) != 1 {
		t.Fatalf("signature was not retained before export: %+v", proposal)
	}
	second, _ := OpenStore(privateDir(t))
	defer second.Close()
	secondFixture := newGovernanceFixture(t, second)
	imported, err := second.ImportGovernance(context.Background(), proposal, secondFixture.observe, fixture.now.Add(time.Second))
	if err != nil || len(imported.Routes[0].Approvals) != 1 {
		t.Fatalf("portable import failed: %+v %v", imported, err)
	}
	secondRoute := imported.Routes[0]
	imported, err = second.AddGovernanceSignature(context.Background(), GovernanceSignatureEnvelope{SchemaVersion: 1, ProposalID: imported.ID, ProfileDigest: secondRoute.Profile.Digest(), PayloadDigest: secondRoute.Payload.Digest, Signature: governanceSignature(t, secondRoute, secondFixture.keys[secondRoute.Profile.ID][1])}, secondFixture.observe, fixture.now.Add(time.Second))
	if err != nil || len(imported.Routes[0].Approvals) != 2 {
		t.Fatalf("second operator signature failed: %+v %v", imported, err)
	}
	merged, err := first.ImportGovernance(context.Background(), imported, fixture.observe, fixture.now.Add(2*time.Second))
	if err != nil || len(merged.Routes[0].Approvals) != 2 {
		t.Fatalf("portable quorum merge failed: %+v %v", merged, err)
	}
	tampered := proposal
	tampered.ID = "tampered-pause"
	tampered.Pause = false
	if _, err := second.ImportGovernance(context.Background(), tampered, secondFixture.observe, fixture.now.Add(time.Second)); err == nil {
		t.Fatal("accepted portable envelope with changed parameter")
	}
}

func TestGovernanceTypedHTTPWorkflowKeepsSigningOutOfBrowser(t *testing.T) {
	store, err := OpenStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fixture := newGovernanceFixture(t, store)
	fixture.now = time.Now().UTC()
	for id, observation := range fixture.observations {
		observation.ObservedAt = fixture.now
		fixture.observations[id] = observation
	}
	token := strings.Repeat("a", 64)
	api := NewServer(store, token, "127.0.0.1:3021", []string{"http://127.0.0.1:5173"})
	api.observe = fixture.observe
	api.governance = &syntheticGovernanceExecutor{}
	request := func(method, path string, body interface{}) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, "http://127.0.0.1:3021"+path, bytes.NewReader(raw))
		req.Host = "127.0.0.1:3021"
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res := httptest.NewRecorder()
		api.ServeHTTP(res, req)
		return res
	}
	create := CreateGovernanceProposal{ID: "api-pause", ProfileIDs: []string{"fixture-evm", "fixture-koinos"}, Pause: true, Expiration: fmt.Sprint(fixture.now.Add(time.Hour).UnixMilli())}
	res := request(http.MethodPost, "/v1/governance/proposals", create)
	if res.Code != http.StatusCreated {
		t.Fatal(res.Body.String())
	}
	var proposal GovernanceProposal
	if json.Unmarshal(res.Body.Bytes(), &proposal) != nil || proposal.Digest == "" {
		t.Fatal("typed proposal response is invalid")
	}
	if res := request(http.MethodPost, "/v1/governance/submit", map[string]string{"proposalId": proposal.ID, "profileId": proposal.Routes[0].Profile.ID}); res.Code != http.StatusConflict {
		t.Fatal("API submitted a route without current quorum")
	}
	for _, route := range proposal.Routes {
		for i := 0; i < 2; i++ {
			envelope := GovernanceSignatureEnvelope{SchemaVersion: 1, ProposalID: proposal.ID, ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Signature: governanceSignature(t, route, fixture.keys[route.Profile.ID][i])}
			if res := request(http.MethodPost, "/v1/governance/signatures", envelope); res.Code != http.StatusOK {
				t.Fatal(res.Body.String())
			}
		}
	}
	res = request(http.MethodGet, "/v1/governance", nil)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"state":"ready"`) || strings.Contains(res.Body.String(), token) || strings.Contains(res.Body.String(), "127.0.0.1:1") {
		t.Fatal("governance inventory is incomplete or leaked private configuration")
	}
	for _, forbidden := range []string{"/v1/governance/sign", "/v1/sign", "/v1/unlock", "/v1/exec"} {
		if res := request(http.MethodPost, forbidden, map[string]string{}); res.Code != http.StatusNotFound {
			t.Fatalf("browser-facing secret or arbitrary execution route exists: %s", forbidden)
		}
	}
}

func TestGovernanceReadyEvidenceExpiresUntilExplicitRevalidation(t *testing.T) {
	store, _ := OpenStore(privateDir(t))
	defer store.Close()
	fixture := newGovernanceFixture(t, store)
	proposal, err := store.CreateGovernance(context.Background(), CreateGovernanceProposal{ID: "stale-ready", ProfileIDs: []string{"fixture-evm", "fixture-koinos"}, Pause: true, Expiration: fmt.Sprint(fixture.now.Add(time.Hour).UnixMilli())}, fixture.observe, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range proposal.Routes {
		for index := 0; index < 2; index++ {
			proposal, err = store.AddGovernanceSignature(context.Background(), GovernanceSignatureEnvelope{SchemaVersion: 1, ProposalID: proposal.ID, ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Signature: governanceSignature(t, route, fixture.keys[route.Profile.ID][index])}, fixture.observe, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	staleAt := fixture.now.Add(31 * time.Second)
	inventory := store.GovernanceInventory(true, staleAt)
	if inventory.Proposals[0].State != "blocked" || inventory.Proposals[0].Routes[0].State != "stale" {
		t.Fatal("stale authority still enabled a governance action")
	}
	fresh := fixture
	fresh.observations = map[string]Observation{}
	for id, observation := range fixture.observations {
		observation.ObservedAt = staleAt
		fresh.observations[id] = observation
	}
	proposal, err = store.RevalidateGovernance(context.Background(), proposal.ID, fresh.observe, staleAt)
	if err != nil || proposal.State != "ready" {
		t.Fatalf("explicit fresh revalidation did not restore readiness: %+v %v", proposal, err)
	}
}
