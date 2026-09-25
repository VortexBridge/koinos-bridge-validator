package operator

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"gopkg.in/yaml.v2"
)

func participationFixture(t *testing.T) (maintenanceFixture, ParticipationRequest, []SignedParticipationObservation) {
	t.Helper()
	f := newMaintenanceFixture(t)
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	revision, _, _ := f.stores[0].Summary()
	request, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"probe-a", revision, envelope}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	reports := []SignedParticipationObservation{}
	for _, s := range f.stores {
		report, err := s.ObserveParticipation(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	return f, request, reports
}

func TestParticipationStageEvidenceIsPrivateFreshAndPolicyBound(t *testing.T) {
	f := newMaintenanceFixture(t)
	s := f.stores[1]
	now := time.Now().UTC()
	evidence := []ParticipationStageEvidence{}
	for i, stage := range []string{"peer", "api", "frontend"} {
		evidence = append(evidence, ParticipationStageEvidence{SchemaVersion: 1, InstanceID: s.InstanceID(), RouteID: f.policy.Routes[0].ID, Stage: stage, Kind: participationStageKinds[stage], CheckedAt: now.Add(-time.Second), ExpiresAt: now.Add(2 * time.Minute), EvidenceDigest: fmt.Sprintf("%064x", i+1), State: "passed", Notice: "Synthetic isolated stage evidence; no production endpoint or credential is included."})
	}
	path := filepath.Join(t.TempDir(), "stage-evidence.json")
	raw, _ := json.Marshal(evidence)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	recorded, err := s.RecordParticipationStageEvidence(path, now)
	if err != nil || !reflect.DeepEqual(recorded, evidence) {
		t.Fatal("valid private stage evidence was not recorded", err)
	}
	stored := filepath.Join(s.dir, "maintenance", "stage-evidence.json")
	if info, err := os.Stat(stored); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("stage evidence is not a private durable file", err)
	}
	loaded, err := s.participationStageEvidence(f.policy, now.Add(time.Second))
	if err != nil || len(loaded) != 3 {
		t.Fatal("recorded stage evidence could not be revalidated", loaded, err)
	}

	invalid := append([]ParticipationStageEvidence{}, evidence...)
	invalid[0].InstanceID = f.stores[0].InstanceID()
	raw, _ = json.Marshal(invalid)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordParticipationStageEvidence(path, now); err == nil {
		t.Fatal("stage evidence for another operator was accepted")
	}
	if _, err := s.RecordParticipationStageEvidence("relative.json", now); err == nil {
		t.Fatal("relative unreviewed stage evidence path was accepted")
	}
}

func TestParticipationExternalStagesExcludeUpdatingOperator(t *testing.T) {
	f := newMaintenanceFixture(t)
	requester := f.stores[0].InstanceID()
	otherA, otherB := f.stores[1].InstanceID(), f.stores[2].InstanceID()
	states := map[string]map[string]string{f.policy.Routes[0].ID: {otherA: "signing-key-proved", otherB: "signing-key-proved"}}
	external := map[string]map[string]bool{}
	for _, stage := range []string{"peer", "api", "frontend"} {
		external[contractTargetKey(f.policy.Routes[0].ID, stage)] = map[string]bool{requester: true, otherA: true, otherB: true}
	}
	stages, contractKeys := participationStages(f.policy, requester, states, external)
	if !contractKeys {
		t.Fatal("two non-updating synthetic signers did not satisfy contract key thresholds")
	}
	for _, stage := range stages {
		if stage.State != "key-threshold-passed" && stage.State != "evidence-threshold-passed" {
			t.Fatalf("stage %s did not pass with two non-updating operators: %+v", stage.Stage, stage)
		}
		for _, id := range stage.Eligible {
			if id == requester {
				t.Fatalf("updating operator counted toward its own %s threshold", stage.Stage)
			}
		}
	}
}

func TestParticipationCanJoinEverySyntheticStageWithoutCountingRequester(t *testing.T) {
	f := newMaintenanceFixture(t)
	identities := make([]syntheticBridgeIdentity, len(f.stores))
	for i := range f.stores {
		identities[i] = newSyntheticBridgeIdentity(t)
		f.policy.Members[i].EVMAddress = identities[i].evmAddress
		f.policy.Members[i].KoinosAddress = identities[i].koinosAddress
	}
	f.plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
	f.savePolicy(t)
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	revision, _, _ := f.stores[0].Summary()
	request, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"all-stage-proof", revision, envelope}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	reports := make([]SignedParticipationObservation, len(f.stores))
	for i, operatorStore := range f.stores {
		reports[i] = signedKeyParticipationResponse(t, operatorStore, request, f.policy.Routes[0], identities[i])
		checkedAt := reports[i].Observation.ObservedAt.Add(-time.Millisecond)
		for j, stage := range []string{"peer", "api", "frontend"} {
			reports[i].Observation.StageEvidence = append(reports[i].Observation.StageEvidence, ParticipationStageEvidence{SchemaVersion: 1, InstanceID: operatorStore.InstanceID(), RouteID: f.policy.Routes[0].ID, Stage: stage, Kind: participationStageKinds[stage], CheckedAt: checkedAt, ExpiresAt: checkedAt.Add(time.Minute), EvidenceDigest: fmt.Sprintf("%064x", i*10+j+1), State: "passed", Notice: "Synthetic isolated stage evidence."})
		}
		_, key, keyErr := operatorStore.maintenanceIdentity()
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		reports[i].Signature = hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", reports[i].Observation)))
	}
	now := request.Probe.Challenge.IssuedAt.Add(2 * time.Second)
	verified, err := VerifyParticipation(request, reports, f.policy, now)
	if err != nil || !verified.AllResponded || !verified.ContractKeyThresholdsMet {
		t.Fatal("fresh all-stage observations failed", verified, err)
	}
	requester := f.stores[0].InstanceID()
	eligible := []string{f.stores[1].InstanceID(), f.stores[2].InstanceID()}
	applyParticipationContractObservations(&verified, []ParticipationContractObservation{
		{RouteID: f.policy.Routes[0].ID, Stage: "evm-contract", Family: "evm", State: "verified", Quorum: 2, MembershipEligible: eligible},
		{RouteID: f.policy.Routes[0].ID, Stage: "koinos-contract", Family: "koinos", State: "verified", Quorum: 2, MembershipEligible: eligible},
	})
	if !verified.ActivationReady || !verified.ContractMembershipThresholdsMet {
		t.Fatal("complete synthetic participation evidence did not become ready", verified)
	}
	for _, stage := range verified.Stages {
		for _, id := range stage.Eligible {
			if id == requester {
				t.Fatalf("requester counted toward %s", stage.Stage)
			}
		}
	}
	reports[1].Observation.StageEvidence[0].EvidenceDigest = strings.Repeat("f", 64)
	if _, err := VerifyParticipation(request, reports, f.policy, now); err == nil {
		t.Fatal("changed stage evidence survived the operator signature")
	}
}
func TestParticipationAuthenticatedUnavailableIsNotQuorum(t *testing.T) {
	f, req, reports := participationFixture(t)
	report, err := f.stores[0].CheckParticipation(context.Background(), reports, time.Now().UTC())
	if err != nil || !report.AllResponded || report.ActivationReady || len(report.Members) != 3 {
		t.Fatal(report, err)
	}
	for _, m := range report.Members {
		if m.State != "unavailable" {
			t.Fatal(m)
		}
	}
	partial, err := VerifyParticipation(req, reports[:1], f.policy, time.Now().UTC())
	if err != nil || partial.AllResponded || len(partial.Missing) != 2 {
		t.Fatal(partial, err)
	}
	// Exact challenge retries remain stable across an operator restart.
	dir := f.stores[0].dir
	f.stores[0].Close()
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retry, err := reopened.BeginParticipation(BeginParticipationRequest{req.Probe.Challenge.ID, 0, req.Envelope}, time.Now().UTC())
	if err != nil || !reflect.DeepEqual(req, retry) {
		t.Fatal("challenge changed on retry", err)
	}
	if _, err := reopened.CheckParticipation(context.Background(), reports, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	revision, _, _ := reopened.Summary()
	if _, err := reopened.BeginParticipation(BeginParticipationRequest{"another", revision, req.Envelope}, time.Now().UTC()); err == nil {
		t.Fatal("replaced active challenge")
	}
	if err := reopened.RevokeRelease(req.Probe.Challenge.ReleaseDigest, revision, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.CheckParticipation(context.Background(), reports, time.Now().UTC()); err == nil {
		t.Fatal("accepted revoked approval")
	}
}
func TestParticipationRejectsReplayTamperingAndStaleReports(t *testing.T) {
	f, req, reports := participationFixture(t)
	for _, name := range []string{"changed-report", "duplicate", "unknown", "wrong-probe", "stale", "future", "wrong-plan", "wrong-release", "expired-probe", "changed-policy", "wrong-domain"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(reports)
			var copy []SignedParticipationObservation
			json.Unmarshal(raw, &copy)
			request := req
			policy := f.policy
			now := time.Now().UTC()
			switch name {
			case "changed-report":
				copy[0].Observation.Problem = "healthy"
			case "duplicate":
				copy[1] = copy[0]
			case "unknown":
				copy[0].Observation.InstanceID = "unknown"
			case "wrong-probe":
				copy[0].Observation.ProbeDigest = strings.Repeat("f", 64)
			case "stale":
				now = copy[0].Observation.ObservedAt.Add(30 * time.Second)
			case "future":
				now = copy[0].Observation.ObservedAt.Add(-time.Nanosecond)
			case "wrong-plan":
				request.Probe.Challenge.PlanDigest = strings.Repeat("f", 64)
			case "wrong-release":
				request.Probe.Challenge.ReleaseDigest = strings.Repeat("f", 64)
			case "expired-probe":
				now = req.Probe.Challenge.ExpiresAt
			case "changed-policy":
				policy.ID = "changed-policy"
			case "wrong-domain":
				_, key, _ := f.stores[0].maintenanceIdentity()
				copy[0].Signature = hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-PROBE-V1", copy[0].Observation)))
			}
			if _, err := VerifyParticipation(request, copy, policy, now); err == nil {
				t.Fatal("accepted", name)
			}
		})
	}
	// A new locally generated nonce cannot accept old responses, even for the same plan.
	now := req.Probe.Challenge.ExpiresAt.Add(time.Second)
	revision, _, _ := f.stores[0].Summary()
	next, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"probe-b", revision, req.Envelope}, now)
	if err != nil || next.Probe.Challenge.Nonce == req.Probe.Challenge.Nonce {
		t.Fatal(next, err)
	}
	if _, err := VerifyParticipation(next, reports, f.policy, now); err == nil {
		t.Fatal("replayed old responses")
	}
}
func TestParticipationRequiresLocalReservationAndStrictHTTP(t *testing.T) {
	f, req, _ := participationFixture(t)
	api := NewServer(f.stores[1], strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	if w := instanceRequest(api, "POST", "/v1/maintenance/participation/respond", map[string]interface{}{"probe": req.Probe, "envelope": req.Envelope, "snapshot": "supplied-health"}); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := instanceRequest(api, "POST", "/v1/maintenance/participation/respond", req); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := os.Remove(filepath.Join(f.stores[1].dir, "maintenance", "journal.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.stores[1].ObserveParticipation(context.Background(), req); err == nil {
		t.Fatal("signed without local reservation history")
	}
}
func TestParticipationPortableCLI(t *testing.T) {
	f, req, _ := participationFixture(t)
	root := privateDir(t)
	binary := filepath.Join(root, "operator")
	command := exec.Command("go", "build", "-o", binary, "../../cmd/vortex-operator")
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	path := filepath.Join(root, "request.json")
	raw, _ := json.Marshal(req)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var reports []SignedParticipationObservation
	for _, s := range f.stores {
		s.Close()
		out, err := exec.Command(binary, "--data", s.dir, "--participation-file", path, "participation-respond").CombinedOutput()
		if err != nil {
			t.Fatalf("respond: %v %s", err, out)
		}
		var report SignedParticipationObservation
		if json.Unmarshal(out, &report) != nil {
			t.Fatal("invalid response")
		}
		reports = append(reports, report)
	}
	raw, _ = json.Marshal(reports)
	path = filepath.Join(root, "responses.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(binary, "--data", f.stores[0].dir, "--participation-file", path, "participation-verify").CombinedOutput()
	if err != nil {
		t.Fatalf("verify: %v %s", err, out)
	}
	var result ParticipationVerification
	if json.Unmarshal(out, &result) != nil || !result.AllResponded || result.ActivationReady {
		t.Fatal(string(out))
	}
}

func TestParticipationCapturesLiveWorkerWithoutClaimingQuorum(t *testing.T) {
	f := newMaintenanceFixture(t)
	reporter, _ := progressStoreFixture(t)
	member, err := reporter.InitializeMaintenance()
	if err != nil {
		t.Fatal(err)
	}
	old := f.stores[1].InstanceID()
	f.stores[1] = reporter
	f.policy.Members[1] = member
	// Only the requester has a planned outage in this synthetic observation test.
	f.plan.Windows = f.plan.Windows[:1]
	snapshot, err := reporter.captureProgress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	binding := snapshot.Worker.Health.NetworkBinding
	route := &f.policy.Routes[0]
	route.EVM.NetworkID = binding.EVMNetworkID
	route.EVM.Contract = binding.EVMContract
	route.Koinos.NetworkID = binding.KoinosNetworkID
	route.Koinos.Contract = binding.KoinosContract
	for i := range route.Stages {
		for j, id := range route.Stages[i].Participants {
			if id == old {
				route.Stages[i].Participants[j] = member.InstanceID
			}
		}
	}
	f.plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
	f.savePolicy(t)
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	rev, _, _ := f.stores[0].Summary()
	req, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"live-worker", rev, envelope}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := reporter.ObserveParticipation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Observation.Snapshot == nil || signed.Observation.Problem != "" {
		t.Fatal(signed)
	}
	result, err := VerifyParticipation(req, []SignedParticipationObservation{signed}, f.policy, time.Now().UTC())
	if err != nil || result.Members[0].State != "observation-only" || result.ActivationReady {
		t.Fatal(result, err)
	}
	// A valid scheduling signature cannot turn a different route into accepted
	// evidence. Nor can stale counters be hidden behind a fresh outer timestamp.
	_, key, _ := reporter.maintenanceIdentity()
	for _, test := range []string{"wrong-route", "old-snapshot", "incomplete"} {
		raw, _ := json.Marshal(signed)
		var bad SignedParticipationObservation
		json.Unmarshal(raw, &bad)
		switch test {
		case "wrong-route":
			bad.Observation.Snapshot.Worker.Health.NetworkBinding.EVMNetworkID = "1"
		case "old-snapshot":
			bad.Observation.Snapshot.SampledAt = req.Probe.Challenge.IssuedAt.Add(-time.Second)
		case "incomplete":
			a := bad.Observation.Snapshot.Worker.Health.Activity["evm-to-koinos"]
			a.Complete = false
			bad.Observation.Snapshot.Worker.Health.Activity["evm-to-koinos"] = a
		}
		bad.Signature = hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", bad.Observation)))
		if _, err := VerifyParticipation(req, []SignedParticipationObservation{bad}, f.policy, time.Now().UTC()); err == nil {
			t.Fatal("accepted", test)
		}
	}
}

func TestParticipationStoredChallengeAndSupersededApproval(t *testing.T) {
	f, req, reports := participationFixture(t)
	approvals := f.stores[0].ReleaseApprovals()
	if !currentParticipationApproval(req.Envelope, approvals, f.stores[0].InstanceID()) {
		t.Fatal("fixture approval missing")
	}
	newer := approvals[0]
	newer.Sequence++
	newer.Digest = strings.Repeat("f", 64)
	newer.Revoked = true
	if currentParticipationApproval(req.Envelope, append(approvals, newer), f.stores[0].InstanceID()) {
		t.Fatal("superseded release still current")
	}
	req.Probe.Challenge.ExpiresAt = req.Probe.Challenge.IssuedAt.Add(time.Second)
	raw, _ := json.Marshal(req)
	if err := os.WriteFile(filepath.Join(f.stores[0].dir, "maintenance", "participation.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	revision, _, _ := f.stores[0].Summary()
	if _, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"replacement", revision, req.Envelope}, req.Probe.Challenge.ExpiresAt.Add(time.Minute)); err == nil {
		t.Fatal("replaced corrupted challenge")
	}
	if _, err := f.stores[0].CheckParticipation(context.Background(), reports, time.Now().UTC()); err == nil {
		t.Fatal("accepted modified stored challenge")
	}
}

type syntheticBridgeIdentity struct {
	evmKey        []byte
	koinosKey     []byte
	evmAddress    string
	koinosAddress string
}

func newSyntheticBridgeIdentity(t *testing.T) syntheticBridgeIdentity {
	t.Helper()
	evmPrivate, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	koinosPrivate, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	koinosKey := crypto.FromECDSA(koinosPrivate)
	digest := make([]byte, 32)
	digest[0] = 1
	signature := base64.URLEncoding.EncodeToString(util.SignKoinosHash(koinosKey, digest))
	koinosAddress, err := util.RecoverKoinosAddressFromSignature(signature, digest)
	if err != nil {
		t.Fatal(err)
	}
	return syntheticBridgeIdentity{
		evmKey: crypto.FromECDSA(evmPrivate), koinosKey: koinosKey,
		evmAddress: crypto.PubkeyToAddress(evmPrivate.PublicKey).Hex(), koinosAddress: koinosAddress,
	}
}

func signedKeyParticipationResponse(t *testing.T, s *Store, request ParticipationRequest, route MaintenanceRoute, identity syntheticBridgeIdentity) SignedParticipationObservation {
	t.Helper()
	sampledAt := request.Probe.Challenge.IssuedAt.Add(time.Second)
	startedAt := sampledAt.Add(-time.Minute)
	health := &worker.Health{
		InstanceID: s.InstanceID(), PID: 1234, StartedAt: startedAt, Mode: "signing",
		EVMAddress: identity.evmAddress, KoinosAddress: identity.koinosAddress,
		NetworkBinding: &worker.NetworkBinding{SchemaVersion: 1, EVMNetworkID: route.EVM.NetworkID, KoinosNetworkID: route.Koinos.NetworkID, EVMContract: route.EVM.Contract, KoinosContract: route.Koinos.Contract},
		Chains:         map[string]worker.ChainHealth{}, Activity: map[string]store.TransactionActivity{},
	}
	for _, chain := range []string{"evm", "koinos"} {
		health.Chains[chain] = worker.ChainHealth{Height: 10, UpdatedAt: sampledAt, Status: "observed"}
	}
	for _, direction := range progressDirections {
		health.Activity[direction] = store.TransactionActivity{Enabled: true, Complete: true, StartedAt: startedAt}
	}
	snapshot := ProgressSnapshot{SampledAt: sampledAt, Worker: WorkerStatus{
		Registered: true, RegistrationDigest: strings.Repeat("a", 64), BinarySHA256: strings.Repeat("b", 64),
		ConfigSHA256: strings.Repeat("c", 64), InstanceID: s.InstanceID(), State: "running", Health: health,
	}}
	probeDigest := maintenanceDigest(request.Probe.Challenge)
	challenge := worker.SigningProofChallenge{
		SchemaVersion: 1, ProbeDigest: probeDigest, InstanceID: health.InstanceID,
		PID: health.PID, StartedAt: health.StartedAt, EVMAddress: health.EVMAddress, KoinosAddress: health.KoinosAddress,
	}
	signingDigest, err := worker.SigningProofDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	evmPrivate, err := crypto.ToECDSA(identity.evmKey)
	if err != nil {
		t.Fatal(err)
	}
	proof := worker.SigningProof{
		Challenge:       challenge,
		EVMSignature:    "0x" + hex.EncodeToString(util.SignEthereumHash(evmPrivate, signingDigest)),
		KoinosSignature: base64.URLEncoding.EncodeToString(util.SignKoinosHash(identity.koinosKey, signingDigest)),
	}
	observation := ParticipationObservation{
		SchemaVersion: 1, InstanceID: s.InstanceID(), ProbeDigest: probeDigest,
		ObservedAt: sampledAt.Add(time.Millisecond), Snapshot: &snapshot, SigningProof: &proof,
	}
	_, key, err := s.maintenanceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return SignedParticipationObservation{Observation: observation, Signature: hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", observation)))}
}

func fakeEVMMembership(t *testing.T, profile Profile, validators []string) *httptest.Server {
	t.Helper()
	selectors := map[string]string{}
	for _, method := range []string{"chainId()", "nonce()", "paused()", "getValidatorsLength()", "validators(uint256)"} {
		selectors[hex.EncodeToString(crypto.Keccak256([]byte(method))[:4])] = method
	}
	network, ok := new(big.Int).SetString(profile.NetworkID, 10)
	if !ok {
		t.Fatal("invalid synthetic EVM network")
	}
	word := func(value *big.Int) string { return "0x" + fmt.Sprintf("%064x", value) }
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var result interface{}
		switch request.Method {
		case "eth_chainId":
			result = "0x" + network.Text(16)
		case "eth_getBlockByNumber":
			result = map[string]string{"number": "0x10", "hash": "0x" + strings.Repeat("a", 64)}
		case "eth_getCode":
			result = "0x6000"
		case "eth_call":
			var call map[string]string
			if err := json.Unmarshal(request.Params[0], &call); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			data := strings.TrimPrefix(call["data"], "0x")
			if len(data) < 8 {
				t.Error("short EVM call")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			switch selectors[data[:8]] {
			case "chainId()":
				result = word(new(big.Int).SetUint64(uint64(profile.BridgeChainID)))
			case "nonce()", "paused()":
				result = word(big.NewInt(0))
			case "getValidatorsLength()":
				result = word(new(big.Int).SetInt64(int64(len(validators))))
			case "validators(uint256)":
				if len(data) != 72 {
					t.Error("invalid validator index call")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				index, ok := new(big.Int).SetString(data[8:], 16)
				if !ok || !index.IsInt64() || index.Int64() < 0 || index.Int64() >= int64(len(validators)) {
					t.Error("invalid validator index")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				address, ok := new(big.Int).SetString(strings.TrimPrefix(validators[index.Int64()], "0x"), 16)
				if !ok {
					t.Error("invalid validator address")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				result = word(address)
			default:
				t.Error("unexpected EVM call selector")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		default:
			t.Errorf("unexpected RPC method %s", request.Method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
}

func TestParticipationJoinsKeyProofsWithFreshEVMContractMembership(t *testing.T) {
	for _, test := range []struct {
		name        string
		memberCount int
		wantState   string
		wantMembers int
	}{
		{"enough-current-members", 3, "membership-threshold-passed", 2},
		{"missing-current-member", 2, "membership-blocked", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newMaintenanceFixture(t)
			identities := make([]syntheticBridgeIdentity, len(f.stores))
			for i := range f.stores {
				identities[i] = newSyntheticBridgeIdentity(t)
				f.policy.Members[i].EVMAddress = identities[i].evmAddress
				f.policy.Members[i].KoinosAddress = identities[i].koinosAddress
			}
			profile := f.policy.Routes[0].EVM
			profile.CodeHash = hex.EncodeToString(crypto.Keccak256([]byte{0x60, 0x00}))
			profile.Reviewed = true
			profile.ReviewEvidence = "synthetic finalized membership fixture"
			f.policy.Routes[0].EVM = profile
			f.plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
			f.savePolicy(t)
			onChain := []string{}
			for i := 0; i < test.memberCount; i++ {
				onChain = append(onChain, identities[i].evmAddress)
			}
			rpc := fakeEVMMembership(t, profile, onChain)
			defer rpc.Close()
			revision, _, _ := f.stores[0].Summary()
			if _, err := f.stores[0].Apply(ApplyConfig{revision, "evm-membership-binding", Binding{profile, rpc.URL}}); err != nil {
				t.Fatal(err)
			}
			envelope := MaintenanceEnvelope{Plan: f.plan}
			for i := range f.stores {
				envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
			}
			revision, _, _ = f.stores[0].Summary()
			request, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"membership-proof", revision, envelope}, f.now)
			if err != nil {
				t.Fatal(err)
			}
			reports := make([]SignedParticipationObservation, len(f.stores))
			for i, store := range f.stores {
				reports[i] = signedKeyParticipationResponse(t, store, request, f.policy.Routes[0], identities[i])
			}
			verified, err := f.stores[0].CheckParticipation(context.Background(), reports, request.Probe.Challenge.IssuedAt.Add(2*time.Second))
			if err != nil || !verified.ContractKeyThresholdsMet || verified.ContractMembershipThresholdsMet || verified.ActivationReady {
				t.Fatal("unexpected joined participation result", verified, err)
			}
			if len(verified.ContractObservations) != 2 {
				t.Fatal("missing per-contract observations", verified.ContractObservations)
			}
			seenEVM, seenKoinos := false, false
			for _, observation := range verified.ContractObservations {
				switch observation.Family {
				case "evm":
					seenEVM = true
					if observation.State != "verified" || observation.Quorum != 2 || len(observation.MembershipEligible) != test.wantMembers {
						t.Fatal("unexpected EVM membership observation", observation)
					}
				case "koinos":
					seenKoinos = true
					if observation.State != "unknown" || len(observation.MembershipEligible) != 0 {
						t.Fatal("missing Koinos binding did not remain unknown", observation)
					}
				}
			}
			if !seenEVM || !seenKoinos {
				t.Fatal("missing chain observation", verified.ContractObservations)
			}
			for _, stage := range verified.Stages {
				if stage.Stage == "evm-contract" && (stage.State != test.wantState || stage.ObservedRequired != 2 || len(stage.MembershipEligible) != test.wantMembers) {
					t.Fatal("unexpected EVM stage result", stage)
				}
				if stage.Stage == "koinos-contract" && stage.State != "membership-unknown" {
					t.Fatal("Koinos stage did not remain unknown", stage)
				}
			}
		})
	}
}

func TestParticipationRequiresFinalityAndCodeBeforeCountingMembership(t *testing.T) {
	identity := newSyntheticBridgeIdentity(t)
	profile := vectors(t)[0].Profile
	profile.CodeHash = strings.Repeat("a", 64)
	profile.Reviewed = true
	profile.ReviewEvidence = "synthetic profile"
	target := participationContractTarget{"route-a", "evm-contract", profile, []string{"operator-a"}, []string{"operator-a"}}
	members := map[string]MaintenanceMember{"operator-a": {InstanceID: "operator-a", EVMAddress: identity.evmAddress, KoinosAddress: identity.koinosAddress}}
	binding := Binding{Profile: profile, RPC: "http://127.0.0.1:8545"}
	base := Observation{Complete: true, ProfileID: profile.ID, ObservedAt: time.Now().UTC(), Status: "observed", NetworkID: profile.NetworkID, Block: "0x1", BlockHash: "0x" + strings.Repeat("b", 64), Finality: "finalized", CodeHash: profile.CodeHash, BridgeChainID: profile.BridgeChainID, Validators: []string{identity.evmAddress}, Quorum: 1}
	verified := evaluateParticipationContractObservation(target, members, binding, true, &base)
	if verified.State != "verified" || len(verified.MembershipEligible) != 1 {
		t.Fatal("complete finalized membership was not verified", verified)
	}
	for _, test := range []struct {
		name   string
		change func(*Observation)
		state  string
	}{
		{"missing-code", func(o *Observation) { o.CodeHash = "" }, "unknown"},
		{"unfinalized", func(o *Observation) { o.Finality = "head snapshot; not pinned to irreversible state" }, "unknown"},
		{"wrong-code", func(o *Observation) { o.CodeHash = strings.Repeat("c", 64) }, "blocked"},
		{"wrong-network", func(o *Observation) { o.NetworkID = "1" }, "blocked"},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := base
			test.change(&observation)
			result := evaluateParticipationContractObservation(target, members, binding, true, &observation)
			if result.State != test.state || len(result.MembershipEligible) != 0 {
				t.Fatal("unsafe membership evidence was counted", result)
			}
		})
	}
	changedBinding := binding
	changedBinding.Profile.Name = "changed deployment"
	result := evaluateParticipationContractObservation(target, members, changedBinding, true, nil)
	if result.State != "blocked" {
		t.Fatal("changed local profile was not blocked", result)
	}
}

func TestParticipationRequiresEveryObservedContractQuorum(t *testing.T) {
	verification := ParticipationVerification{Stages: []ParticipationStageResult{
		{RouteID: "route-a", Stage: "evm-contract", Required: 2, Eligible: []string{"operator-b", "operator-c"}, MembershipEligible: []string{}, Unverified: []string{}},
		{RouteID: "route-a", Stage: "koinos-contract", Required: 2, Eligible: []string{"operator-b", "operator-c"}, MembershipEligible: []string{}, Unverified: []string{}},
		{RouteID: "route-a", Stage: "peer", Required: 2, Eligible: []string{}, MembershipEligible: []string{}, Unverified: []string{"operator-a", "operator-b", "operator-c"}, State: "unknown"},
	}}
	observations := []ParticipationContractObservation{
		{RouteID: "route-a", Stage: "evm-contract", Family: "evm", State: "verified", Quorum: 2, MembershipEligible: []string{"operator-b", "operator-c"}},
		{RouteID: "route-a", Stage: "koinos-contract", Family: "koinos", State: "verified", Quorum: 2, MembershipEligible: []string{"operator-b", "operator-c"}},
	}
	applyParticipationContractObservations(&verification, observations)
	if !verification.ContractMembershipThresholdsMet || verification.ActivationReady {
		t.Fatal("verified contract membership did not pass separately from activation", verification)
	}
	if verification.Stages[0].State != "membership-threshold-passed" || verification.Stages[1].State != "membership-threshold-passed" || verification.Stages[2].State != "unknown" {
		t.Fatal("contract evidence changed an external stage", verification.Stages)
	}

	verification.Stages[0].State = "key-threshold-passed"
	verification.Stages[1].State = "key-threshold-passed"
	observations[1].Quorum = 3
	applyParticipationContractObservations(&verification, observations)
	if verification.ContractMembershipThresholdsMet || verification.Stages[1].State != "membership-blocked" {
		t.Fatal("a stricter observed contract quorum was ignored", verification)
	}
}

func attachSyntheticSigningWorker(t *testing.T, s *Store, route MaintenanceRoute, identity syntheticBridgeIdentity, workerID string) func() {
	t.Helper()
	base := filepath.Join(t.TempDir(), "validator")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	evmKeyFile, koinosKeyFile := filepath.Join(base, "evm.key"), filepath.Join(base, "koinos.key")
	for _, path := range []string{evmKeyFile, koinosKeyFile} {
		if err := os.WriteFile(path, []byte("synthetic-key-never-read"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := util.YamlConfig{Bridge: util.BridgeConfig{
		InstanceID: workerID, EthereumNetworkID: route.EVM.NetworkID, KoinosNetworkID: route.Koinos.NetworkID,
		EthereumContract: route.EVM.Contract, KoinosContract: route.Koinos.Contract,
		EthereumPKFile: evmKeyFile, KoinosPKFile: koinosKeyFile,
	}}
	raw, err := yaml.Marshal(cfg)
	if err != nil || os.WriteFile(filepath.Join(base, "config.yml"), raw, 0600) != nil {
		t.Fatal("cannot write signing-worker configuration", err)
	}
	controlDir := filepath.Join(base, "bridge", ".operator")
	if err := worker.PrivateDir(controlDir); err != nil {
		t.Fatal(err)
	}
	if err := worker.EnsureMode(controlDir, false, false); err != nil {
		t.Fatal(err)
	}
	monitor := worker.NewMonitor(workerID, false, identity.evmAddress, identity.koinosAddress)
	monitor.SetNetworkBinding(networkBinding(cfg))
	monitor.Progress("evm", 10)
	monitor.Progress("koinos", 10)
	startedAt := monitor.Snapshot().StartedAt
	monitor.SetActivitySource(func() map[string]store.TransactionActivity {
		return map[string]store.TransactionActivity{
			"evm-to-koinos": {Enabled: true, Complete: true, StartedAt: startedAt},
			"koinos-to-evm": {Enabled: true, Complete: true, StartedAt: startedAt},
		}
	})
	monitor.SetSigningProofSource(func(digest []byte) (string, string, error) {
		evmPrivate, err := crypto.ToECDSA(identity.evmKey)
		if err != nil {
			return "", "", err
		}
		return "0x" + hex.EncodeToString(util.SignEthereumHash(evmPrivate, digest)), base64.URLEncoding.EncodeToString(util.SignKoinosHash(identity.koinosKey, digest)), nil
	})
	control, err := worker.StartControl(controlDir, monitor, func() {})
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(base, "reviewed-validator")
	if err := os.WriteFile(binary, []byte("synthetic executable snapshot"), 0700); err != nil {
		control.Close()
		t.Fatal(err)
	}
	binaryBytes, _ := os.ReadFile(binary)
	hash := sha256.Sum256(binaryBytes)
	registration, err := s.RegisterWorker(base, binary, hex.EncodeToString(hash[:]))
	if err != nil || registration.Mode != "signing" {
		control.Close()
		t.Fatal("signing worker was not attached", registration, err)
	}
	status := s.WorkerStatus(context.Background())
	if status.State != "running" || status.Mode != "signing" {
		control.Close()
		t.Fatal("attached signing worker was not observable", status)
	}
	doctor := s.Doctor(context.Background())
	modePassed := false
	for _, check := range doctor.Checks {
		if check.ID == "data-mode" && check.Status == "passed" {
			modePassed = true
		}
	}
	if !modePassed {
		control.Close()
		t.Fatal("signing worker data mode failed local diagnostics", doctor)
	}
	if _, err := s.StartWorker(context.Background(), registrationDigest(registration)); err == nil {
		control.Close()
		t.Fatal("operator attempted to start an attached signing worker")
	}
	return func() { control.Close() }
}

func TestParticipationCollectsProofFromAttachedSigningWorkers(t *testing.T) {
	f := newMaintenanceFixture(t)
	identities := make([]syntheticBridgeIdentity, len(f.stores))
	for i := range f.stores {
		identities[i] = newSyntheticBridgeIdentity(t)
		f.policy.Members[i].EVMAddress = identities[i].evmAddress
		f.policy.Members[i].KoinosAddress = identities[i].koinosAddress
	}
	f.plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
	f.savePolicy(t)
	for i := 1; i < len(f.stores); i++ {
		defer attachSyntheticSigningWorker(t, f.stores[i], f.policy.Routes[0], identities[i], fmt.Sprintf("attached-signer-%d", i))()
	}
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	revision, _, _ := f.stores[0].Summary()
	request, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"attached-key-proof", revision, envelope}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	reports := make([]SignedParticipationObservation, len(f.stores))
	for i, s := range f.stores {
		reports[i], err = s.ObserveParticipation(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
	}
	verified, err := VerifyParticipation(request, reports, f.policy, time.Now().UTC())
	if err != nil || !verified.AllResponded || !verified.ContractKeyThresholdsMet || verified.ActivationReady {
		t.Fatal("attached signing workers did not satisfy the contract key proof flow", verified, err)
	}
}

func TestParticipationVerifiesBridgeKeyPossessionPerContractStage(t *testing.T) {
	f := newMaintenanceFixture(t)
	identities := make([]syntheticBridgeIdentity, len(f.stores))
	for i := range f.stores {
		identities[i] = newSyntheticBridgeIdentity(t)
		f.policy.Members[i].EVMAddress = identities[i].evmAddress
		f.policy.Members[i].KoinosAddress = identities[i].koinosAddress
	}
	f.plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
	f.savePolicy(t)
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	revision, _, _ := f.stores[0].Summary()
	request, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"key-proof", revision, envelope}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	reports := make([]SignedParticipationObservation, len(f.stores))
	for i, s := range f.stores {
		reports[i] = signedKeyParticipationResponse(t, s, request, f.policy.Routes[0], identities[i])
	}
	now := request.Probe.Challenge.IssuedAt.Add(2 * time.Second)
	verified, err := VerifyParticipation(request, reports, f.policy, now)
	if err != nil || !verified.AllResponded || !verified.ContractKeyThresholdsMet || verified.ActivationReady {
		t.Fatal(verified, err)
	}
	contractStages, externalStages := 0, 0
	for _, stage := range verified.Stages {
		switch stage.Stage {
		case "evm-contract", "koinos-contract":
			contractStages++
			if stage.State != "key-threshold-passed" || len(stage.Eligible) != 2 {
				t.Fatal("contract key threshold did not exclude only the updating operator", stage)
			}
		default:
			externalStages++
			if stage.State != "unknown" {
				t.Fatal("worker key proof upgraded an external stage", stage)
			}
		}
	}
	if contractStages != 2 || externalStages != 3 {
		t.Fatal("missing stage results", verified.Stages)
	}
	revision, _, _ = f.stores[0].Summary()
	readiness, err := f.stores[0].CheckUpdateReadiness(context.Background(), UpdateReadinessRequest{
		ID: "key-proof-readiness", ExpectedRevision: revision, ReleaseDigest: request.Probe.Challenge.ReleaseDigest,
		Platform: "linux-arm64", ParticipationResponses: reports,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	check, ok := readinessCheck(readiness, "signing-quorum")
	if !ok || check.State != "blocked" || !strings.Contains(check.Message, "proved enough locally mapped bridge keys") {
		t.Fatal("readiness did not preserve the external-stage blocker after contract key proof", check)
	}

	missingProof := append([]SignedParticipationObservation(nil), reports...)
	raw, _ := json.Marshal(reports[1])
	json.Unmarshal(raw, &missingProof[1])
	missingProof[1].Observation.SigningProof = nil
	_, key, _ := f.stores[1].maintenanceIdentity()
	missingProof[1].Signature = hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", missingProof[1].Observation)))
	withoutProof, err := VerifyParticipation(request, missingProof, f.policy, now)
	if err != nil || withoutProof.ContractKeyThresholdsMet {
		t.Fatal("missing worker proof met contract key thresholds", withoutProof, err)
	}

	wrongIdentity := newSyntheticBridgeIdentity(t)
	mismatch := append([]SignedParticipationObservation(nil), reports...)
	mismatch[1] = signedKeyParticipationResponse(t, f.stores[1], request, f.policy.Routes[0], wrongIdentity)
	withMismatch, err := VerifyParticipation(request, mismatch, f.policy, now)
	if err != nil || withMismatch.ContractKeyThresholdsMet {
		t.Fatal("wrong locally mapped key met contract thresholds", withMismatch, err)
	}
	mismatchVisible := false
	for _, member := range withMismatch.Members {
		if member.InstanceID == f.stores[1].InstanceID() && member.State == "signing-identity-mismatch" {
			mismatchVisible = true
		}
	}
	if !mismatchVisible {
		t.Fatal("wrong bridge identity was not visible", withMismatch.Members)
	}

	tampered := append([]SignedParticipationObservation(nil), reports...)
	raw, _ = json.Marshal(reports[1])
	json.Unmarshal(raw, &tampered[1])
	tampered[1].Observation.SigningProof.EVMSignature = "0x" + strings.Repeat("0", 130)
	tampered[1].Signature = hex.EncodeToString(ed25519.Sign(key, participationBytes("VORTEX-MAINTENANCE-OBSERVATION-V1", tampered[1].Observation)))
	if _, err := VerifyParticipation(request, tampered, f.policy, now); err == nil {
		t.Fatal("accepted invalid worker key proof")
	}
}

func TestParticipationDoesNotReuseBridgeKeyProofAcrossRoutes(t *testing.T) {
	f := newMaintenanceFixture(t)
	identities := make([]syntheticBridgeIdentity, len(f.stores))
	for i := range f.stores {
		identities[i] = newSyntheticBridgeIdentity(t)
		f.policy.Members[i].EVMAddress = identities[i].evmAddress
		f.policy.Members[i].KoinosAddress = identities[i].koinosAddress
	}
	firstRoute := f.policy.Routes[0]
	raw, _ := json.Marshal(firstRoute)
	var secondRoute MaintenanceRoute
	if err := json.Unmarshal(raw, &secondRoute); err != nil {
		t.Fatal(err)
	}
	secondRoute.ID = "second-synthetic-route"
	secondRoute.EVM.ID = "second-evm-route"
	secondRoute.EVM.Name = "Second synthetic EVM route"
	secondRoute.EVM.NetworkID = "31338"
	secondRoute.EVM.Contract = identities[0].evmAddress
	secondRoute.Koinos.ID = "second-koinos-route"
	secondRoute.Koinos.Name = "Second synthetic Koinos route"
	secondRoute.Koinos.Contract = identities[0].koinosAddress
	f.policy.Routes = append(f.policy.Routes, secondRoute)
	f.plan.PolicyDigest = MaintenancePolicyDigest(f.policy)
	f.savePolicy(t)
	envelope := MaintenanceEnvelope{Plan: f.plan}
	for i := range f.stores {
		envelope.Endorsements = append(envelope.Endorsements, f.endorse(t, i, f.plan))
	}
	revision, _, _ := f.stores[0].Summary()
	request, err := f.stores[0].BeginParticipation(BeginParticipationRequest{"route-bound-proof", revision, envelope}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	reports := make([]SignedParticipationObservation, len(f.stores))
	for i, s := range f.stores {
		reports[i] = signedKeyParticipationResponse(t, s, request, firstRoute, identities[i])
	}
	verified, err := VerifyParticipation(request, reports, f.policy, request.Probe.Challenge.IssuedAt.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if verified.ContractKeyThresholdsMet {
		t.Fatal("one route's worker proofs satisfied another route", verified.Stages)
	}
	counts := map[string]map[string]int{}
	for _, stage := range verified.Stages {
		if stage.Stage != "evm-contract" && stage.Stage != "koinos-contract" {
			continue
		}
		if counts[stage.RouteID] == nil {
			counts[stage.RouteID] = map[string]int{}
		}
		counts[stage.RouteID][stage.State]++
		if stage.RouteID == firstRoute.ID && (stage.State != "key-threshold-passed" || len(stage.Eligible) != 2) {
			t.Fatal("matching route did not count its non-updating proofs", stage)
		}
		if stage.RouteID == secondRoute.ID && (stage.State != "blocked" || len(stage.Eligible) != 0) {
			t.Fatal("proof leaked across route binding", stage)
		}
	}
	if counts[firstRoute.ID]["key-threshold-passed"] != 2 || counts[secondRoute.ID]["blocked"] != 2 {
		t.Fatal("missing route-specific contract results", verified.Stages)
	}
}
