package managed

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func chainFixture(t *testing.T) (*ChainVerifier, Policy, FinalEVMState, FinalKoinosState) {
	t.Helper()
	vectors := transferVectors(t)
	ep, kp := vectors[0].Profile, vectors[3].Profile
	kp.NetworkID = "EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	for _, p := range []*operator.Profile{&ep, &kp} {
		p.Reviewed = true
		p.CodeHash = strings.Repeat("a", 64)
		p.ReviewEvidence = "synthetic chain composition"
	}
	evm, e := NewEVMSnapshot(operator.Binding{Profile: ep, RPC: "http://127.0.0.1:1"})
	if e != nil {
		t.Fatal(e)
	}
	koinos, e := NewKoinosSnapshot(operator.Binding{Profile: kp, RPC: "http://127.0.0.1:2"}, "http://127.0.0.1:3")
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := NewChainVerifier(evm, koinos)
	if e != nil {
		t.Fatal(e)
	}
	p := policy()
	p.EVMAddress = ep.Contract
	p.KoinosAddress = kp.Contract
	ev := FinalEVMState{ProfileDigest: ep.Digest(), Height: 5, BlockHash: strings.Repeat("b", 64), CodeHash: ep.CodeHash, Nonce: "1", Validators: []string{p.EVMAddress}, Membership: map[string]bool{p.EVMAddress: true}, ObservedAt: time.Now()}
	ko := FinalKoinosState{ProfileDigest: kp.Digest(), Height: 5, BlockHash: strings.Repeat("c", 64), CodeHash: kp.CodeHash, Nonce: 1, StateRoot: "1220" + strings.Repeat("d", 64), Validators: []string{p.KoinosAddress}, ObservedAt: time.Now()}
	return verifier, p, ev, ko
}
func TestChainVerifierComposesFinalMembershipWithoutLocalApprovals(t *testing.T) {
	for _, kind := range []string{"good", "replacement", "evm-old-active", "koinos-old-active", "unprobed-old", "one-key-rotation", "evm-paused", "koinos-paused", "evm-missing", "koinos-missing", "stale", "wrong-profile", "wrong-code", "read-failure"} {
		t.Run(kind, func(t *testing.T) {
			v, p, ev, ko := chainFixture(t)
			if kind == "replacement" || strings.Contains(kind, "old") || kind == "one-key-rotation" {
				p.PreviousEVM = "0x2222222222222222222222222222222222222222"
				p.PreviousKoinos = "1111111111111111111114oLvT2"
				ev.Membership[p.PreviousEVM] = false
				if p.PreviousKoinos == p.KoinosAddress {
					t.Fatal("fixture requires distinct old key")
				}
			}
			switch kind {
			case "evm-old-active":
				ev.Membership[p.PreviousEVM] = true
			case "koinos-old-active":
				ko.Validators = append(ko.Validators, p.PreviousKoinos)
			case "unprobed-old":
				delete(ev.Membership, p.PreviousEVM)
			case "one-key-rotation":
				p.PreviousKoinos = p.KoinosAddress
			case "evm-paused":
				ev.Paused = true
			case "koinos-paused":
				ko.Paused = true
			case "evm-missing":
				ev.Membership[p.EVMAddress] = false
			case "koinos-missing":
				ko.Validators = nil
			case "stale":
				ev.ObservedAt = time.Now().Add(-time.Minute)
			case "wrong-profile":
				ko.ProfileDigest = strings.Repeat("f", 64)
			case "wrong-code":
				ev.CodeHash = strings.Repeat("f", 64)
			}
			v.evmRead = func(_ context.Context, probes []string) (FinalEVMState, error) {
				if len(probes) == 0 || probes[0] != p.EVMAddress {
					t.Error("missing identity probe")
				}
				return ev, nil
			}
			v.koinosRead = func(_ context.Context, seed string, ids []string) (FinalKoinosState, error) {
				if seed != p.KoinosAddress || len(ids) != 0 {
					t.Error("wrong membership seed")
				}
				if kind == "read-failure" {
					return ko, errors.New("unavailable")
				}
				return ko, nil
			}
			evidence, e := v.Inspect(context.Background(), p)
			if kind == "good" || kind == "replacement" {
				if e != nil {
					t.Fatal(e)
				}
				if !evidence.MembershipFinal || !evidence.ProvenanceVerified || !evidence.NetworksMatch || !evidence.LocalDevelopment || evidence.HostSecure || evidence.ReleaseApproved || !validHash(evidence.Checkpoint) || evidence.PolicySHA256 != Digest(p) || evidence.RotationFinal != (kind == "replacement") {
					t.Fatalf("bad evidence %+v", evidence)
				}
				s := &Session{policy: p, verifier: v}
				if s.check(context.Background()) == nil {
					t.Fatal("chain evidence alone allowed activation")
				}
				if _, e = v.Reconcile(context.Background(), p, Journal{Operations: map[string]Operation{"pending": {}}}); e == nil {
					t.Fatal("base certified unexamined operations")
				}
				if _, e = v.Operation(context.Background(), p, "arbitrary"); e == nil {
					t.Fatal("untyped signing accepted")
				}
			} else if e == nil {
				t.Fatal("unsafe chain evidence accepted")
			}
		})
	}
}
func TestChainVerifierRejectsRelabeledPublicNetworks(t *testing.T) {
	for _, network := range []string{"EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==", "EiBncD4pKRIQWco_WRqo5Q-xnXR7JuO3PtZv983mKdKHSQ=="} {
		v, _, _, _ := chainFixture(t)
		v.koinos.live.Profile.NetworkID = network
		if _, e := NewChainVerifier(v.evm, v.koinos); e == nil {
			t.Fatal("public Koinos identity accepted")
		}
	}
	for _, network := range []string{"1", "11155111"} {
		v, _, _, _ := chainFixture(t)
		v.evm.binding.Profile.NetworkID = network
		if _, e := NewChainVerifier(v.evm, v.koinos); e == nil {
			t.Fatal("public EVM identity accepted")
		}
	}
}

func TestChainAnchorAndTypedRecoveryRemainSeparate(t *testing.T) {
	chain, p, ev, ko := chainFixture(t)
	chain.evmRead = func(context.Context, []string) (FinalEVMState, error) { return ev, nil }
	chain.koinosRead = func(context.Context, string, []string) (FinalKoinosState, error) { return ko, nil }
	_, reader, _, retained := operationFixture(t)
	reader.observation.SourceProfileDigest = chain.evm.binding.Profile.Digest()
	reader.observation.DestinationProfileDigest = chain.koinos.live.Profile.Digest()
	verifier, e := NewOperationVerifier(chain, reader, chain.evm.binding.Profile, chain.koinos.live.Profile)
	if e != nil {
		t.Fatal(e)
	}
	j := Journal{Schema: 1, PolicySHA256: Digest(p), Operations: map[string]Operation{retained.ID: retained}}
	checkpoint, e := verifier.Reconcile(context.Background(), p, j)
	if e != nil || !validHash(checkpoint) {
		t.Fatal("joined recovery failed", e)
	}
	if len(j.Operations) != 1 {
		t.Fatal("caller journal mutated")
	}
	reader.observation.Transfer.Amount = "2"
	if _, e = verifier.Reconcile(context.Background(), p, j); e == nil {
		t.Fatal("chain anchor bypassed retained transfer verification")
	}
}
