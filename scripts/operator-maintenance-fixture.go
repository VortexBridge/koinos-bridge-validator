//go:build ignore
// +build ignore

// Creates disposable local scheduling fixtures. No workers, chain keys, RPCs,
// containers or network services are started. Never use these trust roots live.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func save(path string, value interface{}) {
	raw, err := json.MarshalIndent(value, "", "  ")
	must(err)
	must(os.WriteFile(path, raw, 0600))
}
func main() {
	fullConsent := flag.Bool("full-consent", false, "record all three synthetic endorsements for participation tests")
	flag.Parse()
	base, err := os.MkdirTemp("", "vortex-maintenance-dev.")
	must(err)
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := os.ReadFile("internal/operator/testdata/governance.json")
	must(err)
	var vectors struct {
		Vectors []struct {
			Profile operator.Profile `json:"profile"`
		} `json:"vectors"`
	}
	must(json.Unmarshal(raw, &vectors))
	var evm, koinos operator.Profile
	for _, v := range vectors.Vectors {
		if v.Profile.Family == "evm" {
			evm = v.Profile
		} else {
			koinos = v.Profile
		}
	}
	artifact := []byte("synthetic fixture, never executable")
	hash := sha256.Sum256(artifact)
	m := operator.ReleaseManifest{SchemaVersion: 1, ID: "maintenance-fixture", Component: "validator", Version: "1.0.1", Sequence: 2, Channel: "candidate", SourceCommit: strings.Repeat("a", 40), CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), CompatibleFrom: []string{"1.0.0"}, ConfigSchema: 1, DatabaseSchema: 1, SigningCodec: "synthetic-fixture-v1", MixedVersionsSafe: true, Recovery: "Synthetic schedule only; no executable installed", TestEvidence: []string{"synthetic schedule fixture"}, Artifacts: []operator.ReleaseArtifact{{Platform: "linux-arm64", SHA256: hex.EncodeToString(hash[:]), Size: uint64(len(artifact))}}}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	canonical, err := operator.CanonicalRelease(m)
	must(err)
	release := operator.SignedRelease{Manifest: m, Signatures: []operator.ReleaseSignature{{Publisher: "test-only", Signature: hex.EncodeToString(ed25519.Sign(key, canonical))}}}
	trust := operator.ReleaseTrust{SchemaVersion: 1, RequiredSignatures: 1, Publishers: map[string]string{"test-only": hex.EncodeToString(pub)}}
	verified, err := operator.VerifyRelease(release, trust, now)
	must(err)
	policy := operator.MaintenancePolicy{SchemaVersion: 1, ID: "test-only-roster", ExpiresAt: now.Add(12 * time.Hour)}
	stores := []*operator.Store{}
	ids := []string{}
	for i := 0; i < 3; i++ {
		dir := filepath.Join(base, fmt.Sprintf("operator-%d", i))
		s, err := operator.OpenStore(dir)
		must(err)
		defer s.Close()
		member, err := s.InitializeMaintenance()
		must(err)
		save(filepath.Join(dir, "release-trust.json"), trust)
		_, err = s.ApproveRelease(operator.ApproveRelease{InstanceID: s.InstanceID(), ExpectedRevision: 0, Release: release, Digest: verified.Digest, WindowStart: now, WindowEnd: now.Add(8 * time.Hour)}, now)
		must(err)
		stores = append(stores, s)
		ids = append(ids, s.InstanceID())
		policy.Members = append(policy.Members, member)
	}
	route := operator.MaintenanceRoute{ID: "synthetic-route", EVM: evm, Koinos: koinos, Evidence: "TEST ONLY: declared 2 of 3; no chain execution or independent hosts"}
	for _, name := range []string{"evm-contract", "koinos-contract", "peer", "api", "frontend"} {
		route.Stages = append(route.Stages, operator.MaintenanceStage{Name: name, Required: 2, Participants: ids})
	}
	policy.Routes = []operator.MaintenanceRoute{route}
	plan := operator.MaintenancePlan{SchemaVersion: 1, ID: "synthetic-security-update", PolicyDigest: operator.MaintenancePolicyDigest(policy), CreatedAt: now}
	for i, id := range ids {
		start := now.Add(time.Duration(60+i*30) * time.Minute)
		plan.Windows = append(plan.Windows, operator.MaintenanceWindow{InstanceID: id, ReleaseDigest: verified.Digest, Start: start, End: start.Add(15 * time.Minute)})
	}
	envelope := operator.MaintenanceEnvelope{Plan: plan, Endorsements: []operator.MaintenanceEndorsement{}}
	for i := range stores {
		save(filepath.Join(base, fmt.Sprintf("operator-%d", i), "maintenance-policy.json"), policy)
	}
	report, err := operator.VerifyMaintenance(envelope, policy, now)
	must(err)
	firstEndorser := 1
	if *fullConsent {
		firstEndorser = 0
	}
	for i := firstEndorser; i < 3; i++ {
		revision, _, _ := stores[i].Summary()
		envelope, err = stores[i].EndorseMaintenanceEnvelope(operator.EndorseMaintenanceRequest{Envelope: envelope, Digest: report.Digest, ExpectedRevision: revision}, now)
		must(err)
	}
	_, err = stores[0].Token()
	must(err)
	save(filepath.Join(base, "plan.json"), envelope)
	save(filepath.Join(base, "test-only-policy.json"), policy)
	fmt.Println(base)
}
