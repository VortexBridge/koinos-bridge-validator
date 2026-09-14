package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func readinessCheck(receipt UpdateReadinessReceipt, id string) (UpdateReadinessCheck, bool) {
	for _, check := range receipt.Checks {
		if check.ID == id {
			return check, true
		}
	}
	return UpdateReadinessCheck{}, false
}

func TestUpdateReadinessPersistsExactBlockedEvidence(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	s, _, digest := installedFixture(t, now)
	if _, err := s.AdoptInstalledRelease(digest, "linux-arm64", now); err != nil {
		t.Fatal(err)
	}
	req := UpdateReadinessRequest{ID: "readiness-fixture", ExpectedRevision: 0, ReleaseDigest: digest, Platform: "linux-arm64", ParticipationResponses: []SignedParticipationObservation{}}
	receipt, err := s.CheckUpdateReadiness(context.Background(), req, now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "blocked" || receipt.ActivationReady || receipt.RequestDigest != maintenanceDigest(req) || !receipt.ExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("unsafe or malformed readiness receipt: %+v", receipt)
	}
	for _, id := range []string{"current-release", "staged-artifact", "compatibility", "candidate-test", "local-approval", "worker-observation", "encrypted-backup", "maintenance-reservation", "authenticated-participation", "signing-quorum", "prior-wave", "installer"} {
		if check, ok := readinessCheck(receipt, id); !ok || check.Message == "" {
			t.Fatalf("missing readiness check %s: %+v", id, receipt.Checks)
		}
	}
	if check, _ := readinessCheck(receipt, "current-release"); check.State != "passed" {
		t.Fatalf("valid current release was not recognized: %+v", check)
	}
	if check, _ := readinessCheck(receipt, "staged-artifact"); check.State != "passed" {
		t.Fatalf("valid staged bytes were not recognized: %+v", check)
	}
	if check, _ := readinessCheck(receipt, "installer"); check.State != "blocked" {
		t.Fatal("readiness receipt enabled the missing installer")
	}
	again, err := s.CheckUpdateReadiness(context.Background(), req, now.Add(time.Second))
	if err != nil || !again.CheckedAt.Equal(receipt.CheckedAt) {
		t.Fatal("exact readiness retry did not return the durable receipt", err)
	}
	changed := req
	changed.BackupID = "different-backup"
	if _, err := s.CheckUpdateReadiness(context.Background(), changed, now); err == nil {
		t.Fatal("readiness ID was reused for different evidence")
	}
	if receipts := s.UpdateReadinessReceipts(); len(receipts) != 1 || receipts[0].ID != req.ID {
		t.Fatalf("readiness inventory lost durable receipt: %+v", receipts)
	}
	info, err := os.Stat(updateReceiptPath(s, req.ID))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("readiness receipt is not a private regular file")
	}
	if err := os.WriteFile(filepath.Join(s.dir, "update-readiness", "broken.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	inventory := s.UpdateReadinessInventory()
	if len(inventory.Receipts) != 1 || inventory.Receipts[0].ID != req.ID || inventory.Problem == "" {
		t.Fatalf("readiness inventory did not preserve valid evidence and report corruption: %+v", inventory)
	}
}

func TestUpdateReadinessRecognizesExactCandidateAndApproval(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	s, release, currentDigest := installedFixture(t, now)
	if _, err := s.AdoptInstalledRelease(currentDigest, "linux-arm64", now); err != nil {
		t.Fatal(err)
	}
	next := release.Manifest
	next.ID = "next-security-fixture"
	next.Version = "1.0.2"
	next.Sequence = 3
	next.CompatibleFrom = []string{"1.0.1"}
	signed := signedFixtureManifest(t, next)
	registration, err := s.registration()
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(s.dir, "worker-bin", registration.BinarySHA256)
	staged, err := s.StageRelease(signed, "linux-arm64", artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	checks := []string{"pinned-networks-and-both-direction-transfer-records", "observation-produced-zero-signatures", "signature-exchange-refused", "duplicate-process-excluded", "network-mismatch-pauses-and-recovers", "crash-restart-checkpoints-and-records-retained", "graceful-stop", "only-read-rpc-methods"}
	candidate := CandidateResult{ReleaseDigest: staged.Digest, Platform: staged.Platform, ArtifactSHA256: staged.Artifact.SHA256, CheckerSHA256: strings.Repeat("1", 64), StartedAt: now.Add(-2 * time.Minute), FinishedAt: now.Add(-time.Minute), Report: CandidateReport{SchemaVersion: 2, Scope: "isolated-observation-transfer-v2", ArtifactSHA256: staged.Artifact.SHA256, State: "checks-passed", Checks: checks}, Isolation: "synthetic-unit-fixture", Notice: "Synthetic readiness fixture only."}
	raw, _ := json.Marshal(candidate)
	if err := atomicFile(filepath.Join(s.dir, "releases", staged.Digest, staged.Platform), "candidate-result.json", raw); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRelease(signed, mustReleaseTrust(t, s), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRelease(ApproveRelease{InstanceID: s.InstanceID(), ExpectedRevision: 0, Release: signed, Digest: verified.Digest, WindowStart: now, WindowEnd: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	receipt, err := s.CheckUpdateReadiness(context.Background(), UpdateReadinessRequest{ID: "candidate-approval", ExpectedRevision: 1, ReleaseDigest: staged.Digest, Platform: staged.Platform, ParticipationResponses: []SignedParticipationObservation{}}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"current-release", "staged-artifact", "compatibility", "candidate-test", "local-approval"} {
		if check, ok := readinessCheck(receipt, id); !ok || check.State != "passed" {
			t.Fatalf("exact %s gate did not pass: %+v", id, check)
		}
	}
	if check, _ := readinessCheck(receipt, "encrypted-backup"); check.State != "blocked" {
		t.Fatal("missing backup did not block the combined receipt")
	}
}

func mustReleaseTrust(t *testing.T, s *Store) ReleaseTrust {
	t.Helper()
	trust, err := s.ReleaseTrust()
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func TestUpdateReadinessRejectsStaleAuthorityAndUnknownInput(t *testing.T) {
	now := time.Now().UTC()
	s, _, digest := installedFixture(t, now)
	if _, err := s.AdoptInstalledRelease(digest, "linux-arm64", now); err != nil {
		t.Fatal(err)
	}
	for _, req := range []UpdateReadinessRequest{
		{ID: "../escape", ReleaseDigest: digest, Platform: "linux-arm64"},
		{ID: "valid-id", ReleaseDigest: strings.Repeat("g", 64), Platform: "linux-arm64"},
		{ID: "valid-id", ReleaseDigest: digest, Platform: "web"},
		{ID: "valid-id", ExpectedRevision: 1, ReleaseDigest: digest, Platform: "linux-arm64"},
	} {
		if _, err := s.CheckUpdateReadiness(context.Background(), req, now); err == nil {
			t.Fatalf("accepted invalid readiness request: %+v", req)
		}
	}
}

func TestConcurrentReadinessCannotReuseOneIDForDifferentEvidence(t *testing.T) {
	now := time.Now().UTC()
	s, _, digest := installedFixture(t, now)
	if _, err := s.AdoptInstalledRelease(digest, "linux-arm64", now); err != nil {
		t.Fatal(err)
	}
	requests := []UpdateReadinessRequest{
		{ID: "concurrent-readiness", ReleaseDigest: digest, Platform: "linux-arm64", BackupID: "backup-a", ParticipationResponses: []SignedParticipationObservation{}},
		{ID: "concurrent-readiness", ReleaseDigest: digest, Platform: "linux-arm64", BackupID: "backup-b", ParticipationResponses: []SignedParticipationObservation{}},
	}
	var wg sync.WaitGroup
	results := make(chan error, len(requests))
	for _, request := range requests {
		wg.Add(1)
		go func(req UpdateReadinessRequest) {
			defer wg.Done()
			_, err := s.CheckUpdateReadiness(context.Background(), req, now)
			results <- err
		}(request)
	}
	wg.Wait()
	close(results)
	successes, failures := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			failures++
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("concurrent conflicting readiness results: %d success, %d failure", successes, failures)
	}
}

func TestUpdateReadinessHTTPIsDurableAndNonAuthorizing(t *testing.T) {
	now := time.Now().UTC()
	s, _, digest := installedFixture(t, now)
	if _, err := s.AdoptInstalledRelease(digest, "linux-arm64", now); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	server := NewServer(s, token, "operator.test", nil)
	reqBody := UpdateReadinessRequest{ID: "http-readiness", ExpectedRevision: 0, ReleaseDigest: digest, Platform: "linux-arm64", ParticipationResponses: []SignedParticipationObservation{}}
	raw, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "http://operator.test/v1/updates/readiness", bytes.NewReader(raw))
	req.Host = "operator.test"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("readiness returned %d: %s", response.Code, response.Body.String())
	}
	var receipt UpdateReadinessReceipt
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil || receipt.ActivationReady {
		t.Fatal("HTTP readiness authorized activation", err)
	}
	get := httptest.NewRequest(http.MethodGet, "http://operator.test/v1/updates", nil)
	get.Host = "operator.test"
	get.Header.Set("Authorization", "Bearer "+token)
	listed := httptest.NewRecorder()
	server.ServeHTTP(listed, get)
	var body struct {
		InstallerEnabled bool                     `json:"installerEnabled"`
		Readiness        []UpdateReadinessReceipt `json:"readiness"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &body); err != nil || body.InstallerEnabled || len(body.Readiness) != 1 || body.Readiness[0].ID != receipt.ID || body.Readiness[0].ActivationReady {
		t.Fatalf("updates inventory hid or overstated readiness: %s", listed.Body.String())
	}
}
