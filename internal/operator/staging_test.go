package operator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStagingIsImmutableAndRechecksCurrentTrust(t *testing.T) {
	now := time.Now().UTC()
	release, trust := fixtureRelease(t, now)
	dir := privateDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	policy, _ := json.Marshal(trust)
	os.WriteFile(filepath.Join(dir, "release-trust.json"), policy, 0600)
	source := filepath.Join(t.TempDir(), "artifact")
	os.WriteFile(source, []byte("tampered artifact"), 0600)
	if _, err := s.StageRelease(release, "linux-arm64", source, now); err == nil {
		t.Fatal("tampered artifact staged")
	}
	os.WriteFile(source, []byte("synthetic artifact, not executable"), 0600)
	record, err := s.StageRelease(release, "linux-arm64", source, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ReleaseApprovals()) != 0 {
		t.Fatal("staging implicitly approved activation")
	}
	again, err := s.StageRelease(release, "linux-arm64", source, now.Add(time.Second))
	if err != nil || !again.StagedAt.Equal(record.StagedAt) {
		t.Fatal("repeat staging rewrote immutable metadata")
	}
	if _, err := s.loadStaged(record.Digest, "linux-arm64", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadStaged("../escape", "linux-arm64", now); err == nil {
		t.Fatal("staging path traversal allowed")
	}
	staged := filepath.Join(dir, "releases", record.Digest, "linux-arm64", "artifact")
	os.Chmod(staged, 0600)
	os.WriteFile(staged, []byte("changed bytes"), 0600)
	if _, err := s.loadStaged(record.Digest, "linux-arm64", now); err == nil {
		t.Fatal("modified staged bytes accepted")
	}
	os.WriteFile(staged, []byte("synthetic artifact, not executable"), 0400)
	trust.Publishers["a"] = strings.Repeat("0", 64)
	changed, _ := json.Marshal(trust)
	os.WriteFile(filepath.Join(dir, "release-trust.json"), changed, 0600)
	if _, err := s.loadStaged(record.Digest, "linux-arm64", now); err == nil {
		t.Fatal("stale publisher trust accepted")
	}
	if summaries := s.StagedReleases(now); len(summaries) != 1 || summaries[0].State != "blocked" {
		t.Fatal("invalid publisher policy hidden in summary")
	}
}
func TestCandidateIsolationPolicyRejectsHostAccess(t *testing.T) {
	valid := map[string]interface{}{"Config": map[string]interface{}{"User": "65532:65532", "Entrypoint": []string{"/candidate/checker"}}, "HostConfig": map[string]interface{}{"NetworkMode": "none", "ReadonlyRootfs": true, "Privileged": false, "CapDrop": []string{"ALL"}, "CapAdd": []string{}, "SecurityOpt": []string{"no-new-privileges:true"}, "Binds": []string{}, "VolumesFrom": []string{}, "PidsLimit": 64, "Memory": 768 * 1024 * 1024, "Tmpfs": map[string]string{"/work": "restricted", "/tmp": "restricted"}}, "Mounts": []interface{}{}}
	encode := func(v map[string]interface{}) []byte { b, _ := json.Marshal([]interface{}{v}); return b }
	if err := verifyContainerIsolation(encode(valid)); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]interface{}){
		func(v map[string]interface{}) { v["HostConfig"].(map[string]interface{})["NetworkMode"] = "host" },
		func(v map[string]interface{}) { v["HostConfig"].(map[string]interface{})["Privileged"] = true },
		func(v map[string]interface{}) {
			v["HostConfig"].(map[string]interface{})["Binds"] = []string{"/private:/host"}
		},
		func(v map[string]interface{}) {
			v["HostConfig"].(map[string]interface{})["CapAdd"] = []string{"SYS_ADMIN"}
		},
		func(v map[string]interface{}) { v["Config"].(map[string]interface{})["User"] = "0" },
		func(v map[string]interface{}) { v["Mounts"] = []interface{}{map[string]string{"Type": "bind"}} },
	} {
		var copy map[string]interface{}
		b, _ := json.Marshal(valid)
		json.Unmarshal(b, &copy)
		change(copy)
		if verifyContainerIsolation(encode(copy)) == nil {
			t.Fatal("unsafe candidate environment accepted")
		}
	}
}

func TestCandidateReportRequiresEveryNamedCheck(t *testing.T) {
	report := CandidateReport{SchemaVersion: 2, Scope: "isolated-observation-transfer-v2", ArtifactSHA256: strings.Repeat("1", 64), State: "checks-passed", Checks: []string{"pinned-networks-and-both-direction-transfer-records", "observation-produced-zero-signatures", "signature-exchange-refused", "duplicate-process-excluded", "network-mismatch-pauses-and-recovers", "crash-restart-checkpoints-and-records-retained", "graceful-stop", "only-read-rpc-methods"}}
	if err := validateCandidateReport(report, report.ArtifactSHA256); err != nil {
		t.Fatal(err)
	}
	report.Checks[7] = "unchecked"
	if validateCandidateReport(report, report.ArtifactSHA256) == nil {
		t.Fatal("unnamed or omitted check accepted")
	}
	legacy := CandidateReport{SchemaVersion: 1, Scope: "isolated-observation-smoke-v1", ArtifactSHA256: report.ArtifactSHA256, State: "smoke-passed", Checks: []string{"keyless-start-and-both-chain-observation", "signature-exchange-refused", "duplicate-process-excluded", "crash-restart-checkpoint-retained", "graceful-stop", "only-read-rpc-methods"}}
	if validateStoredCandidateReport(legacy, legacy.ArtifactSHA256) != nil {
		t.Fatal("valid historical report became unreadable")
	}
	if validateCandidateReport(legacy, legacy.ArtifactSHA256) == nil {
		t.Fatal("historical smoke report accepted for a new candidate run")
	}
}
