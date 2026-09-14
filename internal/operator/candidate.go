package operator

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CandidateReport struct {
	SchemaVersion  int      `json:"schemaVersion"`
	Scope          string   `json:"scope"`
	ArtifactSHA256 string   `json:"artifactSha256"`
	State          string   `json:"state"`
	Checks         []string `json:"checks"`
	Error          string   `json:"error,omitempty"`
}
type CandidateResult struct {
	ReleaseDigest  string          `json:"releaseDigest"`
	Platform       string          `json:"platform"`
	ArtifactSHA256 string          `json:"artifactSha256"`
	CheckerSHA256  string          `json:"checkerSha256"`
	StartedAt      time.Time       `json:"startedAt"`
	FinishedAt     time.Time       `json:"finishedAt"`
	Report         CandidateReport `json:"report"`
	Isolation      string          `json:"isolation"`
	Notice         string          `json:"notice"`
}
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	space := b.limit - b.Len()
	if space > 0 {
		if len(p) > space {
			p = p[:space]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}
func dockerOutput(ctx context.Context, host string, input io.Reader, args ...string) ([]byte, error) {
	if host != "" {
		args = append([]string{"--host", host}, args...)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = input
	out := &limitedBuffer{limit: 65536}
	stderr := &limitedBuffer{limit: 8192}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), errors.New("local Docker operation failed; inspect local engine availability and candidate compatibility")
	}
	return out.Bytes(), nil
}
func containerArgs(name, imageID string) []string {
	return []string{"create", "--name", name, "--label", "vortex.local-candidate=true", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "64", "--memory", "768m", "--memory-swap", "768m", "--cpus", "2", "--user", "65532:65532", "--init", "--pull", "never", "--tmpfs", "/work:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=65532,gid=65532", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777", "--env", "VORTEX_CANDIDATE_SANDBOX=1", "--entrypoint", "/candidate/checker", imageID}
}
func verifyContainerIsolation(raw []byte) error {
	var rows []struct {
		Config struct {
			User       string
			Env        []string
			Entrypoint []string
		}
		HostConfig struct {
			NetworkMode    string
			ReadonlyRootfs bool
			Privileged     bool
			CapDrop        []string
			CapAdd         []string
			SecurityOpt    []string
			Binds          []string
			VolumesFrom    []string
			PidsLimit      int64
			Memory         int64
			Tmpfs          map[string]string
		}
		Mounts []struct{ Type string }
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
		return errors.New("cannot verify candidate container isolation")
	}
	r := rows[0]
	h := r.HostConfig
	if r.Config.User != "65532:65532" || h.NetworkMode != "none" || !h.ReadonlyRootfs || h.Privileged || len(h.CapAdd) != 0 || len(h.CapDrop) != 1 || strings.ToUpper(h.CapDrop[0]) != "ALL" || len(h.SecurityOpt) != 1 || h.SecurityOpt[0] != "no-new-privileges:true" || len(h.Binds) != 0 || len(h.VolumesFrom) != 0 || h.PidsLimit != 64 || h.Memory != 768*1024*1024 || len(h.Tmpfs) != 2 || h.Tmpfs["/work"] == "" || h.Tmpfs["/tmp"] == "" {
		return errors.New("candidate container isolation differs from required policy")
	}
	for _, m := range r.Mounts {
		if m.Type != "tmpfs" {
			return errors.New("candidate container unexpectedly mounts host data")
		}
	}
	if len(r.Config.Entrypoint) != 1 || r.Config.Entrypoint[0] != "/candidate/checker" {
		return errors.New("candidate container entrypoint mismatch")
	}
	return nil
}

// TestCandidate never executes the artifact on the host. The only build context
// consists of a fixed scratch Dockerfile, the verified artifact and a locally
// reviewed checker. There are no Docker RUN commands or host-directory mounts.
func (s *Store) TestCandidate(ctx context.Context, digest, platform, checkerPath, checkerHash string) (CandidateResult, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	result := CandidateResult{ReleaseDigest: digest, Platform: platform, CheckerSHA256: checkerHash, StartedAt: time.Now().UTC(), Isolation: "local-docker-network-none-readonly-no-host-mounts-uid65532", Notice: "Isolated observation-transfer evidence only. Signing, contract execution, mixed-version compatibility, migration, independent-host approval and rollout preflight are still required."}
	record, err := s.loadStaged(digest, platform, time.Now().UTC())
	if err != nil {
		return result, err
	}
	if record.Release.Manifest.Component != "validator" || !(platform == "linux-arm64" || platform == "linux-amd64") {
		return result, errors.New("candidate smoke runner requires a staged Linux validator binary")
	}
	result.ArtifactSHA256 = record.Artifact.SHA256
	if !hexHash.MatchString(checkerHash) {
		return result, errors.New("reviewed checker SHA-256 required")
	}
	checker, err := OpenBoundedArtifact(checkerPath, maxStagedArtifact)
	if err != nil {
		return result, err
	}
	defer checker.Close()
	checkerBytes, err := io.ReadAll(io.LimitReader(checker, maxStagedArtifact+1))
	if err != nil || len(checkerBytes) > maxStagedArtifact {
		return result, errors.New("checker unreadable or oversized")
	}
	hash := sha256.Sum256(checkerBytes)
	if hex.EncodeToString(hash[:]) != checkerHash {
		return result, errors.New("checker digest differs from local review")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	hostRaw, err := dockerOutput(ctx, "", nil, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	if err != nil {
		return result, err
	}
	host := strings.TrimSpace(string(hostRaw))
	if !strings.HasPrefix(host, "unix:///") || strings.ContainsAny(host, "\r\n") {
		return result, errors.New("candidate execution requires a local Unix-socket Docker engine")
	}
	archRaw, err := dockerOutput(ctx, host, nil, "version", "--format", "{{.Server.Os}}-{{.Server.Arch}}")
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(string(archRaw)) != platform {
		return result, errors.New("staged platform must match local Docker engine; emulated tests are not accepted")
	}
	contextFile, err := os.CreateTemp(s.dir, ".candidate-context-")
	if err != nil {
		return result, err
	}
	defer os.Remove(contextFile.Name())
	defer contextFile.Close()
	tw := tar.NewWriter(contextFile)
	add := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0555, Size: int64(len(b))}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	dockerfile := []byte("FROM scratch\nCOPY --chmod=0555 validator /candidate/validator\nCOPY --chmod=0555 checker /candidate/checker\n")
	if err := add("Dockerfile", dockerfile); err != nil {
		return result, err
	}
	if err := add("checker", checkerBytes); err != nil {
		return result, err
	}
	artifact, err := OpenBoundedArtifact(filepath.Join(s.dir, "releases", digest, platform, "artifact"), maxStagedArtifact)
	if err != nil {
		return result, err
	}
	// Rehash the same bytes that enter Docker, closing the staging/copy race.
	if err := tw.WriteHeader(&tar.Header{Name: "validator", Mode: 0555, Size: int64(record.Artifact.Size)}); err != nil {
		artifact.Close()
		return result, err
	}
	ah := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, ah), io.LimitReader(artifact, int64(record.Artifact.Size)+1))
	artifact.Close()
	if err != nil || uint64(n) != record.Artifact.Size || hex.EncodeToString(ah.Sum(nil)) != record.Artifact.SHA256 {
		return result, errors.New("candidate artifact changed while preparing sandbox")
	}
	if err := tw.Close(); err != nil {
		return result, err
	}
	if _, err := contextFile.Seek(0, 0); err != nil {
		return result, err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return result, err
	}
	name := "vortex-candidate-" + hex.EncodeToString(random)
	tag := "vortex-local-candidate:" + hex.EncodeToString(random)
	// Remove only this invocation's uniquely named resources, even after failure.
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		dockerOutput(clean, host, nil, "rm", "-f", name)
		dockerOutput(clean, host, nil, "image", "rm", tag)
	}()
	if _, err := dockerOutput(ctx, host, contextFile, "build", "--network=none", "--pull=false", "--platform", strings.ReplaceAll(platform, "-", "/"), "--tag", tag, "-"); err != nil {
		return result, err
	}
	imageID, err := dockerOutput(ctx, host, nil, "image", "inspect", "--format", "{{.Id}}", tag)
	if err != nil {
		return result, err
	}
	image := strings.TrimSpace(string(imageID))
	if !strings.HasPrefix(image, "sha256:") || !hexHash.MatchString(strings.TrimPrefix(image, "sha256:")) {
		return result, errors.New("invalid local candidate image identity")
	}
	if _, err := dockerOutput(ctx, host, nil, containerArgs(name, image)...); err != nil {
		return result, err
	}
	inspection, err := dockerOutput(ctx, host, nil, "inspect", name)
	if err != nil {
		return result, err
	}
	if err := verifyContainerIsolation(inspection); err != nil {
		return result, err
	}
	output, runErr := dockerOutput(ctx, host, nil, "start", "--attach", name)
	result.FinishedAt = time.Now().UTC()
	if strictJSON(output, &result.Report) != nil {
		result.Report = CandidateReport{SchemaVersion: 2, State: "failed", Scope: "isolated-observation-transfer-v2", ArtifactSHA256: record.Artifact.SHA256, Checks: []string{}, Error: "Candidate checker did not return a valid bounded report"}
	}
	if runErr != nil || validateCandidateReport(result.Report, record.Artifact.SHA256) != nil {
		result.Report.State = "failed"
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return result, err
	}
	reportDir := filepath.Join(s.dir, "releases", digest, platform)
	reportHash := sha256.Sum256(encoded)
	historyDir := filepath.Join(reportDir, "candidate-history")
	if err := os.MkdirAll(historyDir, 0700); err != nil {
		return result, errors.New("cannot preserve candidate history")
	}
	if err := atomicFile(historyDir, hex.EncodeToString(reportHash[:])+".json", encoded); err != nil {
		return result, errors.New("cannot preserve candidate history")
	}
	if err := atomicFile(reportDir, "candidate-result.json", encoded); err != nil {
		return result, errors.New("cannot persist candidate report")
	}
	if result.Report.State != "checks-passed" {
		return result, fmt.Errorf("candidate observation-transfer checks failed: %s", result.Report.Error)
	}
	return result, nil
}

func validateCandidateReport(report CandidateReport, artifact string) error {
	expected := []string{"pinned-networks-and-both-direction-transfer-records", "observation-produced-zero-signatures", "signature-exchange-refused", "duplicate-process-excluded", "network-mismatch-pauses-and-recovers", "crash-restart-checkpoints-and-records-retained", "graceful-stop", "only-read-rpc-methods"}
	if report.SchemaVersion != 2 || report.Scope != "isolated-observation-transfer-v2" || report.ArtifactSHA256 != artifact || report.State != "checks-passed" || report.Error != "" || len(report.Checks) != len(expected) {
		return errors.New("invalid candidate observation-transfer report")
	}
	for i, check := range expected {
		if report.Checks[i] != check {
			return errors.New("candidate report omits required observation-transfer check")
		}
	}
	return nil
}

// Historical v1 reports remain readable in local history, but TestCandidate
// accepts only the stronger v2 report for a new execution.
func validateStoredCandidateReport(report CandidateReport, artifact string) error {
	if validateCandidateReport(report, artifact) == nil {
		return nil
	}
	expected := []string{"keyless-start-and-both-chain-observation", "signature-exchange-refused", "duplicate-process-excluded", "crash-restart-checkpoint-retained", "graceful-stop", "only-read-rpc-methods"}
	if report.SchemaVersion != 1 || report.Scope != "isolated-observation-smoke-v1" || report.ArtifactSHA256 != artifact || report.State != "smoke-passed" || report.Error != "" || len(report.Checks) != len(expected) {
		return errors.New("invalid stored candidate report")
	}
	for i, check := range expected {
		if report.Checks[i] != check {
			return errors.New("stored candidate report omits required historical check")
		}
	}
	return nil
}
func (s *Store) candidateResult(digest, platform, artifact string) *CandidateResult {
	file, err := OpenBoundedArtifact(filepath.Join(s.dir, "releases", digest, platform, "candidate-result.json"), 32768)
	if err != nil {
		return nil
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 32769))
	if err != nil || len(raw) > 32768 {
		return nil
	}
	var result CandidateResult
	if strictJSON(raw, &result) != nil || result.ReleaseDigest != digest || result.Platform != platform || result.ArtifactSHA256 != artifact || !hexHash.MatchString(result.CheckerSHA256) || result.FinishedAt.Before(result.StartedAt) {
		return nil
	}
	if validateStoredCandidateReport(result.Report, artifact) != nil {
		result.Report.State = "failed"
	}
	return &result
}
