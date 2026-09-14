//go:build ignore
// +build ignore

// Creates and executes a disposable signed candidate-release fixture against
// the local restricted Docker runner. It never persists the synthetic release
// signing key and never uses production configuration, RPCs or validator keys.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
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

func regularArtifact(path string) ([]byte, string) {
	info, err := os.Lstat(path)
	must(err)
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 {
		panic("fixture artifact must be a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	must(err)
	hash := sha256.Sum256(raw)
	return raw, hex.EncodeToString(hash[:])
}

func save(path string, value interface{}) {
	raw, err := json.MarshalIndent(value, "", "  ")
	must(err)
	must(os.WriteFile(path, raw, 0600))
}

func command(path string, args ...string) []byte {
	cmd := exec.Command(path, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("fixture command failed: %w: %s", err, strings.TrimSpace(string(output))))
	}
	return output
}

func main() {
	operatorPath := flag.String("operator", "", "absolute host vortex-operator executable")
	validatorPath := flag.String("validator", "", "absolute linux-arm64 validator candidate")
	checkerPath := flag.String("checker", "", "absolute linux-arm64 reviewed candidate checker")
	flag.Parse()
	for name, value := range map[string]string{"operator": *operatorPath, "validator": *validatorPath, "checker": *checkerPath} {
		if !filepath.IsAbs(value) {
			panic(errors.New(name + " path must be absolute"))
		}
	}
	validator, validatorHash := regularArtifact(*validatorPath)
	_, checkerHash := regularArtifact(*checkerPath)
	base, err := os.MkdirTemp("", "vortex-candidate-v2.")
	must(err)
	now := time.Now().UTC().Truncate(time.Second)
	manifest := operator.ReleaseManifest{
		SchemaVersion: 1,
		ID:            "synthetic-candidate-v2",
		Component:     "validator",
		Version:       "0.0.0-candidate-v2",
		Sequence:      1,
		Channel:       "candidate",
		SourceCommit:  strings.Repeat("a", 40),
		CreatedAt:     now.Format(time.RFC3339),
		ExpiresAt:     now.Add(2 * time.Hour).Format(time.RFC3339),
		CompatibleFrom: []string{
			"0.0.0-synthetic",
		},
		ConfigSchema:      1,
		DatabaseSchema:    1,
		SigningCodec:      "synthetic-candidate-v2",
		MixedVersionsSafe: false,
		Recovery:          "Disposable isolated fixture; no installation is performed",
		TestEvidence:      []string{"local restricted observation-transfer fixture"},
		Artifacts: []operator.ReleaseArtifact{{
			Platform: "linux-arm64",
			SHA256:   validatorHash,
			Size:     uint64(len(validator)),
		}},
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	canonical, err := operator.CanonicalRelease(manifest)
	must(err)
	release := operator.SignedRelease{Manifest: manifest, Signatures: []operator.ReleaseSignature{{Publisher: "synthetic-local", Signature: hex.EncodeToString(ed25519.Sign(private, canonical))}}}
	trust := operator.ReleaseTrust{SchemaVersion: 1, RequiredSignatures: 1, Publishers: map[string]string{"synthetic-local": hex.EncodeToString(public)}}
	releasePath := filepath.Join(base, "release.json")
	save(filepath.Join(base, "release-trust.json"), trust)
	save(releasePath, release)
	stageOutput := command(*operatorPath, "--data", base, "--release-file", releasePath, "--artifact-file", *validatorPath, "--artifact-platform", "linux-arm64", "release-stage")
	var staged struct {
		Digest         string `json:"digest"`
		ArtifactSHA256 string `json:"artifactSha256"`
		State          string `json:"state"`
		Installed      bool   `json:"installed"`
	}
	must(json.Unmarshal(stageOutput, &staged))
	if staged.Digest == "" || staged.ArtifactSHA256 != validatorHash || staged.State != "artifact-verified" || staged.Installed {
		panic("unexpected release staging result")
	}
	resultOutput := command(*operatorPath, "--data", base, "--release-digest", staged.Digest, "--artifact-platform", "linux-arm64", "--candidate-checker", *checkerPath, "--checker-sha256", checkerHash, "candidate-test")
	var result operator.CandidateResult
	must(json.Unmarshal(resultOutput, &result))
	if result.ReleaseDigest != staged.Digest || result.ArtifactSHA256 != validatorHash || result.CheckerSHA256 != checkerHash || result.Report.SchemaVersion != 2 || result.Report.Scope != "isolated-observation-transfer-v2" || result.Report.State != "checks-passed" || len(result.Report.Checks) != 8 {
		panic("unexpected candidate qualification result")
	}
	summary := struct {
		BaseDir         string                   `json:"baseDir"`
		ReleaseDigest   string                   `json:"releaseDigest"`
		ArtifactSHA256  string                   `json:"artifactSha256"`
		CheckerSHA256   string                   `json:"checkerSha256"`
		CandidateReport operator.CandidateReport `json:"candidateReport"`
		Isolation       string                   `json:"isolation"`
		Notice          string                   `json:"notice"`
		Installed       bool                     `json:"installed"`
	}{base, staged.Digest, validatorHash, checkerHash, result.Report, result.Isolation, result.Notice, false}
	must(json.NewEncoder(os.Stdout).Encode(summary))
}
