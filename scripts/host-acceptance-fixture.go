//go:build ignore
// +build ignore

// Generates disposable, locally approved operator-bundle inputs for isolated
// host acceptance. Its publisher key is never stored; never use these files as
// production trust, release approval, or validator signing authorization.
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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func run() error {
	bundlePath := flag.String("bundle", "", "absolute path to the exact Linux bundle")
	out := flag.String("out", "", "new private output directory")
	instance := flag.String("instance", "", "synthetic instance name")
	commit := flag.String("source-commit", "", "reviewed 40-character source commit")
	sequence := flag.Uint64("sequence", 1, "synthetic release sequence; increment for an upgrade")
	flag.Parse()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errors.New("unsupported fixture platform")
	}
	if !filepath.IsAbs(*bundlePath) || !filepath.IsAbs(*out) || !strings.HasPrefix(*instance, "synthetic-") || *sequence == 0 {
		return errors.New("absolute bundle/output paths, synthetic- instance and positive sequence required")
	}
	info, err := os.Lstat(*bundlePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 256<<20 {
		return errors.New("bundle must be a bounded regular file")
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(bundle)
	now := time.Now().UTC().Truncate(time.Second)
	m := operator.ReleaseManifest{
		SchemaVersion: 1,
		ID:            "synthetic-host-acceptance",
		Component:     "operator",
		Version:       "0.3.0",
		Sequence:      *sequence,
		Channel:       "candidate",
		SourceCommit:  *commit,
		CreatedAt:     now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:     now.Add(4 * time.Hour).Format(time.RFC3339),
		CompatibleFrom: []string{
			"0.3.0",
		},
		ConfigSchema:   1,
		DatabaseSchema: 1,
		SigningCodec:   "observation-v1",
		Recovery:       "Disposable host acceptance only; preserve state and never enable public signing",
		TestEvidence:   []string{"repeated clean-source bundle build and isolated host CLI test"},
		Artifacts: []operator.ReleaseArtifact{{
			Platform: "linux-amd64",
			SHA256:   hex.EncodeToString(hash[:]),
			Size:     uint64(len(bundle)),
		}},
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(priv)
	canonical, err := operator.CanonicalRelease(m)
	if err != nil {
		return err
	}
	release := operator.SignedRelease{Manifest: m, Signatures: []operator.ReleaseSignature{{
		Publisher: "synthetic-host-only",
		Signature: hex.EncodeToString(ed25519.Sign(priv, canonical)),
	}}}
	trust := operator.ReleaseTrust{SchemaVersion: 1, RequiredSignatures: 1, Publishers: map[string]string{
		"synthetic-host-only": hex.EncodeToString(pub),
	}}
	verified, err := operator.VerifyRelease(release, trust, now)
	if err != nil {
		return err
	}
	approval := operator.ReleaseApproval{
		InstanceID: *instance,
		Digest:     verified.Digest, Component: "operator", Version: m.Version, Sequence: m.Sequence,
		WindowStart: now.Add(-time.Minute), WindowEnd: now.Add(2 * time.Hour), ApprovedAt: now,
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		return err
	}
	for name, value := range map[string]any{"release.json": release, "trust.json": trust, "approval.json": approval} {
		if err := writeJSON(filepath.Join(*out, name), value); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(filepath.Join(*out, "bundle.tar"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(bundle); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"instance": *instance, "artifactSha256": m.Artifacts[0].SHA256,
		"releaseDigest": verified.Digest, "sequence": m.Sequence, "approvalExpiresAt": approval.WindowEnd,
		"notice": "synthetic host acceptance only; no production publisher or signer key",
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
