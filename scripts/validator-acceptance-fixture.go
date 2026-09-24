//go:build ignore
// +build ignore

// Creates a short-lived, synthetic validator release for an exact host bundle.
// The publisher private key is discarded. The output never authorizes signing.
package main

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func writeFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(data, '\n'), 0600)
}

func bundleMembers(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	want := map[string]bool{"koinos-bridge-validator": true, "vortex-candidate-check": true}
	out := map[string][]byte{}
	r := tar.NewReader(f)
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if !want[h.Name] {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > 128<<20 || out[h.Name] != nil {
			return nil, errors.New("invalid or duplicate executable in bundle")
		}
		data, err := io.ReadAll(io.LimitReader(r, h.Size+1))
		if err != nil || int64(len(data)) != h.Size {
			return nil, errors.New("incomplete executable in bundle")
		}
		out[h.Name] = data
	}
	if len(out) != len(want) {
		return nil, errors.New("bundle lacks validator or candidate checker")
	}
	return out, nil
}

func run() error {
	bundle := flag.String("bundle", "", "absolute verified Linux AMD64 host bundle")
	out := flag.String("out", "", "new private output directory")
	sourceCommit := flag.String("source-commit", "", "source revision of the exact bundle")
	flag.Parse()
	if !filepath.IsAbs(*bundle) || !filepath.IsAbs(*out) || !commitPattern.MatchString(*sourceCommit) {
		return errors.New("absolute bundle/output paths and 40-character source commit required")
	}
	info, err := os.Lstat(*bundle)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 256<<20 {
		return errors.New("bundle must be a bounded regular file")
	}
	members, err := bundleMembers(*bundle)
	if err != nil {
		return err
	}
	validatorHash := sha256.Sum256(members["koinos-bridge-validator"])
	checkerHash := sha256.Sum256(members["vortex-candidate-check"])
	now := time.Now().UTC().Truncate(time.Second)
	manifest := operator.ReleaseManifest{
		SchemaVersion:  1,
		ID:             "synthetic-validator-acceptance",
		Component:      "validator",
		Version:        "0.3.0",
		Sequence:       1,
		Channel:        "candidate",
		SourceCommit:   *sourceCommit,
		CreatedAt:      now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:      now.Add(4 * time.Hour).Format(time.RFC3339),
		CompatibleFrom: []string{"0.3.0"},
		ConfigSchema:   1,
		DatabaseSchema: 1,
		SigningCodec:   "observation-v1",
		Recovery:       "Disposable candidate qualification only; never activate a public signer",
		TestEvidence:   []string{"Actual isolated candidate runner still required before local approval"},
		Artifacts:      []operator.ReleaseArtifact{{Platform: "linux-amd64", SHA256: hex.EncodeToString(validatorHash[:]), Size: uint64(len(members["koinos-bridge-validator"]))}},
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()
	canonical, err := operator.CanonicalRelease(manifest)
	if err != nil {
		return err
	}
	release := operator.SignedRelease{Manifest: manifest, Signatures: []operator.ReleaseSignature{{Publisher: "synthetic-validator-only", Signature: hex.EncodeToString(ed25519.Sign(priv, canonical))}}}
	trust := operator.ReleaseTrust{SchemaVersion: 1, RequiredSignatures: 1, Publishers: map[string]string{"synthetic-validator-only": hex.EncodeToString(pub)}}
	verified, err := operator.VerifyRelease(release, trust, now)
	if err != nil {
		return err
	}
	if err = os.Mkdir(*out, 0700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"validator.bin": members["koinos-bridge-validator"], "candidate-checker": members["vortex-candidate-check"]} {
		if err = writeFile(filepath.Join(*out, name), data, 0700); err != nil {
			return err
		}
	}
	if err = writeJSON(filepath.Join(*out, "validator-release.json"), release); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(*out, "validator-trust.json"), trust); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"releaseDigest": verified.Digest, "validatorSha256": hex.EncodeToString(validatorHash[:]), "checkerSha256": hex.EncodeToString(checkerHash[:]), "notice": "synthetic validator candidate release only; private publisher key discarded"})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
