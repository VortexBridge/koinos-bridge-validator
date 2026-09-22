// Package host installs authenticated bundles without granting signing authority.
package host

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

const MaxBundle = 256 << 20

var Files = []string{"koinos-bridge-validator", "vortex-operator", "vortex-keys", "vortex-candidate-check", "vortex-host", "vortex-operator.service"}

type Installation struct {
	Schema         int               `json:"schema"`
	Instance       string            `json:"instance"`
	Digest         string            `json:"releaseDigest"`
	Artifact       string            `json:"artifactSha256"`
	Version        string            `json:"version"`
	Sequence       uint64            `json:"sequence"`
	ConfigSchema   uint32            `json:"configSchema"`
	DatabaseSchema uint32            `json:"databaseSchema"`
	Codec          string            `json:"codec"`
	Platform       string            `json:"platform"`
	Files          map[string]string `json:"files"`
	Enabled        bool              `json:"enabled"`
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func JSON(raw []byte, v interface{}) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("invalid structured input")
	}
	if d.Decode(new(interface{})) != io.EOF {
		return errors.New("trailing structured input")
	}
	return nil
}
func Atomic(dir, name string, value interface{}) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func Read(root string) (Installation, error) {
	var i Installation
	b, err := worker.ReadPrivateFile(filepath.Join(root, "installation.json"), 32768)
	if err != nil {
		return i, err
	}
	err = JSON(b, &i)
	if err != nil || i.Schema != 1 || len(i.Files) != len(Files) || len(i.Artifact) != 64 || i.Instance == "" {
		return i, errors.New("invalid installation record")
	}
	if _, err = hex.DecodeString(i.Artifact); err != nil {
		return i, errors.New("invalid artifact identity")
	}
	return i, nil
}
func Verify(root string, i Installation) error {
	for _, dir := range []string{root, filepath.Join(root, "releases"), filepath.Join(root, "releases", i.Artifact)} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return errors.New("installed directories must be private and not symlinks")
		}
	}
	if i.Platform != "linux-"+runtime.GOARCH {
		return errors.New("bundle architecture differs from host")
	}
	for _, name := range Files {
		want, ok := i.Files[name]
		if !ok {
			return errors.New("incomplete bundle")
		}
		b, err := worker.ReadPrivateFile(filepath.Join(root, "releases", i.Artifact, name), MaxBundle)
		if err != nil || hash(b) != want {
			return errors.New("installed artifact is missing, unsafe or changed")
		}
	}
	return nil
}

// Install checks the signed archive, independent local approval and predecessor.
// Callers must hold host.lock; Run holds that same lock for the child lifetime.
func Install(root, instance string, archive []byte, signed operator.SignedRelease, trust operator.ReleaseTrust, approval operator.ReleaseApproval, now time.Time) (Installation, error) {
	var empty Installation
	if !filepath.IsAbs(root) || instance == "" || len(instance) > 128 {
		return empty, errors.New("absolute private root and instance required")
	}
	v, err := operator.VerifyRelease(signed, trust, now)
	if err != nil {
		return empty, err
	}
	if v.Manifest.Component != "operator" {
		return empty, errors.New("host bundle requires an operator-component release; worker binaries use separate validator releases")
	}
	if err = operator.CheckActivation(approval, v, instance, now); err != nil {
		return empty, err
	}
	platform := "linux-" + runtime.GOARCH
	artifact := hash(archive)
	matched := false
	for _, a := range v.Manifest.Artifacts {
		if a.Platform == platform && a.SHA256 == artifact && a.Size == uint64(len(archive)) {
			matched = true
		}
	}
	if !matched || len(archive) > MaxBundle {
		return empty, errors.New("bundle bytes do not match approved platform artifact")
	}
	if err = worker.PrivateDir(root); err != nil {
		return empty, err
	}
	old, oldErr := Read(root)
	if _, e := os.Lstat(filepath.Join(root, "installation.json")); !os.IsNotExist(e) && oldErr != nil {
		return empty, errors.New("existing installation record cannot be verified")
	}
	if oldErr == nil {
		if old.Instance != instance {
			return empty, errors.New("installation belongs to another instance")
		}
		if old.Artifact == artifact && old.Digest == v.Digest {
			if err = Verify(root, old); err != nil {
				return empty, err
			}
			old.Enabled = true
			return old, Atomic(root, "installation.json", old)
		}
		compatible := false
		for _, previous := range v.Manifest.CompatibleFrom {
			if previous == old.Version {
				compatible = true
			}
		}
		if v.Manifest.Sequence <= old.Sequence || !compatible || v.Manifest.ConfigSchema != old.ConfigSchema || v.Manifest.DatabaseSchema != old.DatabaseSchema || v.Manifest.SigningCodec != old.Codec {
			return empty, errors.New("downgrade or migration requires separate reviewed recovery")
		}
	}
	releases := filepath.Join(root, "releases")
	if err = worker.PrivateDir(releases); err != nil {
		return empty, err
	}
	stage, err := os.MkdirTemp(releases, ".stage-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(stage)
	allowed := map[string]bool{}
	for _, name := range Files {
		allowed[name] = true
	}
	hashes := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(archive))
	var total int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return empty, errors.New("invalid bundle archive")
		}
		if !allowed[h.Name] || hashes[h.Name] != "" || h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > MaxBundle {
			return empty, errors.New("unexpected, duplicate, linked or oversized bundle entry")
		}
		total += h.Size
		if total > MaxBundle {
			return empty, errors.New("expanded bundle too large")
		}
		b, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil || int64(len(b)) != h.Size {
			return empty, errors.New("truncated bundle")
		}
		mode := os.FileMode(0700)
		if h.Name == "vortex-operator.service" {
			mode = 0600
		}
		f, e := os.OpenFile(filepath.Join(stage, h.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if e != nil {
			return empty, e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return empty, e
		}
		if closeErr != nil {
			return empty, closeErr
		}
		hashes[h.Name] = hash(b)
	}
	if len(hashes) != len(Files) {
		return empty, errors.New("bundle is incomplete")
	}
	next := Installation{1, instance, v.Digest, artifact, v.Manifest.Version, v.Manifest.Sequence, v.Manifest.ConfigSchema, v.Manifest.DatabaseSchema, v.Manifest.SigningCodec, platform, hashes, true}
	dest := filepath.Join(releases, artifact)
	if _, e := os.Lstat(dest); os.IsNotExist(e) {
		if err = os.Rename(stage, dest); err != nil {
			return empty, err
		}
	} else if e != nil {
		return empty, e
	}
	if err = Verify(root, next); err != nil {
		return empty, err
	}
	if err = worker.PrivateDir(filepath.Join(root, "state")); err != nil {
		return empty, err
	}
	// Persist the release-directory rename before publishing the active pointer.
	rd, e := os.Open(releases)
	if e != nil {
		return empty, e
	}
	e = rd.Sync()
	rd.Close()
	if e != nil {
		return empty, e
	}
	if err = Atomic(root, "installation.json", next); err != nil {
		return empty, err
	}
	return next, nil
}

// Uninstall disables future starts; state, vaults, journals and releases stay intact.
func Uninstall(root string) error {
	i, err := Read(root)
	if err != nil {
		return err
	}
	i.Enabled = false
	return Atomic(root, "installation.json", i)
}
