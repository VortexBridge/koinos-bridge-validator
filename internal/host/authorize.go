package host

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// Authorize re-verifies installation against independent publisher trust and
// live local approval. It does not itself authorize a chain signature.
func Authorize(root string, trust operator.ReleaseTrust, instance string, now time.Time) (Installation, error) {
	i, err := Read(root)
	if err != nil {
		return i, err
	}
	if !i.Enabled || i.Instance != instance {
		return i, errors.New("installation disabled or wrong instance")
	}
	v, err := operator.VerifyRelease(i.Release, trust, now)
	if err != nil {
		return i, err
	}
	if err = operator.CheckActivation(i.Approval, v, instance, now); err != nil {
		return i, err
	}
	m := v.Manifest
	if v.Digest != i.Digest || m.Component != "operator" || m.Version != i.Version || m.Sequence != i.Sequence || m.ConfigSchema != i.ConfigSchema || m.DatabaseSchema != i.DatabaseSchema || m.SigningCodec != i.Codec {
		return i, errors.New("installation differs from authenticated release")
	}
	if err = Verify(root, i); err != nil {
		return i, err
	}
	archive, err := worker.ReadPrivateFile(filepath.Join(root, "releases", i.Artifact, "approved-bundle.tar"), MaxBundle)
	if err != nil {
		return i, err
	}
	matched := false
	for _, a := range m.Artifacts {
		if a.Platform == i.Platform && a.SHA256 == i.Artifact && operator.VerifyArtifact(a, archive) == nil {
			matched = true
		}
	}
	if !matched {
		return i, errors.New("retained archive differs from approved release")
	}
	seen := map[string]bool{}
	tr := tar.NewReader(bytes.NewReader(archive))
	var total int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return i, errors.New("invalid retained archive")
		}
		want, ok := i.Files[h.Name]
		if !ok || seen[h.Name] || h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > MaxBundle {
			return i, errors.New("invalid retained archive entry")
		}
		seen[h.Name] = true
		total += h.Size
		if total > MaxBundle {
			return i, errors.New("oversized retained archive")
		}
		b, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil || int64(len(b)) != h.Size || hash(b) != want {
			return i, errors.New("installed file map differs from publisher-authenticated archive")
		}
	}
	if len(seen) != len(Files) {
		return i, errors.New("incomplete retained archive")
	}
	return i, nil
}
