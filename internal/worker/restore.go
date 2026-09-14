package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

type RestoreFence struct {
	SchemaVersion        int       `json:"schemaVersion"`
	State                string    `json:"state"`
	BackupSHA256         string    `json:"backupSha256"`
	PublicConfigSHA256   string    `json:"publicConfigSha256"`
	ReviewedConfigSHA256 string    `json:"reviewedConfigSha256,omitempty"`
	SourceInstanceID     string    `json:"sourceInstanceId"`
	SourceMode           string    `json:"sourceMode"`
	RestoredAt           time.Time `json:"restoredAt"`
	ReviewNote           string    `json:"reviewNote,omitempty"`
}

func ReadRestoreFence(dir string) (*RestoreFence, error) {
	path := filepath.Join(dir, "restore.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, nil
	}
	raw, err := ReadPrivateFile(path, 8192)
	if err != nil {
		return nil, err
	}
	var fence RestoreFence
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	validHash := func(s string) bool {
		b, err := hex.DecodeString(s)
		return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
	}
	if d.Decode(&fence) != nil || d.Decode(new(interface{})) != io.EOF || fence.SchemaVersion != 1 || !validHash(fence.BackupSHA256) || !validHash(fence.PublicConfigSHA256) || fence.RestoredAt.IsZero() || (fence.State != "review-required" && fence.State != "observation-enabled") || (fence.State == "observation-enabled" && !validHash(fence.ReviewedConfigSHA256)) {
		return nil, errors.New("invalid restore review marker")
	}
	return &fence, nil
}
func CheckRestoreFence(dir string, observe bool) error {
	fence, err := ReadRestoreFence(dir)
	if err != nil {
		return err
	}
	if fence == nil {
		return nil
	}
	if !observe {
		return errors.New("restored state is restricted to observation; signing recovery requires a reviewed reconciliation workflow")
	}
	if fence.State != "observation-enabled" {
		return errors.New("restored state requires local configuration and checkpoint review before observation")
	}
	raw, err := ReadPrivateFile(filepath.Join(dir, "..", "..", "config.yml"), 128<<10)
	if err != nil {
		return err
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != fence.ReviewedConfigSHA256 {
		return errors.New("restored configuration changed after review; review it again before observation")
	}
	return nil
}
