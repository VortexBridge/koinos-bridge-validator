package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// These views deliberately duplicate only the public subset of the managed-host
// records. The managed package imports operator codecs, so importing managed here
// would create a cycle. Private RPCs, vault paths and review paths are parsed for
// validation and then omitted from every response.
type managedInstallationRecord struct {
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
	Release        json.RawMessage   `json:"release"`
	Approval       json.RawMessage   `json:"approval"`
}

type managedRuntimeRecord struct {
	Schema         int               `json:"schemaVersion"`
	Instance       string            `json:"instance"`
	EVM            Binding           `json:"evm"`
	Koinos         Binding           `json:"koinos"`
	Replica        string            `json:"koinosReplica"`
	EVMAddress     string            `json:"evmAddress"`
	KoinosAddress  string            `json:"koinosAddress"`
	PreviousEVM    string            `json:"previousEvm,omitempty"`
	PreviousKoinos string            `json:"previousKoinos,omitempty"`
	Tokens         map[string]string `json:"tokens"`
	Lifetime       uint64            `json:"signatureLifetimeMs"`
	BlockHints     map[string]uint64 `json:"koinosBlockHints"`
	Vault          string            `json:"vault"`
	HostReview     string            `json:"hostReview"`
	Reviewer       string            `json:"reviewer"`
	HostEvidence   string            `json:"hostEvidence"`
}

type ManagedOperationView struct {
	ID                   string    `json:"id"`
	Direction            string    `json:"direction"`
	Family               string    `json:"destinationFamily"`
	Digest               string    `json:"digest"`
	State                string    `json:"state"`
	Signed               bool      `json:"signed"`
	ObservedAt           time.Time `json:"observedAt,omitempty"`
	SourceBlockHash      string    `json:"sourceBlockHash,omitempty"`
	DestinationBlockHash string    `json:"destinationBlockHash,omitempty"`
	SourceFinality       string    `json:"sourceFinality,omitempty"`
	DestinationFinality  string    `json:"destinationFinality,omitempty"`
	ExpiresAt            string    `json:"expiresAt,omitempty"`
}

type managedJournalRecord struct {
	Schema       int                             `json:"schema"`
	PolicySHA256 string                          `json:"policySha256"`
	State        string                          `json:"state"`
	Checkpoint   string                          `json:"checkpoint"`
	Operations   map[string]managedOperationDisk `json:"operations"`
}

type managedOperationDisk struct {
	ID                   string    `json:"id"`
	Family               string    `json:"family"`
	Digest               string    `json:"digest"`
	State                string    `json:"state"`
	Signature            string    `json:"signature,omitempty"`
	ObservedAt           time.Time `json:"observedAt,omitempty"`
	SourceBlockHash      string    `json:"sourceBlockHash,omitempty"`
	DestinationBlockHash string    `json:"destinationBlockHash,omitempty"`
	SourceFinality       string    `json:"sourceFinality,omitempty"`
	DestinationFinality  string    `json:"destinationFinality,omitempty"`
	ExpiresAt            string    `json:"expiresAt,omitempty"`
}

type ManagedInstallationView struct {
	State          string `json:"state"`
	Enabled        bool   `json:"enabled"`
	Verified       bool   `json:"verified"`
	Version        string `json:"version,omitempty"`
	Sequence       uint64 `json:"sequence,omitempty"`
	ReleaseDigest  string `json:"releaseDigest,omitempty"`
	ArtifactSHA256 string `json:"artifactSha256,omitempty"`
	Platform       string `json:"platform,omitempty"`
	Problem        string `json:"problem,omitempty"`
}

type ManagedRouteView struct {
	Direction               string  `json:"direction"`
	Source                  Profile `json:"source"`
	Destination             Profile `json:"destination"`
	SignerAddress           string  `json:"signerAddress"`
	PreviousSignerAddress   string  `json:"previousSignerAddress,omitempty"`
	SignatureLifetimeMillis uint64  `json:"signatureLifetimeMs"`
}

type ManagedSignerView struct {
	Configured       bool                   `json:"configured"`
	State            string                 `json:"state"`
	ProcessEvidence  string                 `json:"processEvidence"`
	PolicySHA256     string                 `json:"policySha256,omitempty"`
	Checkpoint       string                 `json:"checkpoint,omitempty"`
	OperationCount   int                    `json:"operationCount"`
	UnfinalizedCount int                    `json:"unfinalizedCount"`
	Operations       []ManagedOperationView `json:"operations"`
	Problem          string                 `json:"problem,omitempty"`
}

type ManagedAuthorityView struct {
	BrowserCanUnlock bool   `json:"browserCanUnlock"`
	BrowserCanSign   bool   `json:"browserCanSign"`
	SecretEntry      string `json:"secretEntry"`
	Activation       string `json:"activation"`
	Drain            string `json:"drain"`
	Notice           string `json:"notice"`
}

type ManagedLifecycleView struct {
	SchemaVersion int                     `json:"schemaVersion"`
	Supported     bool                    `json:"supported"`
	InstanceID    string                  `json:"instanceId"`
	CheckedAt     time.Time               `json:"checkedAt"`
	Installation  ManagedInstallationView `json:"installation"`
	Signer        ManagedSignerView       `json:"signer"`
	Routes        []ManagedRouteView      `json:"routes"`
	Authority     ManagedAuthorityView    `json:"authority"`
	Notice        string                  `json:"notice"`
}

type TransferStageView struct {
	State    string `json:"state"`
	Evidence string `json:"evidence"`
}

type TransferHistoryItem struct {
	ID                string            `json:"id"`
	Direction         string            `json:"direction"`
	DestinationFamily string            `json:"destinationFamily"`
	Digest            string            `json:"digest"`
	SourceEvent       TransferStageView `json:"sourceEvent"`
	Observation       TransferStageView `json:"observation"`
	Signatures        TransferStageView `json:"signatures"`
	Quorum            TransferStageView `json:"quorum"`
	Submission        TransferStageView `json:"submission"`
	Finality          TransferStageView `json:"finality"`
	Expiry            TransferStageView `json:"expiry"`
	Rejection         TransferStageView `json:"rejection"`
}

type TransferHistoryView struct {
	SchemaVersion int                   `json:"schemaVersion"`
	CheckedAt     time.Time             `json:"checkedAt"`
	Items         []TransferHistoryItem `json:"items"`
	Notice        string                `json:"notice"`
}

type RecoveryView struct {
	SchemaVersion int             `json:"schemaVersion"`
	CheckedAt     time.Time       `json:"checkedAt"`
	Backup        BackupInventory `json:"backup"`
	RestoreState  string          `json:"restoreState"`
	RestoreDigest string          `json:"restoreDigest,omitempty"`
	ReviewNote    string          `json:"reviewNote,omitempty"`
	FencingState  string          `json:"fencingState"`
	Steps         []string        `json:"steps"`
	Notice        string          `json:"notice"`
}

func (s *Store) hostRoot() string {
	root := s
	if s.parent != nil {
		root = s.parent
	}
	return filepath.Dir(root.dir)
}

func readStrictPrivate(path string, max int64, value interface{}) error {
	raw, err := worker.ReadPrivateFile(path, max)
	if err != nil {
		return err
	}
	return strictJSON(raw, value)
}

func fileSHA256(path string, max int64) (string, error) {
	raw, err := worker.ReadPrivateFile(path, max)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

func verifyManagedInstallation(root string, record managedInstallationRecord) error {
	if record.Schema != 1 || record.Instance == "" || record.Version == "" || record.Platform == "" || !hexHash.MatchString(record.Digest) || !hexHash.MatchString(record.Artifact) || len(record.Files) == 0 || len(record.Files) > 32 || len(record.Release) == 0 || len(record.Approval) == 0 {
		return errors.New("installation record is incomplete")
	}
	releaseDir := filepath.Join(root, "releases", record.Artifact)
	info, err := os.Lstat(releaseDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("installed release directory is unavailable or unsafe")
	}
	expected := map[string]bool{
		"koinos-bridge-validator": true,
		"vortex-operator":         true,
		"vortex-keys":             true,
		"vortex-candidate-check":  true,
		"vortex-host":             true,
		"vortex-operator.service": true,
	}
	if len(record.Files) != len(expected) {
		return errors.New("installation file inventory is incomplete")
	}
	for name, want := range record.Files {
		if filepath.Base(name) != name || name == "." || name == ".." || !hexHash.MatchString(want) {
			return errors.New("installation file inventory is invalid")
		}
		if !expected[name] {
			return errors.New("installation file inventory is invalid")
		}
		got, err := fileSHA256(filepath.Join(releaseDir, name), 256<<20)
		if err != nil || got != want {
			return errors.New("one or more installed files changed")
		}
	}
	return nil
}

func readManagedRuntime(root string) (managedRuntimeRecord, error) {
	var cfg managedRuntimeRecord
	if err := readStrictPrivate(filepath.Join(root, "runtime.json"), 128<<10, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Schema != 1 || cfg.Instance == "" || cfg.EVM.Validate() != nil || cfg.Koinos.Validate() != nil || cfg.EVM.Profile.Family != "evm" || cfg.Koinos.Profile.Family != "koinos" || cfg.EVM.Profile.Environment != "local" || cfg.Koinos.Profile.Environment != "local" || cfg.Lifetime == 0 || cfg.Lifetime > 86400000 || !filepath.IsAbs(cfg.Vault) || !filepath.IsAbs(cfg.HostReview) || !filepath.IsAbs(cfg.Reviewer) || !filepath.IsAbs(cfg.HostEvidence) || len(cfg.BlockHints) > 4096 || (cfg.PreviousEVM == "") != (cfg.PreviousKoinos == "") {
		return cfg, errors.New("managed runtime configuration is invalid")
	}
	if _, err := addressBytes("evm", cfg.EVMAddress); err != nil {
		return cfg, errors.New("managed runtime signer identity is invalid")
	}
	if _, err := addressBytes("koinos", cfg.KoinosAddress); err != nil {
		return cfg, errors.New("managed runtime signer identity is invalid")
	}
	if cfg.PreviousEVM != "" {
		if _, err := addressBytes("evm", cfg.PreviousEVM); err != nil {
			return cfg, errors.New("managed runtime previous signer identity is invalid")
		}
		if _, err := addressBytes("koinos", cfg.PreviousKoinos); err != nil {
			return cfg, errors.New("managed runtime previous signer identity is invalid")
		}
	}
	return cfg, nil
}

func sessionLockHeld(root string) (bool, error) {
	path := filepath.Join(root, "managed-session", "session.lock")
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false, errors.New("managed session lock is unsafe")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true, nil
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, nil
}

func validateManagedJournal(j managedJournalRecord) error {
	if j.Schema != 1 || !hexHash.MatchString(j.PolicySHA256) || len(j.Operations) > 4096 || (j.Checkpoint != "" && !hexHash.MatchString(j.Checkpoint)) {
		return errors.New("managed journal is invalid")
	}
	if j.State != "locked" && j.State != "active" && j.State != "recovery-required" {
		return errors.New("managed journal lifecycle is unknown")
	}
	for id, operation := range j.Operations {
		if id == "" || len(id) > 128 || operation.ID != id || !hexHash.MatchString(operation.Digest) || (operation.Family != "evm" && operation.Family != "koinos") || (operation.State != "pending" && operation.State != "signed" && operation.State != "completed") {
			return errors.New("managed operation journal is invalid")
		}
		if (operation.Family == "koinos" && !strings.HasPrefix(id, "evm-to-koinos/")) || (operation.Family == "evm" && !strings.HasPrefix(id, "koinos-to-evm/")) {
			return errors.New("managed operation route is invalid")
		}
		if (operation.State == "pending" && operation.Signature != "") || (operation.Signature != "" && len(operation.Signature) > 512) {
			return errors.New("managed operation signature state is invalid")
		}
		if !operation.ObservedAt.IsZero() || operation.SourceBlockHash != "" || operation.DestinationBlockHash != "" || operation.SourceFinality != "" || operation.DestinationFinality != "" || operation.ExpiresAt != "" {
			if operation.ObservedAt.IsZero() || operation.ObservedAt.After(time.Now().Add(5*time.Second)) || !hexHash.MatchString(strings.TrimPrefix(operation.SourceBlockHash, "0x")) || !hexHash.MatchString(strings.TrimPrefix(operation.DestinationBlockHash, "0x")) || operation.SourceFinality != "finalized" || operation.DestinationFinality != "finalized" {
				return errors.New("managed operation evidence is invalid")
			}
			expiry, err := strconv.ParseUint(operation.ExpiresAt, 10, 64)
			if err != nil || expiry == 0 || strconv.FormatUint(expiry, 10) != operation.ExpiresAt {
				return errors.New("managed operation expiry is invalid")
			}
		}
	}
	return nil
}

func (s *Store) ManagedLifecycle() ManagedLifecycleView {
	now := time.Now().UTC()
	result := ManagedLifecycleView{
		SchemaVersion: 1,
		InstanceID:    s.InstanceID(),
		CheckedAt:     now,
		Installation:  ManagedInstallationView{State: "not-managed"},
		Signer:        ManagedSignerView{State: "not-configured", ProcessEvidence: "unknown", Operations: []ManagedOperationView{}},
		Routes:        []ManagedRouteView{},
		Authority: ManagedAuthorityView{
			BrowserCanUnlock: false,
			BrowserCanSign:   false,
			SecretEntry:      "protected local terminal only",
			Activation:       "vortex-host --root <private-installation-root> --config <private-runtime.json> --trust <publisher-policy.json> activate",
			Drain:            "enter drain in the active protected signer terminal; use stop only when an immediate lock is required",
			Notice:           "This API has no passphrase, key-import, arbitrary-signing or process-execution route.",
		},
		Notice: "Managed host state is read from owner-only local records. Unknown or inconsistent evidence never enables an action.",
	}
	root := s.hostRoot()
	var installation managedInstallationRecord
	if err := readStrictPrivate(filepath.Join(root, "installation.json"), 256<<10, &installation); err != nil {
		result.Installation.Problem = "No verified managed installation record is available to this operator service."
		return result
	}
	result.InstanceID = installation.Instance
	result.Supported = true
	result.Installation = ManagedInstallationView{State: "installed", Enabled: installation.Enabled, Version: installation.Version, Sequence: installation.Sequence, ReleaseDigest: installation.Digest, ArtifactSHA256: installation.Artifact, Platform: installation.Platform}
	if err := verifyManagedInstallation(root, installation); err != nil {
		result.Installation.State = "invalid"
		result.Installation.Problem = err.Error()
		return result
	}
	result.Installation.Verified = true
	if !installation.Enabled {
		result.Installation.State = "disabled"
	}
	cfg, err := readManagedRuntime(root)
	if err != nil {
		result.Signer.Problem = "A valid managed runtime has not been installed. Complete runtime configuration and independent host review before activation."
		return result
	}
	if cfg.Instance != installation.Instance {
		result.Signer.State = "invalid"
		result.Signer.Problem = "Managed runtime and installation instance identities differ."
		return result
	}
	result.Signer.Configured = true
	result.Routes = []ManagedRouteView{
		{Direction: "evm-to-koinos", Source: cfg.EVM.Profile, Destination: cfg.Koinos.Profile, SignerAddress: cfg.KoinosAddress, PreviousSignerAddress: cfg.PreviousKoinos, SignatureLifetimeMillis: cfg.Lifetime},
		{Direction: "koinos-to-evm", Source: cfg.Koinos.Profile, Destination: cfg.EVM.Profile, SignerAddress: cfg.EVMAddress, PreviousSignerAddress: cfg.PreviousEVM, SignatureLifetimeMillis: cfg.Lifetime},
	}
	var journal managedJournalRecord
	if err := readStrictPrivate(filepath.Join(root, "managed-session", "session.json"), 4<<20, &journal); err != nil {
		result.Signer.State = "never-activated"
		result.Signer.ProcessEvidence = "no managed session journal"
		return result
	}
	if err := validateManagedJournal(journal); err != nil {
		result.Signer.State = "invalid"
		result.Signer.Problem = err.Error()
		return result
	}
	held, lockErr := sessionLockHeld(root)
	result.Signer.State = journal.State
	result.Signer.PolicySHA256 = journal.PolicySHA256
	result.Signer.Checkpoint = journal.Checkpoint
	result.Signer.OperationCount = len(journal.Operations)
	ids := make([]string, 0, len(journal.Operations))
	for id := range journal.Operations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		op := journal.Operations[id]
		direction := strings.SplitN(id, "/", 2)[0]
		result.Signer.Operations = append(result.Signer.Operations, ManagedOperationView{ID: id, Direction: direction, Family: op.Family, Digest: op.Digest, State: op.State, Signed: op.Signature != "", ObservedAt: op.ObservedAt, SourceBlockHash: op.SourceBlockHash, DestinationBlockHash: op.DestinationBlockHash, SourceFinality: op.SourceFinality, DestinationFinality: op.DestinationFinality, ExpiresAt: op.ExpiresAt})
		if op.State != "completed" {
			result.Signer.UnfinalizedCount++
		}
	}
	if lockErr != nil {
		result.Signer.ProcessEvidence = "session lock unavailable"
		result.Signer.Problem = "The managed session process lock cannot be inspected."
		if journal.State == "active" {
			result.Signer.State = "recovery-required"
		} else {
			result.Signer.State = "invalid"
		}
		return result
	}
	if held {
		result.Signer.ProcessEvidence = "local managed session lock held"
		if journal.State != "active" {
			result.Signer.State = "starting-or-stopping"
		}
	} else {
		result.Signer.ProcessEvidence = "no process holds the managed session lock"
		if journal.State == "active" {
			result.Signer.State = "recovery-required"
			result.Signer.Problem = "The journal says active but no local process owns the session. Reconcile before another unlock."
		}
	}
	return result
}

func (s *Store) TransferHistory() TransferHistoryView {
	lifecycle := s.ManagedLifecycle()
	result := TransferHistoryView{SchemaVersion: 1, CheckedAt: lifecycle.CheckedAt, Items: []TransferHistoryItem{}, Notice: "History contains only independently persisted managed-journal evidence. Peer availability, aggregate quorum, destination submission and expiry stay unknown unless a verified receipt records them."}
	for _, operation := range lifecycle.Signer.Operations {
		item := TransferHistoryItem{
			ID: operation.ID, Direction: operation.Direction, DestinationFamily: operation.Family, Digest: operation.Digest,
			SourceEvent: TransferStageView{"verified", "The managed signer persisted this intent only after reconstructing a finalized source receipt."},
			Observation: TransferStageView{"verified", "The exact digest was independently reconstructed for the configured route."},
			Signatures:  TransferStageView{"pending", "No local signature is retained."},
			Quorum:      TransferStageView{"unknown", "The local journal does not assert current aggregate quorum."},
			Submission:  TransferStageView{"unknown", "No authoritative destination submission receipt is retained."},
			Finality:    TransferStageView{"pending", "Destination completion is not recorded."},
			Expiry:      TransferStageView{"unknown", "The journal intentionally does not retain a coordinator-supplied expiry claim."},
			Rejection:   TransferStageView{"none-recorded", "Rejected attempts do not become accepted journal entries."},
		}
		if operation.SourceBlockHash != "" {
			item.SourceEvent = TransferStageView{operation.SourceFinality, "Finalized source block " + operation.SourceBlockHash + "."}
			item.Observation = TransferStageView{"verified", "Digest reconstructed at " + operation.ObservedAt.Format(time.RFC3339) + " for the configured route."}
		}
		if operation.Signed {
			item.Signatures = TransferStageView{"local-signature-retained", "The local public signature is durably retained; this is not aggregate quorum."}
		}
		if operation.State == "completed" {
			item.Submission = TransferStageView{"observed-complete", "The managed reader observed destination completion while reconciling the retained operation."}
			evidence := "Both configured route readers reconciled the completed operation against finalized checkpoints."
			if operation.DestinationBlockHash != "" {
				evidence = "Finalized destination block " + operation.DestinationBlockHash + "."
			}
			item.Finality = TransferStageView{"finalized", evidence}
			item.Expiry = TransferStageView{"not-applicable", "The destination completion was observed before the retained operation was closed."}
		} else if expiry, err := strconv.ParseInt(operation.ExpiresAt, 10, 64); err == nil {
			if time.Now().UnixMilli() >= expiry {
				item.Expiry = TransferStageView{"expired", "The independently reconstructed signature deadline has passed."}
			} else {
				item.Expiry = TransferStageView{"current", "Signature deadline: " + time.UnixMilli(expiry).UTC().Format(time.RFC3339) + "."}
			}
		}
		result.Items = append(result.Items, item)
	}
	return result
}

func (s *Store) RecoveryState() RecoveryView {
	result := RecoveryView{
		SchemaVersion: 1,
		CheckedAt:     time.Now().UTC(),
		Backup:        s.ManagedBackups(),
		RestoreState:  "no-restored-worker-registered",
		FencingState:  "not-evaluated",
		Steps: []string{
			"Verify the encrypted archive and its receipt before recovery.",
			"In a protected local terminal, run vortex-operator backup-restore with the recovery identity file and a new private destination.",
			"Inspect both restored checkpoints and configuration, then run restore-review with the exact backup digest.",
			"Register the restored directory as observation-only and run preflight before starting it.",
			"For a signer replacement, retire both previous identities on finalized contracts before importing public journal state or unlocking a new vault.",
		},
		Notice: "Recovery identities and vault passwords are accepted only by protected local terminal commands. Restore never enables signing automatically.",
	}
	if registration, err := s.registration(); err == nil {
		if fence, err := worker.ReadRestoreFence(filepath.Join(registration.BaseDir, "bridge", ".operator")); err == nil && fence != nil {
			result.RestoreState = fence.State
			result.RestoreDigest = fence.BackupSHA256
			result.ReviewNote = fence.ReviewNote
		}
	}
	lifecycle := s.ManagedLifecycle()
	if len(lifecycle.Routes) == 2 && lifecycle.Routes[0].PreviousSignerAddress != "" && lifecycle.Routes[1].PreviousSignerAddress != "" {
		result.FencingState = "replacement-configured-both-chains"
	} else if lifecycle.Signer.Configured {
		result.FencingState = "same-identity-runtime"
	}
	return result
}
