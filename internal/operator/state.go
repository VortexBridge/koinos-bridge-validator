package operator

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Event struct {
	At        time.Time `json:"at"`
	Action    string    `json:"action"`
	ProfileID string    `json:"profileId,omitempty"`
	Revision  uint64    `json:"revision"`
}
type appliedRequest struct {
	Digest   string `json:"digest"`
	Revision uint64 `json:"revision"`
}
type diskState struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Revision      uint64                    `json:"revision"`
	Bindings      []Binding                 `json:"bindings"`
	Events        []Event                   `json:"events"`
	Applied       map[string]appliedRequest `json:"applied"`
	Approvals     []ReleaseApproval         `json:"approvals"`
}

func strictJSON(b []byte, v interface{}) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(interface{})) != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}

type Store struct {
	instancesMu sync.Mutex
	instances   map[string]*Store
	parent      *Store
	workerMu    sync.Mutex
	updateMu    sync.Mutex
	mu          sync.Mutex
	dir         string
	lock        *os.File
	data        diskState
	instanceID  string
}

func OpenStore(dir string) (*Store, error) {
	s, err := openSingleStore(dir)
	if err != nil {
		return nil, err
	}
	if err := s.loadInstances(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func openSingleStore(dir string) (*Store, error) {
	absolute, absErr := filepath.Abs(dir)
	if absErr != nil {
		return nil, absErr
	}
	dir = absolute
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("operator directory must be a private directory (0700), not a symlink")
	}
	lockPath := filepath.Join(dir, "operator.lock")
	if info, err := os.Lstat(lockPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("operator lock cannot be a symlink")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("operator state is already in use")
	}
	s := &Store{dir: dir, lock: lock, data: diskState{SchemaVersion: 1, Bindings: []Binding{}, Events: []Event{}, Applied: map[string]appliedRequest{}}}
	identityPath := filepath.Join(dir, "instance-id")
	identityInfo, identityErr := os.Lstat(identityPath)
	if os.IsNotExist(identityErr) {
		seed := make([]byte, 16)
		if _, err := rand.Read(seed); err != nil {
			s.Close()
			return nil, err
		}
		s.instanceID = "operator-" + hex.EncodeToString(seed)
		if err := atomicFile(dir, "instance-id", []byte(s.instanceID)); err != nil {
			s.Close()
			return nil, err
		}
	} else {
		if identityErr != nil || !identityInfo.Mode().IsRegular() || identityInfo.Mode().Perm()&0077 != 0 || identityInfo.Size() != 41 {
			s.Close()
			return nil, errors.New("invalid private instance-id file")
		}
		identity, err := os.ReadFile(identityPath)
		if err != nil || !slug.Match(identity) {
			s.Close()
			return nil, errors.New("invalid operator instance identity")
		}
		s.instanceID = string(identity)
	}
	statePath := filepath.Join(dir, "state.json")
	info, err = os.Lstat(statePath)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2*1024*1024 {
		s.Close()
		return nil, errors.New("operator state must be a private regular file under 2 MiB")
	}
	f, err := os.Open(statePath)
	if err != nil {
		s.Close()
		return nil, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 2*1024*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&s.data); err != nil {
		s.Close()
		return nil, errors.New("operator state corrupt; restore reviewed backup, never reset automatically")
	}
	if d.Decode(new(interface{})) != io.EOF || s.data.SchemaVersion != 1 || s.data.Applied == nil {
		s.Close()
		return nil, errors.New("unsupported or malformed operator state")
	}
	seen := map[string]bool{}
	for _, b := range s.data.Bindings {
		if b.Validate() != nil || seen[b.Profile.ID] {
			s.Close()
			return nil, errors.New("invalid stored deployment configuration")
		}
		seen[b.Profile.ID] = true
	}
	return s, nil
}

func (s *Store) Close() error {
	for _, child := range s.instances {
		child.Close()
	}
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func (s *Store) InstanceID() string { return s.instanceID }

func atomicFile(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Store) Token() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, "access-token")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", errors.New("access-token must be a private regular file")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if len(b) != 64 {
			return "", errors.New("invalid access-token file")
		}
		if _, err := hex.DecodeString(string(b)); err != nil {
			return "", errors.New("invalid access-token file")
		}
		return string(b), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	return token, atomicFile(s.dir, "access-token", []byte(token))
}

type ApplyConfig struct {
	ExpectedRevision uint64  `json:"expectedRevision"`
	IdempotencyKey   string  `json:"idempotencyKey"`
	Binding          Binding `json:"binding"`
}

func (s *Store) Apply(req ApplyConfig) (uint64, error) {
	if err := req.Binding.Validate(); err != nil {
		return 0, err
	}
	if !slug.MatchString(req.IdempotencyKey) {
		return 0, errors.New("idempotencyKey must be a lowercase slug")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(req)
	hash := sha256.Sum256(b)
	digest := hex.EncodeToString(hash[:])
	if old, ok := s.data.Applied[req.IdempotencyKey]; ok {
		if old.Digest != digest {
			return 0, errors.New("idempotency key reused for different request")
		}
		return old.Revision, nil
	}
	if req.ExpectedRevision != s.data.Revision {
		return 0, errors.New("configuration revision changed; refresh before applying")
	}
	if len(s.data.Applied) >= 1000 {
		return 0, errors.New("request ledger full; reviewed compaction required")
	}
	// Clone before committing so failed writes cannot mutate live configuration.
	raw, _ := json.Marshal(s.data)
	var next diskState
	json.Unmarshal(raw, &next)
	found := false
	for i, b := range next.Bindings {
		if b.Profile.ID == req.Binding.Profile.ID {
			next.Bindings[i] = req.Binding
			found = true
			break
		}
	}
	if !found {
		if len(next.Bindings) >= 32 {
			return 0, errors.New("maximum 32 deployment profiles")
		}
		next.Bindings = append(next.Bindings, req.Binding)
	}
	next.Revision++
	next.Events = append(next.Events, Event{time.Now().UTC(), "configuration applied", req.Binding.Profile.ID, next.Revision})
	next.Applied[req.IdempotencyKey] = appliedRequest{digest, next.Revision}
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := atomicFile(s.dir, "state.json", encoded); err != nil {
		return 0, errors.New("cannot persist configuration")
	}
	s.data = next
	return next.Revision, nil
}

func (s *Store) Binding(id string) (Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.data.Bindings {
		if b.Profile.ID == id {
			return b, true
		}
	}
	return Binding{}, false
}
func (s *Store) Summary() (uint64, []Profile, []Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	profiles := []Profile{}
	for _, b := range s.data.Bindings {
		profiles = append(profiles, b.Profile)
	}
	events := append([]Event{}, s.data.Events...)
	return s.data.Revision, profiles, events
}
