package operator

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

const maxLocalInstances = 16

type InstanceDescriptor struct {
	SchemaVersion      int       `json:"schemaVersion"`
	ID                 string    `json:"id"`
	OperatorInstanceID string    `json:"operatorInstanceId"`
	CreatedAt          time.Time `json:"createdAt"`
}
type LocalInstance struct {
	ID                 string `json:"id"`
	OperatorInstanceID string `json:"operatorInstanceId"`
	Revision           uint64 `json:"revision"`
	DeploymentCount    int    `json:"deploymentCount"`
	ControlDomain      string `json:"controlDomain"`
}

func (s *Store) loadInstances() error {
	s.instances = map[string]*Store{}
	parent := filepath.Join(s.dir, "instances")
	info, err := os.Lstat(parent)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("local instances directory must be private and not a symlink")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	if len(entries) > maxLocalInstances+16 {
		return errors.New("local instances directory exceeds inventory limit; inspect abandoned local creation jobs")
	}
	for _, entry := range entries {
		// Interrupted preparation never becomes an instance. Only the atomic rename
		// into a validated public slot name publishes a fully initialized store.
		if strings.HasPrefix(entry.Name(), ".creating-") {
			continue
		}
		id := entry.Name()
		if !slug.MatchString(id) || id == "default" || !entry.IsDir() || len(s.instances) >= maxLocalInstances {
			return errors.New("invalid local instance inventory")
		}
		dir := filepath.Join(parent, id)
		raw, err := worker.ReadPrivateFile(filepath.Join(dir, "instance.json"), 4096)
		if err != nil {
			return errors.New("local instance descriptor missing or invalid")
		}
		var descriptor InstanceDescriptor
		if strictJSON(raw, &descriptor) != nil || descriptor.SchemaVersion != 1 || descriptor.ID != id || descriptor.CreatedAt.IsZero() {
			return errors.New("local instance descriptor does not match its slot")
		}
		identity, err := worker.ReadPrivateFile(filepath.Join(dir, "instance-id"), 64)
		if err != nil || string(identity) != descriptor.OperatorInstanceID {
			return errors.New("local instance identity changed; refusing to recreate approval authority")
		}
		child, err := openSingleStore(dir)
		if err != nil {
			return err
		}
		child.parent = s
		s.instances[id] = child
	}
	return nil
}

// CreateInstance is a local CLI operation. HTTP callers never supply filesystem
// paths or create stores. All instances share this operator's local authority;
// separate stores are not evidence of separate hosts or administrators.
func (s *Store) CreateInstance(id string) (*Store, error) {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	if !slug.MatchString(id) || id == "default" {
		return nil, errors.New("instance name must be a lowercase slug other than default")
	}
	if len(s.instances) >= maxLocalInstances {
		return nil, errors.New("local instance limit reached")
	}
	if s.instances[id] != nil {
		return nil, errors.New("local instance already exists")
	}
	parent := filepath.Join(s.dir, "instances")
	if err := worker.PrivateDir(parent); err != nil {
		return nil, err
	}
	destination := filepath.Join(parent, id)
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return nil, errors.New("instance slot already exists or is unreadable")
	}
	temp, err := os.MkdirTemp(parent, ".creating-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(temp)
	child, err := openSingleStore(temp)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			child.Close()
		}
	}()
	descriptor := InstanceDescriptor{1, id, child.InstanceID(), time.Now().UTC()}
	raw, _ := json.Marshal(descriptor)
	if err := atomicFile(temp, "instance.json", raw); err != nil {
		return nil, err
	}
	if err := child.recordLifecycle("local instance created", id); err != nil {
		return nil, err
	}
	if err := os.Rename(temp, destination); err != nil {
		return nil, err
	}
	child.dir = destination
	child.parent = s
	if err := syncDirectory(parent); err != nil {
		return nil, errors.New("instance published but directory durability is uncertain; reopen operator inventory before retrying")
	}
	if s.instances == nil {
		s.instances = map[string]*Store{}
	}
	s.instances[id] = child
	success = true
	return child, nil
}

func (s *Store) LocalInstance(id string) (*Store, bool) {
	if id == "default" {
		return s, true
	}
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	child, ok := s.instances[id]
	return child, ok
}
func (s *Store) LocalInstances() []LocalInstance {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	ids := []string{}
	for id := range s.instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := []LocalInstance{}
	add := func(id string, child *Store) {
		revision, profiles, _ := child.Summary()
		result = append(result, LocalInstance{id, child.InstanceID(), revision, len(profiles), "same-local-operator"})
	}
	add("default", s)
	for _, id := range ids {
		add(id, s.instances[id])
	}
	return result
}

func (s *Store) lockWorkerOwnership(base, instanceID string) (func(), error) {
	root := s
	if s.parent != nil {
		root = s.parent
	}
	root.instancesMu.Lock()
	accepted := false
	defer func() {
		if !accepted {
			root.instancesMu.Unlock()
		}
	}()
	canonical, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, err
	}
	others := []*Store{root}
	for _, child := range root.instances {
		others = append(others, child)
	}
	for _, other := range others {
		if other == s {
			continue
		}
		if _, err := os.Lstat(filepath.Join(other.dir, "worker.json")); os.IsNotExist(err) {
			continue
		}
		r, err := other.registration()
		if err != nil {
			return nil, errors.New("another local instance has an invalid registration; inspect it before adding a worker")
		}
		owned, err := filepath.EvalSymlinks(r.BaseDir)
		if err != nil {
			return nil, errors.New("another registered data directory is unavailable; ownership cannot be verified")
		}
		if canonical == owned || instanceID == r.InstanceID {
			return nil, errors.New("worker directory or instance identity is already registered to another local instance")
		}
	}
	accepted = true
	return root.instancesMu.Unlock, nil
}
