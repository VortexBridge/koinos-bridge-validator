package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"gopkg.in/yaml.v2"
)

var workerHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func networkBinding(cfg util.YamlConfig) worker.NetworkBinding {
	return worker.NetworkBinding{SchemaVersion: 1, EVMNetworkID: cfg.Bridge.EthereumNetworkID, KoinosNetworkID: cfg.Bridge.KoinosNetworkID, EVMContract: cfg.Bridge.EthereumContract, KoinosContract: cfg.Bridge.KoinosContract}
}

// Registration is installed only by the local CLI. The browser never supplies
// executable paths, argument lists, key paths or shell commands.
type WorkerRegistration struct {
	SchemaVersion int    `json:"schemaVersion"`
	InstanceID    string `json:"instanceId"`
	BaseDir       string `json:"baseDir"`
	BinarySHA256  string `json:"binarySha256"`
	ConfigSHA256  string `json:"configSha256"`
	Mode          string `json:"mode"`
}
type WorkerStatus struct {
	Registered         bool           `json:"registered"`
	RegistrationDigest string         `json:"registrationDigest,omitempty"`
	InstanceID         string         `json:"instanceId,omitempty"`
	BinarySHA256       string         `json:"binarySha256,omitempty"`
	ConfigSHA256       string         `json:"configSha256,omitempty"`
	State              string         `json:"state"`
	Health             *worker.Health `json:"health,omitempty"`
	Message            string         `json:"message"`
}

func registrationDigest(r WorkerRegistration) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Store) registration() (WorkerRegistration, error) {
	b, err := worker.ReadPrivateFile(filepath.Join(s.dir, "worker.json"), 16384)
	if err != nil {
		return WorkerRegistration{}, err
	}
	var r WorkerRegistration
	if err := strictJSON(b, &r); err != nil {
		return r, errors.New("invalid worker registration")
	}
	if r.SchemaVersion != 1 || !slug.MatchString(r.InstanceID) || !filepath.IsAbs(r.BaseDir) || !workerHashPattern.MatchString(r.BinarySHA256) || !workerHashPattern.MatchString(r.ConfigSHA256) || r.Mode != "observation-only" {
		return r, errors.New("unsupported worker registration")
	}
	return r, nil
}
func workerConfig(base string) ([]byte, util.YamlConfig, error) {
	b, err := worker.ReadPrivateFile(filepath.Join(base, "config.yml"), 128*1024)
	if err != nil {
		return nil, util.YamlConfig{}, err
	}
	var cfg util.YamlConfig
	if yaml.UnmarshalStrict(b, &cfg) != nil {
		return nil, cfg, errors.New("invalid or unknown worker configuration fields")
	}
	if cfg.Bridge.EthereumPK != "" || cfg.Bridge.KoinosPK != "" {
		return nil, cfg, errors.New("managed observation configuration must not contain inline signing keys")
	}
	if cfg.Bridge.Reset {
		return nil, cfg, errors.New("managed worker cannot use reset on startup")
	}
	if binding := networkBinding(cfg); binding.Enabled() {
		if err := binding.Validate(); err != nil {
			return nil, cfg, err
		}
	}
	return b, cfg, nil
}
func (s *Store) RegisterWorker(base, binary, expectedHash string) (WorkerRegistration, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if !workerHashPattern.MatchString(expectedHash) {
		return WorkerRegistration{}, errors.New("provide the reviewed binary SHA-256")
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "worker.json")); !os.IsNotExist(err) {
		return WorkerRegistration{}, errors.New("worker is already registered or registration cannot be read")
	}
	base, err := filepath.Abs(base)
	if err != nil {
		return WorkerRegistration{}, err
	}
	if err := worker.PrivateDir(base); err != nil {
		return WorkerRegistration{}, err
	}
	b, cfg, err := workerConfig(base)
	if err != nil {
		return WorkerRegistration{}, err
	}
	if !slug.MatchString(cfg.Bridge.InstanceID) {
		return WorkerRegistration{}, errors.New("worker requires a stable instance-id")
	}
	releaseOwnership, err := s.lockWorkerOwnership(base, cfg.Bridge.InstanceID)
	if err != nil {
		return WorkerRegistration{}, err
	}
	defer releaseOwnership()
	if _, err := os.Lstat(filepath.Join(base, "bridge", ".operator", "data-mode")); err == nil {
		mode, err := worker.ReadPrivateFile(filepath.Join(base, "bridge", ".operator", "data-mode"), 32)
		if err != nil || string(mode) != "observation-only" {
			return WorkerRegistration{}, errors.New("cannot register signing data as an observation worker")
		}
	}
	// Copy through a single open descriptor, hash the copied bytes, then make the
	// private immutable snapshot executable. Changing the source cannot change it.
	f, err := os.OpenFile(binary, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return WorkerRegistration{}, errors.New("local validator binary unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 256*1024*1024 {
		return WorkerRegistration{}, errors.New("invalid validator binary")
	}
	binDir := filepath.Join(s.dir, "worker-bin")
	if err := worker.PrivateDir(binDir); err != nil {
		return WorkerRegistration{}, err
	}
	temp, err := os.CreateTemp(binDir, ".binary-")
	if err != nil {
		return WorkerRegistration{}, err
	}
	defer os.Remove(temp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(temp, h), io.LimitReader(f, 256*1024*1024+1))
	if err != nil || n != info.Size() || hex.EncodeToString(h.Sum(nil)) != expectedHash {
		temp.Close()
		return WorkerRegistration{}, errors.New("validator binary digest or size changed")
	}
	if err = temp.Chmod(0500); err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return WorkerRegistration{}, err
	}
	if closeErr != nil {
		return WorkerRegistration{}, closeErr
	}
	if err = os.Rename(temp.Name(), filepath.Join(binDir, expectedHash)); err != nil {
		return WorkerRegistration{}, err
	}
	dirFD, err := os.Open(binDir)
	if err != nil {
		return WorkerRegistration{}, err
	}
	err = dirFD.Sync()
	dirFD.Close()
	if err != nil {
		return WorkerRegistration{}, err
	}
	configHash := sha256.Sum256(b)
	r := WorkerRegistration{1, cfg.Bridge.InstanceID, base, expectedHash, hex.EncodeToString(configHash[:]), "observation-only"}
	encoded, _ := json.Marshal(r)
	if err = atomicFile(s.dir, "worker.json", encoded); err != nil {
		return WorkerRegistration{}, err
	}
	return r, nil
}
func (s *Store) WorkerStatus(ctx context.Context) WorkerStatus {
	r, err := s.registration()
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(s.dir, "worker.json")); !os.IsNotExist(statErr) {
			return WorkerStatus{State: "invalid", Message: "Local worker registration is invalid or unreadable; restore a reviewed registration."}
		}
		return WorkerStatus{State: "unregistered", Message: "Register a reviewed local observation worker using the CLI."}
	}
	result := WorkerStatus{Registered: true, RegistrationDigest: registrationDigest(r), InstanceID: r.InstanceID, BinarySHA256: r.BinarySHA256, ConfigSHA256: r.ConfigSHA256, State: "unavailable", Message: "Worker socket is unavailable; it may be stopped or unhealthy."}
	var health worker.Health
	if err := worker.Call(ctx, filepath.Join(r.BaseDir, "bridge", ".operator"), "GET", "/health", &health); err == nil {
		if health.InstanceID != r.InstanceID || health.Mode != r.Mode {
			result.State = "mismatch"
			result.Message = "Worker identity or mode does not match its local registration."
			return result
		}
		result.State = "running"
		result.Health = &health
		result.Message = "Independent observation worker. Chain observations do not establish signing readiness."
	}
	return result
}
func (s *Store) StartWorker(ctx context.Context, digest string) (WorkerStatus, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	r, err := s.registration()
	if err != nil {
		return WorkerStatus{}, err
	}
	if registrationDigest(r) != digest {
		return WorkerStatus{}, errors.New("worker registration changed; review it again")
	}
	status := s.WorkerStatus(ctx)
	if status.State == "running" {
		return status, nil
	}
	if status.State == "mismatch" {
		return status, errors.New(status.Message)
	}
	b, cfg, err := workerConfig(r.BaseDir)
	if err != nil {
		return status, err
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != r.ConfigSHA256 || cfg.Bridge.InstanceID != r.InstanceID {
		return status, errors.New("worker configuration changed since local review")
	}
	binary := filepath.Join(s.dir, "worker-bin", r.BinarySHA256)
	f, err := worker.ReadPrivateFile(binary, 256*1024*1024)
	if err != nil {
		return status, err
	}
	h = sha256.Sum256(f)
	if hex.EncodeToString(h[:]) != r.BinarySHA256 {
		return status, errors.New("registered binary digest mismatch")
	}
	logPath := filepath.Join(s.dir, "worker.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return status, errors.New("worker log unavailable")
	}
	defer log.Close()
	cmd := exec.Command(binary, "--basedir", r.BaseDir, "--observe-only") // Fixed arguments; no shell and no key material.
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.Stdin = nil
	cmd.Dir = r.BaseDir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME")}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := s.recordLifecycle("worker start requested", r.InstanceID); err != nil {
		return status, err
	}
	if err := cmd.Start(); err != nil {
		return status, errors.New("worker failed to start")
	}
	go cmd.Wait()
	// A request cancellation must not terminate the independent worker.
	status.State = "starting"
	status.Message = "Start requested; refresh to verify the worker socket and chain progress."
	return status, nil
}
func (s *Store) StopWorker(ctx context.Context, digest string, pid int, startedAt time.Time) (WorkerStatus, error) {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	r, err := s.registration()
	if err != nil {
		return WorkerStatus{}, err
	}
	if registrationDigest(r) != digest {
		return WorkerStatus{}, errors.New("worker registration changed")
	}
	status := s.WorkerStatus(ctx)
	if status.State != "running" || status.Health == nil {
		return status, errors.New("registered worker is not verifiably running")
	}
	if status.Health.PID != pid || !status.Health.StartedAt.Equal(startedAt) {
		return status, errors.New("worker restarted since review; refresh before stopping")
	}
	if err := s.recordLifecycle("worker stop requested", r.InstanceID); err != nil {
		return status, err
	}
	var result map[string]bool
	if err := worker.Call(ctx, filepath.Join(r.BaseDir, "bridge", ".operator"), "POST", "/stop", &result, *status.Health); err != nil {
		return status, err
	}
	status.State = "stopping"
	status.Message = "Graceful stop requested; refresh to verify exit."
	return status, nil
}

func (s *Store) recordLifecycle(action, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Events) >= 4096 {
		return errors.New("event ledger full; reviewed compaction required")
	}
	raw, _ := json.Marshal(s.data)
	var next diskState
	json.Unmarshal(raw, &next)
	next.Revision++
	next.Events = append(next.Events, Event{time.Now().UTC(), action, id, next.Revision})
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded) > 2*1024*1024 {
		return errors.New("operator state size limit reached")
	}
	if err := atomicFile(s.dir, "state.json", encoded); err != nil {
		return errors.New("cannot persist worker action intent")
	}
	s.data = next
	return nil
}
