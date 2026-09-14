// Package worker provides the validator's private, authenticated local control
// socket. It is independent of the dashboard/operator process.
package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ChainHealth struct {
	Height    uint64    `json:"height"`
	UpdatedAt time.Time `json:"updatedAt"`
	Status    string    `json:"status"`
}
type Health struct {
	InstanceID    string                 `json:"instanceId"`
	PID           int                    `json:"pid"`
	StartedAt     time.Time              `json:"startedAt"`
	Mode          string                 `json:"mode"`
	EVMAddress    string                 `json:"evmAddress,omitempty"`
	KoinosAddress string                 `json:"koinosAddress,omitempty"`
	Chains        map[string]ChainHealth `json:"chains"`
}
type Monitor struct {
	mu     sync.Mutex
	health Health
}

func NewMonitor(id string, observe bool, evm, koinos string) *Monitor {
	mode := "signing"
	if observe {
		mode = "observation-only"
	}
	return &Monitor{health: Health{id, os.Getpid(), time.Now().UTC(), mode, evm, koinos, map[string]ChainHealth{"evm": {Status: "starting"}, "koinos": {Status: "starting"}}}}
}
func (m *Monitor) Progress(chain string, height uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.health.Chains[chain] = ChainHealth{height, time.Now().UTC(), "observed"}
}
func (m *Monitor) Problem(chain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.health.Chains[chain]
	h.Status = "unavailable"
	m.health.Chains[chain] = h
}
func (m *Monitor) Snapshot() Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.health
	h.Chains = map[string]ChainHealth{}
	for k, v := range m.health.Chains {
		if v.Status == "observed" && time.Since(v.UpdatedAt) > 30*time.Second {
			v.Status = "stale"
		}
		h.Chains[k] = v
	}
	return h
}

// Lease excludes accidental duplicate processes using the same local resource.
// It does not establish cross-host fencing or independence of cloud accounts.
type Lease struct{ file *os.File }

func PrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("control directory must be private (0700) and not a symlink")
	}
	return nil
}
func Acquire(dir, name string) (*Lease, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, errors.New("invalid lease name")
	}
	if err := PrivateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("lease must be a regular file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("resource is already owned by another local process")
	}
	return &Lease{f}, nil
}
func (l *Lease) Close() error { return l.file.Close() }

func ReadPrivateFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("private file unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() == 0 || info.Size() > maxBytes {
		return nil, errors.New("private file must be a bounded regular file with mode 0600")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(b)) > maxBytes || len(b) == 0 {
		return nil, errors.New("private file unreadable or oversized")
	}
	return b, nil
}
func LoadKey(inline, path string, observe bool) (string, error) {
	if observe {
		return "", nil
	} // Never even open key files in observation-only mode.
	if inline != "" && path != "" {
		return "", errors.New("choose a key file or an inline key, not both")
	}
	if path != "" {
		b, err := ReadPrivateFile(path, 4096)
		if err != nil {
			return "", err
		}
		value := strings.TrimSpace(string(b))
		if value == "" {
			return "", errors.New("signing key missing")
		}
		return value, nil
	}
	if inline == "" {
		return "", errors.New("signing key missing")
	}
	return inline, nil
}
func Token(dir string) (string, error) {
	path := filepath.Join(dir, "control-token")
	if _, err := os.Lstat(path); err == nil {
		b, err := ReadPrivateFile(path, 64)
		if err != nil {
			return "", err
		}
		if len(b) != 64 {
			return "", errors.New("invalid control token")
		}
		if _, err := hex.DecodeString(string(b)); err != nil {
			return "", errors.New("invalid control token")
		}
		return string(b), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(token)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	return token, closeErr
}

type Control struct {
	server   *http.Server
	listener net.Listener
	socket   string
}

// Caller must hold process.lock until the worker exits, including after Close.
func StartControl(dir string, monitor *Monitor, stop context.CancelFunc) (*Control, error) {
	if err := PrivateDir(dir); err != nil {
		return nil, err
	}
	token, err := Token(dir)
	if err != nil {
		return nil, err
	}
	socket := filepath.Join(dir, "control.sock")
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("control socket path is occupied by a non-socket")
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0600); err != nil {
		l.Close()
		return nil, err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if r.Header.Get("Origin") != "" || r.Host != "localhost" || provided == r.Header.Get("Authorization") || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"error": "private worker authorization required"})
			return
		}
		if r.Method == "GET" && r.URL.Path == "/health" {
			json.NewEncoder(w).Encode(monitor.Snapshot())
			return
		}
		if r.Method == "POST" && r.URL.Path == "/stop" {
			var expected struct {
				PID       int       `json:"pid"`
				StartedAt time.Time `json:"startedAt"`
			}
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			d.DisallowUnknownFields()
			current := monitor.Snapshot()
			if d.Decode(&expected) != nil || d.Decode(new(interface{})) != io.EOF || expected.PID != current.PID || !expected.StartedAt.Equal(current.StartedAt) {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{"error": "worker changed since review"})
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"stopping": true})
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			stop()
			return
		}
		w.WriteHeader(404)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	c := &Control{server, l, socket}
	go server.Serve(l)
	return c, nil
}
func (c *Control) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.server.Shutdown(ctx)
}

// Call never uses DNS or TCP. The URL is a constant; only a local Unix socket
// selected by the operator's registered worker directory is contacted.
func Call(ctx context.Context, dir, method, path string, out interface{}, expected ...Health) error {
	if !((method == "GET" && path == "/health") || (method == "POST" && path == "/stop")) {
		return errors.New("unsupported worker control action")
	}
	token, err := ReadPrivateFile(filepath.Join(dir, "control-token"), 64)
	if err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "control.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect disabled") }}
	var body io.Reader
	if method == "POST" {
		if len(expected) != 1 {
			return errors.New("stop requires the reviewed worker identity")
		}
		b, _ := json.Marshal(struct {
			PID       int       `json:"pid"`
			StartedAt time.Time `json:"startedAt"`
		}{expected[0].PID, expected[0].StartedAt})
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	res, err := client.Do(req)
	if err != nil {
		return errors.New("worker control socket unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("worker rejected control request")
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(out); err != nil {
		return errors.New("invalid worker response")
	}
	return nil
}

// EnsureMode prevents an observation checkpoint being mistaken for a signed
// history after a configuration toggle. Call under the process lease.
func EnsureMode(dir string, observe, existingDatabase bool) error {
	mode := "signing"
	if observe {
		mode = "observation-only"
	}
	path := filepath.Join(dir, "data-mode")
	if _, err := os.Lstat(path); err == nil {
		b, err := ReadPrivateFile(path, 32)
		if err != nil {
			return err
		}
		if string(b) != mode {
			return errors.New("data directory belongs to another mode; use a separate directory or an explicitly reviewed migration")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if observe && existingDatabase {
		return errors.New("existing validator database cannot be adopted as observation data without an explicit migration")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.WriteString(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
