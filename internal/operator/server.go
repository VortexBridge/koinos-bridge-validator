package operator

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Store        *Store
	Token        string
	Host         string
	Origins      []string
	mu           sync.Mutex
	observations map[string]Observation
	reads        chan struct{}
	instances    map[string]*Server
}

func NewServer(store *Store, token, host string, origins []string) *Server {
	s := &Server{Store: store, Token: token, Host: host, Origins: origins, observations: map[string]Observation{}, reads: make(chan struct{}, 2), instances: map[string]*Server{}}
	for _, entry := range store.LocalInstances() {
		if entry.ID != "default" {
			child, _ := store.LocalInstance(entry.ID)
			s.instances[entry.ID] = NewServer(child, token, host, origins)
		}
	}
	return s
}
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v interface{}) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("invalid, unknown or oversized request fields")
	}
	if d.Decode(new(interface{})) != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Host != s.Host {
		fail(w, 403, "untrusted Host")
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		allowed := false
		for _, o := range s.Origins {
			if o == origin {
				allowed = true
			}
		}
		if !allowed {
			fail(w, 403, "untrusted Origin")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
	if r.Method == http.MethodOptions {
		if origin == "" {
			fail(w, 403, "Origin required")
			return
		}
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.WriteHeader(204)
		return
	}
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(s.Token) != 64 || r.Header.Get("Authorization") == provided || subtle.ConstantTimeCompare([]byte(provided), []byte(s.Token)) != 1 {
		fail(w, 401, "operator access token required")
		return
	}
	if r.URL.Path == "/v1/instances" && r.Method == "GET" {
		writeJSON(w, 200, map[string]interface{}{"instances": s.Store.LocalInstances(), "notice": "These instances share one local operator and host control domain. Separate storage does not establish independent validators."})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/instances/") {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/v1/instances/"), "/", 2)
		if len(parts) != 2 || !slug.MatchString(parts[0]) || parts[1] == "" || strings.Contains(parts[1], "..") || strings.HasPrefix(parts[1], "instances") {
			fail(w, 404, "unknown instance route")
			return
		}
		target := s
		if parts[0] != "default" {
			target = s.instances[parts[0]]
		}
		if target == nil {
			fail(w, 404, "unknown local instance")
			return
		}
		request := r.Clone(r.Context())
		request.URL.Path = "/v1/" + parts[1]
		request.URL.RawPath = ""
		target.serveAPI(w, request)
		return
	}
	s.serveAPI(w, r)
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/worker/setup" && r.Method == "GET":
		writeJSON(w, 200, s.Store.SetupState())
	case r.URL.Path == "/v1/worker/setup/preview" && r.Method == "POST":
		var req SetupInput
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		preview, err := s.Store.PreviewWorkerSetup(req)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		writeJSON(w, 200, preview)
	case r.URL.Path == "/v1/worker/setup/create" && r.Method == "POST":
		var req CreateWorker
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		receipt, err := s.Store.CreateObservationWorker(req)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		writeJSON(w, 201, receipt)
	case r.URL.Path == "/v1/worker/doctor" && r.Method == "POST":
		var req struct{}
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		select {
		case s.reads <- struct{}{}:
			defer func() { <-s.reads }()
		default:
			fail(w, 429, "observation capacity busy; retry later")
			return
		}
		writeJSON(w, 200, s.Store.Doctor(r.Context()))
	case r.URL.Path == "/v1/worker" && r.Method == "GET":
		writeJSON(w, 200, s.Store.WorkerStatus(r.Context()))
	case r.URL.Path == "/v1/worker/start" && r.Method == "POST":
		var req struct {
			RegistrationDigest string `json:"registrationDigest"`
		}
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		status, err := s.Store.StartWorker(r.Context(), req.RegistrationDigest)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		writeJSON(w, 202, status)
	case r.URL.Path == "/v1/worker/stop" && r.Method == "POST":
		var req struct {
			RegistrationDigest string    `json:"registrationDigest"`
			PID                int       `json:"pid"`
			StartedAt          time.Time `json:"startedAt"`
		}
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		status, err := s.Store.StopWorker(r.Context(), req.RegistrationDigest, req.PID, req.StartedAt)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		writeJSON(w, 202, status)
	case r.URL.Path == "/v1/capabilities" && r.Method == "GET":
		writeJSON(w, 200, map[string]interface{}{"families": []map[string]string{{"id": "evm", "codec": EVMCodec, "sourceCommit": EVMSource}, {"id": "koinos", "codec": KoinosCodec, "sourceCommit": KoinosSource}}, "actions": actionIDs, "signingEnabled": false, "lifecycleEnabled": true, "workerModes": []string{"observation-only"}})
	case r.URL.Path == "/v1/updates" && r.Method == "GET":
		trust, err := s.Store.ReleaseTrust()
		publishers := []string{}
		if err == nil {
			for id := range trust.Publishers {
				publishers = append(publishers, id)
			}
		}
		writeJSON(w, 200, map[string]interface{}{"approvals": s.Store.ReleaseApprovals(), "trustedPublishers": publishers, "requiredSignatures": trust.RequiredSignatures, "installerEnabled": false, "installedVersion": nil, "staged": s.Store.StagedReleases(time.Now().UTC())})
	case r.URL.Path == "/v1/updates/verify" && r.Method == "POST":
		var release SignedRelease
		if err := decode(w, r, &release); err != nil {
			fail(w, 400, err.Error())
			return
		}
		trust, err := s.Store.ReleaseTrust()
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		verified, err := VerifyRelease(release, trust, time.Now().UTC())
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		writeJSON(w, 200, verified)
	case r.URL.Path == "/v1/updates/approve" && r.Method == "POST":
		var req ApproveRelease
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		approval, err := s.Store.ApproveRelease(req, time.Now().UTC())
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		writeJSON(w, 200, map[string]interface{}{"approval": approval, "installed": false})
	case r.URL.Path == "/v1/updates/revoke" && r.Method == "POST":
		var req struct {
			Digest           string `json:"digest"`
			ExpectedRevision uint64 `json:"expectedRevision"`
		}
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if err := s.Store.RevokeRelease(req.Digest, req.ExpectedRevision, time.Now().UTC()); err != nil {
			fail(w, 409, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"revoked": true})
	case r.URL.Path == "/v1/status" && r.Method == "GET":
		revision, profiles, events := s.Store.Summary()
		s.mu.Lock()
		observations := []Observation{}
		for _, o := range s.observations {
			if time.Since(o.ObservedAt) > 30*time.Second || o.ConfigurationRevision != revision {
				o.Status = "stale"
				o.GovernanceReady = false
				o.Message = "Observation is old or configuration changed. Refresh before acting."
			}
			observations = append(observations, o)
		}
		s.mu.Unlock()
		writeJSON(w, 200, map[string]interface{}{"version": "operator-dev-1", "instanceId": s.Store.InstanceID(), "mode": "observation-only", "revision": revision, "profiles": profiles, "observations": observations, "events": events, "signerAvailable": false, "notice": "Private control plane. Locally registered observation workers have an independent lifecycle; managed signing is unavailable."})
	case r.URL.Path == "/v1/config/validate" && r.Method == "POST":
		var b Binding
		if err := decode(w, r, &b); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if err := b.Validate(); err != nil {
			fail(w, 422, err.Error())
			return
		}
		writeJSON(w, 200, map[string]interface{}{"valid": true, "profileDigest": b.Profile.Digest(), "mode": "observation-only"})
	case r.URL.Path == "/v1/config/apply" && r.Method == "POST":
		var req ApplyConfig
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		revision, err := s.Store.Apply(req)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		s.mu.Lock()
		delete(s.observations, req.Binding.Profile.ID)
		s.mu.Unlock()
		writeJSON(w, 200, map[string]interface{}{"revision": revision})
	case strings.HasPrefix(r.URL.Path, "/v1/observations/") && r.Method == "POST":
		select {
		case s.reads <- struct{}{}:
			defer func() { <-s.reads }()
		default:
			fail(w, 429, "two observations already running; retry shortly")
			return
		}
		revision, _, _ := s.Store.Summary()
		id := strings.TrimPrefix(r.URL.Path, "/v1/observations/")
		binding, ok := s.Store.Binding(id)
		if !ok {
			fail(w, 404, "unknown deployment profile")
			return
		}
		observation := Observe(r.Context(), binding)
		observation.ConfigurationRevision = revision
		// A read finishing after a config change must not overwrite fresh context.
		current, ok := s.Store.Binding(id)
		if !ok || current != binding {
			fail(w, 409, "configuration changed during observation")
			return
		}
		s.mu.Lock()
		s.observations[id] = observation
		s.mu.Unlock()
		writeJSON(w, 200, observation)
	case r.URL.Path == "/v1/governance/encode" && r.Method == "POST":
		var req struct {
			ProfileID string `json:"profileId"`
			Action    Action `json:"action"`
		}
		if err := decode(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		b, ok := s.Store.Binding(req.ProfileID)
		if !ok {
			fail(w, 404, "unknown deployment profile")
			return
		}
		payload, err := EncodeAction(b.Profile, req.Action)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		writeJSON(w, 200, map[string]interface{}{"payload": payload, "state": "unsigned-draft", "notice": "Encoding is not authorization or verification of current contract state."})
	default:
		fail(w, 404, "unsupported operator route or method")
	}
}
