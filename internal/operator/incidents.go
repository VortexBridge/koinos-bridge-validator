package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Incident struct {
	ID         string    `json:"id"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observedAt"`
	Evidence   string    `json:"evidence"`
	Action     string    `json:"action"`
}

type incidentDisk struct {
	SchemaVersion int        `json:"schemaVersion"`
	CheckedAt     time.Time  `json:"checkedAt"`
	History       []Incident `json:"history"`
}

type IncidentInventory struct {
	SchemaVersion int        `json:"schemaVersion"`
	CheckedAt     time.Time  `json:"checkedAt,omitempty"`
	Current       []Incident `json:"current"`
	History       []Incident `json:"history"`
	Problem       string     `json:"problem,omitempty"`
	Notice        string     `json:"notice"`
}

func incidentCategory(check DoctorCheck) string {
	switch {
	case check.ID == "local-ownership":
		return "duplicate-signer-risk"
	case strings.HasSuffix(check.ID, "-rpc"):
		if strings.Contains(strings.ToLower(check.Message), "network") || strings.Contains(strings.ToLower(check.Message), "chain") {
			return "wrong-network"
		}
		return "rpc-disagreement"
	case strings.Contains(check.ID, "network-binding") || strings.HasSuffix(check.ID, "-binding"):
		return "wrong-network"
	case check.ID == "configuration" || check.ID == "registration" || check.ID == "data-mode" || check.ID == "restore-review":
		return "failed-persistence"
	default:
		return "operator-preflight"
	}
}

func incidentFor(category, severity, evidence, action string, at time.Time, index int) Incident {
	return Incident{
		ID:         at.Format("20060102t150405.000000000z") + "-" + category + "-" + strconv.Itoa(index),
		Category:   category,
		Severity:   severity,
		State:      "open",
		ObservedAt: at,
		Evidence:   evidence,
		Action:     action,
	}
}

func validateIncident(i Incident) bool {
	validCategory := map[string]bool{"rpc-disagreement": true, "wrong-network": true, "stalled-chain": true, "disk-pressure": true, "invalid-peer-data": true, "failed-persistence": true, "duplicate-signer-risk": true, "operator-preflight": true}
	return i.ID != "" && len(i.ID) <= 128 && validCategory[i.Category] && (i.Severity == "warning" || i.Severity == "critical") && i.State == "open" && !i.ObservedAt.IsZero() && i.Evidence != "" && len(i.Evidence) <= 1024 && i.Action != "" && len(i.Action) <= 1024
}

func (s *Store) readIncidentHistory() (incidentDisk, error) {
	var state incidentDisk
	path := filepath.Join(s.dir, "incident-history.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return incidentDisk{SchemaVersion: 1, History: []Incident{}}, nil
	}
	if err := readStrictPrivate(path, 512<<10, &state); err != nil || state.SchemaVersion != 1 || len(state.History) > 128 {
		return state, errors.New("incident history is unavailable or invalid")
	}
	for _, incident := range state.History {
		if !validateIncident(incident) || incident.ObservedAt.After(state.CheckedAt) {
			return state, errors.New("incident history is unavailable or invalid")
		}
	}
	return state, nil
}

func (s *Store) inspectIncidents(ctx context.Context, includeDoctor bool) []Incident {
	now := time.Now().UTC()
	result := []Incident{}
	add := func(category, severity, evidence, action string) {
		result = append(result, incidentFor(category, severity, evidence, action, now, len(result)))
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &fs); err != nil || fs.Blocks == 0 {
		add("failed-persistence", "warning", "Free storage could not be measured for the operator state directory.", "Inspect the private state filesystem before creating a backup, update or new signing record.")
	} else if fs.Bavail < fs.Blocks/10 {
		add("disk-pressure", "critical", "Less than ten percent of the operator state filesystem is available.", "Stop nonessential writes, preserve current state and free reviewed storage before continuing lifecycle work.")
	}
	if _, err := os.Lstat(filepath.Join(s.dir, "state.json")); err == nil {
		var state diskState
		if err := readStrictPrivate(filepath.Join(s.dir, "state.json"), 4<<20, &state); err != nil {
			add("failed-persistence", "critical", "The persisted operator state file is unreadable or unsafe.", "Stop mutations and recover the state file from reviewed local evidence.")
		}
	} else if !os.IsNotExist(err) {
		add("failed-persistence", "critical", "The operator state path cannot be inspected safely.", "Inspect filesystem ownership and links before continuing.")
	}
	status := s.WorkerStatus(ctx)
	if status.Registered && status.State != "running" {
		add("stalled-chain", "warning", "The registered validator process is not currently reporting health.", "Review the process state and preflight checks before restarting it.")
	}
	if status.Health != nil {
		for family, chain := range status.Health.Chains {
			switch chain.Status {
			case "network-unverified":
				add("wrong-network", "critical", family+" stopped because its configured network identity could not be verified.", "Keep signing stopped and reconcile the RPC network, contract and saved binding.")
			case "stale", "unavailable":
				add("stalled-chain", "warning", family+" has no fresh chain progress.", "Check the private RPC and compare finalized height with an independent source.")
			}
		}
	}
	if registration, err := s.registration(); err == nil {
		_, cfg, cfgErr := workerConfig(registration.BaseDir)
		if cfgErr != nil {
			add("failed-persistence", "critical", "The registered validator configuration cannot be parsed or no longer matches safe key rules.", "Keep the worker stopped and restore the reviewed configuration.")
		} else {
			seenEVM, seenKoinos, seenEndpoint := map[string]bool{}, map[string]bool{}, map[string]bool{}
			for _, peer := range cfg.Bridge.Validators {
				evm := strings.ToLower(peer.EthereumAddress)
				invalid := ValidateEndpoint(peer.ApiUrl) != nil
				if _, err := addressBytes("evm", peer.EthereumAddress); err != nil {
					invalid = true
				}
				if _, err := addressBytes("koinos", peer.KoinosAddress); err != nil {
					invalid = true
				}
				if seenEVM[evm] || seenKoinos[peer.KoinosAddress] || seenEndpoint[peer.ApiUrl] {
					invalid = true
				}
				seenEVM[evm], seenKoinos[peer.KoinosAddress], seenEndpoint[peer.ApiUrl] = true, true, true
				if invalid {
					add("invalid-peer-data", "critical", "A configured peer has an invalid or duplicate public identity or endpoint.", "Review the private peer map; do not lower quorum or accept peer replies until it is corrected.")
					break
				}
			}
		}
	}
	lifecycle := s.ManagedLifecycle()
	if lifecycle.Signer.State == "invalid" {
		add("failed-persistence", "critical", "Managed signer state cannot be validated from its owner-only journal.", "Do not unlock. Preserve the journal and perform reviewed recovery.")
	}
	if lifecycle.Signer.State == "recovery-required" || lifecycle.Signer.State == "starting-or-stopping" {
		add("duplicate-signer-risk", "critical", "Managed journal and local process ownership do not establish one clean active signer.", "Fence prior processes and reconcile retained operations before another activation.")
	}
	if includeDoctor {
		report := s.Doctor(ctx)
		for _, check := range report.Checks {
			if check.Status == "failed" {
				add(incidentCategory(check), "critical", check.Message, "Resolve this preflight failure and run the incident checks again before lifecycle changes.")
			}
		}
	}
	return result
}

func (s *Store) IncidentState(ctx context.Context, refresh bool) IncidentInventory {
	s.incidentMu.Lock()
	defer s.incidentMu.Unlock()
	state, err := s.readIncidentHistory()
	result := IncidentInventory{SchemaVersion: 1, CheckedAt: state.CheckedAt, Current: s.inspectIncidents(ctx, false), History: state.History, Notice: "Incident evidence is local and sanitized. Endpoints, credentials and host identifiers are never returned. A clear check is point-in-time evidence only."}
	if err != nil {
		result.Problem = err.Error()
		result.History = []Incident{}
	}
	if !refresh {
		return result
	}
	now := time.Now().UTC()
	current := s.inspectIncidents(ctx, true)
	for index := range current {
		current[index].ObservedAt = now
		current[index].ID = incidentFor(current[index].Category, current[index].Severity, current[index].Evidence, current[index].Action, now, index).ID
	}
	history := append([]Incident{}, result.History...)
	history = append(history, current...)
	if len(history) > 128 {
		history = history[len(history)-128:]
	}
	sort.Slice(history, func(i, j int) bool { return history[i].ObservedAt.Before(history[j].ObservedAt) })
	disk := incidentDisk{SchemaVersion: 1, CheckedAt: now, History: history}
	raw, _ := json.Marshal(disk)
	if err := atomicFile(s.dir, "incident-history.json", raw); err != nil {
		result.Problem = "Incident checks completed but their history could not be persisted."
		result.Current = current
		result.CheckedAt = now
		return result
	}
	result.CheckedAt = now
	result.Current = current
	result.History = history
	return result
}
