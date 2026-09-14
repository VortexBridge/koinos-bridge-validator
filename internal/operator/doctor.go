package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

type DoctorCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type DoctorReport struct {
	CheckedAt          time.Time     `json:"checkedAt"`
	InstanceID         string        `json:"instanceId"`
	Revision           uint64        `json:"revision"`
	RegistrationDigest string        `json:"registrationDigest,omitempty"`
	Status             string        `json:"status"`
	SigningReady       bool          `json:"signingReady"`
	Checks             []DoctorCheck `json:"checks"`
	Notice             string        `json:"notice"`
}

// Doctor inspects only the registered local worker and this slot's saved
// bindings. It does not create directories, open databases, read signing files,
// execute the binary, reserve a process/port, or authorize a later start.
func (s *Store) Doctor(ctx context.Context) DoctorReport {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	s.mu.Lock()
	bindings := append([]Binding{}, s.data.Bindings...)
	revision := s.data.Revision
	s.mu.Unlock()
	report := DoctorReport{CheckedAt: time.Now().UTC(), InstanceID: s.InstanceID(), Revision: revision, Status: "checks-passed", Checks: []DoctorCheck{}, Notice: "Point-in-time observation preflight, not signing readiness or a start permit. Process and database ownership are checked again by the worker at startup. No state was changed."}
	add := func(id, status, message string) {
		report.Checks = append(report.Checks, DoctorCheck{id, status, message})
		if status == "failed" {
			report.Status = "attention-required"
		}
	}
	add("signing-readiness", "unknown", "Managed signing is disabled. Membership, peer/token mappings, finality, independent custody and recovery fencing still require separate verification.")
	r, err := s.registration()
	if err != nil {
		add("registration", "failed", "No readable registration. Use the local worker-register command with a private worker directory and reviewed binary digest.")
		return report
	}
	report.RegistrationDigest = registrationDigest(r)
	if r.Mode == "signing" {
		report.Notice = "Point-in-time attached signing-worker diagnostic, not proof of productive signing or a start permit. The independently reviewed host service retains start authority. No state was changed."
		add("registration", "passed", "An independently started signing worker is registered to this instance for observation and maintenance proof requests.")
	} else {
		add("registration", "passed", "A local observation worker is registered to this instance.")
	}
	info, err := os.Lstat(r.BaseDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		add("private-directory", "failed", "Worker directory must exist, be private (0700), and not be a symlink.")
		return report
	}
	add("private-directory", "passed", "Worker directory is private.")
	b, cfg, err := workerConfig(r.BaseDir)
	if err != nil {
		add("configuration", "failed", "Configuration is unreadable, contains unknown fields, inline keys or a reset flag. Review config.yml locally; diagnostics never include its contents.")
		return report
	}
	hash := sha256.Sum256(b)
	if hex.EncodeToString(hash[:]) != r.ConfigSHA256 || cfg.Bridge.InstanceID != r.InstanceID {
		add("configuration", "failed", "Configuration differs from the registered digest or identity. Restore the reviewed configuration; do not replace registration to bypass release review.")
		return report
	}
	add("configuration", "passed", "Configuration and worker identity match local registration. Key files are never opened by this check.")
	existingRouteData, databaseErr := worker.HasValidatorData(r.BaseDir)
	binding := networkBinding(cfg)
	if !binding.Enabled() {
		add("runtime-network-binding", "failed", "Worker configuration has no pinned network identities. Configure a new route directory with both network IDs; existing unbound checkpoints require reviewed migration.")
	} else if databaseErr != nil || worker.CheckNetworkBinding(filepath.Join(r.BaseDir, "bridge", ".operator"), binding, existingRouteData) != nil {
		add("runtime-network-binding", "failed", "Saved worker network/contract binding differs or cannot be verified. Inspect the route locally; do not relabel or reset its data.")
	} else {
		add("runtime-network-binding", "passed", "Network identities and contracts are pinned for this route. A compatible worker must verify identities around its read batches; this report does not attest an arbitrary registered executable's behavior.")
	}
	releaseOwnership, err := s.lockWorkerOwnership(r.BaseDir, r.InstanceID)
	if err != nil {
		add("local-ownership", "failed", "Local ownership cannot be established. Check other instance registrations for duplicate identities, directories or unavailable storage.")
	} else {
		releaseOwnership()
		add("local-ownership", "passed", "No other slot in this operator claims this worker identity or directory. This does not prove independence across hosts.")
	}
	binary := filepath.Join(s.dir, "worker-bin", r.BinarySHA256)
	raw, err := worker.ReadPrivateFile(binary, 256<<20)
	hash = sha256.Sum256(raw)
	info, statErr := os.Lstat(binary)
	if err != nil || statErr != nil || info.Mode().Perm()&0100 == 0 || hex.EncodeToString(hash[:]) != r.BinarySHA256 {
		add("binary", "failed", "The private executable is missing, not executable or differs from its registered SHA-256. Restore the reviewed artifact locally.")
	} else {
		add("binary", "passed", "Private executable bytes match the registered SHA-256. No executable was run; publisher provenance and compatibility are separate checks.")
	}
	host, port, err := net.SplitHostPort(cfg.Bridge.ApiUrl)
	p, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || p < 1 || p > 65535 || (host != "127.0.0.1" && host != "::1") {
		add("api-listener", "failed", "Set an explicit literal loopback worker API address and port. The legacy default listens on all interfaces.")
	} else {
		add("api-listener", "passed", "Worker API is configured on literal loopback. Port availability is not reserved by this check.")
	}
	control := filepath.Join(r.BaseDir, "bridge", ".operator")
	if worker.CheckRestoreFence(control, r.Mode != "signing") != nil {
		add("restore-review", "failed", "Restored state is unreviewed or incompatible with this worker mode. Complete the local reconciliation workflow before starting.")
	} else {
		add("restore-review", "passed", "No incompatible restore fence was detected. This is not proof that an old signer is fenced.")
	}
	mode, modeErr := worker.ReadPrivateFile(filepath.Join(control, "data-mode"), 32)
	_, markerErr := os.Lstat(filepath.Join(control, "data-mode"))
	_, metadataErr := os.Lstat(filepath.Join(r.BaseDir, "bridge", "metadata"))
	if (modeErr == nil && string(mode) == r.Mode) || (r.Mode == "observation-only" && os.IsNotExist(markerErr) && os.IsNotExist(metadataErr)) {
		add("data-mode", "passed", "The saved data mode matches this registration. Startup must acquire the actual database locks.")
	} else {
		add("data-mode", "failed", "Existing data does not match the registered worker mode. Inspect it locally; do not reset or relabel signing data.")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	type result struct {
		family      string
		observation Observation
	}
	results := make(chan result, 2)
	pending := 0
	for _, family := range []string{"evm", "koinos"} {
		contract, endpoint := cfg.Bridge.EthereumContract, cfg.Bridge.EthereumRpc
		if family == "koinos" {
			contract, endpoint = cfg.Bridge.KoinosContract, cfg.Bridge.KoinosRpc
		}
		if _, err := addressBytes(family, contract); err != nil || ValidateEndpoint(endpoint) != nil {
			add(family+"-binding", "failed", "Configure an explicit valid contract and private RPC endpoint locally.")
			continue
		}
		matches := []Binding{}
		for _, binding := range bindings {
			equal := binding.Profile.Contract == contract
			if family == "evm" {
				equal = strings.EqualFold(binding.Profile.Contract, contract)
			}
			if binding.Profile.Family == family && equal && binding.RPC == endpoint {
				matches = append(matches, binding)
			}
		}
		if len(matches) != 1 {
			add(family+"-binding", "failed", "Exactly one saved deployment must match the worker contract and exact private RPC endpoint. Add or reconcile that deployment in this instance.")
			continue
		}
		expected := cfg.Bridge.EthereumNetworkID
		if family == "koinos" {
			expected = cfg.Bridge.KoinosNetworkID
		}
		if expected != matches[0].Profile.NetworkID {
			add(family+"-binding", "failed", "The saved deployment network ID differs from the worker's pinned identity. Reconcile the route before observation.")
			continue
		}
		add(family+"-binding", "passed", "Worker contract and RPC match one saved deployment. Token and peer mappings have not been reconciled.")
		pending++
		go func(f string, binding Binding) { results <- result{f, Observe(ctx, binding)} }(family, matches[0])
	}
	// Append observations in stable family order even when RPCs complete in a
	// different order. Observe uses only allowlisted reads and sanitized errors.
	observations := map[string]Observation{}
	for i := 0; i < pending; i++ {
		r := <-results
		observations[r.family] = r.observation
	}
	for _, family := range []string{"evm", "koinos"} {
		if o, ok := observations[family]; ok {
			if !o.Complete || o.Status != "observed" {
				add(family+"-rpc", "failed", o.Message)
			} else {
				add(family+"-rpc", "passed", "Fresh contract reads match the deployment network identity and bridge protocol chain ID.")
				if o.CodeHash == "" || o.Finality != "finalized" {
					add(family+"-provenance-finality", "unknown", "These reads do not verify contract code and irreversible finality. Signing remains disabled.")
				}
			}
		}
	}
	current, _, _ := s.Summary()
	again, _, cfgErr := workerConfig(r.BaseDir)
	hash = sha256.Sum256(again)
	if current != revision || cfgErr != nil || hex.EncodeToString(hash[:]) != r.ConfigSHA256 {
		add("snapshot", "failed", "Configuration changed during preflight. Run the checks again after reviewing the change.")
	}
	return report
}
