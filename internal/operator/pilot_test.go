package operator

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pilotRequest(alias string, now time.Time) PilotAcceptanceRequest {
	evidence := make([]PilotControlEvidence, len(pilotControlDomains))
	for i, domain := range pilotControlDomains {
		evidence[i] = PilotControlEvidence{Domain: domain, Reference: strings.Repeat(string(rune('a'+i)), 64)}
	}
	return PilotAcceptanceRequest{
		SchemaVersion:   1,
		ID:              alias + "-acceptance",
		OperatorAlias:   alias,
		PolicyDigest:    strings.Repeat("f", 64),
		HostProfile:     "standard",
		AcceptedDuties:  append([]string(nil), pilotDuties...),
		ControlEvidence: evidence,
		ExpiresAt:       now.Add(30 * 24 * time.Hour),
	}
}

func pilotStores(t *testing.T, now time.Time) ([]*Store, []SignedPilotAcceptance) {
	t.Helper()
	stores := make([]*Store, 3)
	acceptances := make([]SignedPilotAcceptance, 3)
	for i := range stores {
		store, err := OpenStore(filepath.Join(t.TempDir(), "operator"))
		if err != nil {
			t.Fatal(err)
		}
		stores[i] = store
		t.Cleanup(func() { store.Close() })
		if _, err := store.InitializeMaintenance(); err != nil {
			t.Fatal(err)
		}
		acceptance, err := store.RecordPilotAcceptance(pilotRequest("operator-"+string(rune('a'+i)), now), now)
		if err != nil {
			t.Fatal(err)
		}
		acceptances[i] = acceptance
	}
	return stores, acceptances
}

func TestPilotAcceptancesArePortableButNotActivationAuthority(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	stores, acceptances := pilotStores(t, now)
	report, err := VerifyPilotAcceptances(acceptances, strings.Repeat("f", 64), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "signed-declarations-valid" || report.ActivationReady || len(report.Operators) != 3 || !strings.Contains(report.Notice, "Human review") {
		t.Fatal("signed declarations were treated as activation authority", report)
	}
	state := stores[0].PilotState(now.Add(time.Minute))
	if state["state"] != "locally-accepted" || state["activationReady"] != false {
		t.Fatal("local acceptance state unavailable or unsafe", state)
	}
	raw, _ := json.Marshal(state)
	if strings.Contains(string(raw), "seed") || strings.Contains(string(raw), stores[0].dir) {
		t.Fatal("pilot state leaked private identity or path")
	}
	info, err := os.Stat(filepath.Join(stores[0].dir, "maintenance", "pilot-acceptance.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("pilot acceptance was not stored privately")
	}
}

func TestPilotAcceptanceFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	_, acceptances := pilotStores(t, now)
	for _, test := range []struct {
		name   string
		change func([]SignedPilotAcceptance)
	}{
		{"duplicate-operator", func(values []SignedPilotAcceptance) { values[1] = values[0] }},
		{"tampered-duty", func(values []SignedPilotAcceptance) { values[0].Claim.AcceptedDuties[0] = "other" }},
		{"changed-policy", func(values []SignedPilotAcceptance) { values[0].Claim.PolicyDigest = strings.Repeat("e", 64) }},
		{"stale", func(values []SignedPilotAcceptance) { values[0].Claim.ExpiresAt = now.Add(-time.Minute) }},
		{"bad-evidence", func(values []SignedPilotAcceptance) { values[0].Claim.ControlEvidence[0].Reference = "server.example" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyOf := make([]SignedPilotAcceptance, len(acceptances))
			raw, _ := json.Marshal(acceptances)
			json.Unmarshal(raw, &copyOf)
			test.change(copyOf)
			if _, err := VerifyPilotAcceptances(copyOf, strings.Repeat("f", 64), now.Add(time.Minute)); err == nil {
				t.Fatal("unsafe pilot acceptance set verified")
			}
		})
	}
	if _, err := VerifyPilotAcceptances(acceptances[:2], strings.Repeat("f", 64), now); err == nil {
		t.Fatal("two operators satisfied the three-operator pilot")
	}
}

func TestPilotHTTPExportsOnlySignedPublicDeclaration(t *testing.T) {
	now := time.Now().UTC()
	stores, _ := pilotStores(t, now)
	api := NewServer(stores[0], strings.Repeat("a", 64), "127.0.0.1:3021", nil)
	response := instanceRequest(api, http.MethodGet, "/v1/pilot", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "locally-accepted") || strings.Contains(response.Body.String(), "seed") || strings.Contains(response.Body.String(), stores[0].dir) {
		t.Fatal(response.Code, response.Body.String())
	}
}
