package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const governanceJournalFile = "governance-journal.json"

type GovernanceAnchor struct {
	ObservedAt time.Time `json:"observedAt"`
	NetworkID  string    `json:"networkId"`
	Block      string    `json:"block"`
	BlockHash  string    `json:"blockHash"`
	Finality   string    `json:"finality"`
	CodeHash   string    `json:"codeHash"`
	Nonce      string    `json:"nonce"`
	Paused     *bool     `json:"paused"`
	Validators []string  `json:"validators"`
	Quorum     int       `json:"quorum"`
}

type GovernanceApproval struct {
	Signer    string    `json:"signer"`
	Signature string    `json:"signature"`
	AddedAt   time.Time `json:"addedAt"`
}

type GovernanceReceipt struct {
	TransactionID string    `json:"transactionId"`
	State         string    `json:"state"`
	SubmittedAt   time.Time `json:"submittedAt"`
	FinalizedAt   time.Time `json:"finalizedAt,omitempty"`
	Block         string    `json:"block,omitempty"`
	BlockHash     string    `json:"blockHash,omitempty"`
	Message       string    `json:"message"`
}

type GovernanceRoute struct {
	Profile   Profile              `json:"profile"`
	Payload   Payload              `json:"payload"`
	Anchor    GovernanceAnchor     `json:"anchor"`
	Approvals []GovernanceApproval `json:"approvals"`
	State     string               `json:"state"`
	Problem   string               `json:"problem,omitempty"`
	Receipt   *GovernanceReceipt   `json:"receipt,omitempty"`
}

type GovernanceEvent struct {
	At        time.Time `json:"at"`
	Action    string    `json:"action"`
	ProfileID string    `json:"profileId,omitempty"`
	Detail    string    `json:"detail"`
}

type GovernanceProposal struct {
	SchemaVersion int               `json:"schemaVersion"`
	ID            string            `json:"id"`
	Digest        string            `json:"digest"`
	CreatedAt     time.Time         `json:"createdAt"`
	State         string            `json:"state"`
	Action        string            `json:"action"`
	Pause         bool              `json:"pause"`
	Expiration    string            `json:"expiration"`
	Routes        []GovernanceRoute `json:"routes"`
	History       []GovernanceEvent `json:"history"`
	Notice        string            `json:"notice"`
}

type GovernanceInventory struct {
	SchemaVersion     int                  `json:"schemaVersion"`
	Proposals         []GovernanceProposal `json:"proposals"`
	SubmissionEnabled bool                 `json:"submissionEnabled"`
	Notice            string               `json:"notice"`
}

type CreateGovernanceProposal struct {
	ID         string   `json:"id"`
	ProfileIDs []string `json:"profileIds"`
	Pause      bool     `json:"pause"`
	Expiration string   `json:"expiration"`
}

type GovernanceSignatureEnvelope struct {
	SchemaVersion int    `json:"schemaVersion"`
	ProposalID    string `json:"proposalId"`
	ProfileDigest string `json:"profileDigest"`
	PayloadDigest string `json:"payloadDigest"`
	Signature     string `json:"signature"`
}

type GovernanceExecutor interface {
	Submit(context.Context, Binding, GovernanceProposal, GovernanceRoute) (GovernanceReceipt, error)
	Reconcile(context.Context, Binding, GovernanceProposal, GovernanceRoute, GovernanceReceipt) (GovernanceReceipt, error)
}

type governanceJournal struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Proposals     []GovernanceProposal `json:"proposals"`
}

func observationAnchor(o Observation) GovernanceAnchor {
	return GovernanceAnchor{ObservedAt: o.ObservedAt, NetworkID: o.NetworkID, Block: o.Block, BlockHash: o.BlockHash, Finality: o.Finality, CodeHash: o.CodeHash, Nonce: o.Nonce, Paused: o.Paused, Validators: append([]string{}, o.Validators...), Quorum: o.Quorum}
}

func validateGovernanceObservation(binding Binding, o Observation, now time.Time) error {
	if !o.Complete || !o.GovernanceReady || o.Status != "observed" || o.ProfileID != binding.Profile.ID {
		return errors.New("fresh governance-ready contract state is required")
	}
	if o.ObservedAt.IsZero() || o.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(o.ObservedAt) > 30*time.Second {
		return errors.New("contract observation is stale")
	}
	if o.NetworkID != binding.Profile.NetworkID || o.BridgeChainID != binding.Profile.BridgeChainID || o.CodeHash != binding.Profile.CodeHash || o.Finality != "finalized" || o.Nonce == "" || len(o.Validators) == 0 || o.Quorum != Quorum(len(o.Validators)) || o.Paused == nil {
		return errors.New("contract identity, code, finality or membership is incomplete")
	}
	if binding.Profile.Environment != "local" || !binding.Profile.Reviewed {
		return errors.New("governance workflow is restricted to reviewed local deployments")
	}
	return nil
}

func (s *Store) readGovernanceJournal() (governanceJournal, error) {
	journal := governanceJournal{SchemaVersion: 1, Proposals: []GovernanceProposal{}}
	path := filepath.Join(s.dir, governanceJournalFile)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return journal, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2*1024*1024 {
		return journal, errors.New("governance journal must be a private regular file under 2 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return journal, errors.New("governance journal unreadable")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 2*1024*1024))
	d.DisallowUnknownFields()
	if d.Decode(&journal) != nil || d.Decode(new(interface{})) != io.EOF || journal.SchemaVersion != 1 || len(journal.Proposals) > 100 {
		return governanceJournal{}, errors.New("governance journal corrupt; restore reviewed public proposal evidence")
	}
	return journal, nil
}

func (s *Store) writeGovernanceJournal(journal governanceJournal) error {
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil || len(encoded) > 2*1024*1024 {
		return errors.New("governance journal exceeds its bounded format")
	}
	if err := atomicFile(s.dir, governanceJournalFile, encoded); err != nil {
		return errors.New("cannot persist governance journal")
	}
	return nil
}

func proposalDigest(p GovernanceProposal) string {
	raw, _ := json.Marshal(p)
	var copy GovernanceProposal
	_ = json.Unmarshal(raw, &copy)
	copy.State = ""
	copy.Digest = ""
	copy.History = nil
	copy.Notice = ""
	for index := range copy.Routes {
		copy.Routes[index].Anchor = GovernanceAnchor{}
		copy.Routes[index].Approvals = nil
		copy.Routes[index].State = ""
		copy.Routes[index].Problem = ""
		copy.Routes[index].Receipt = nil
	}
	b, _ := json.Marshal(copy)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func payloadEquivalent(left, right Payload) bool {
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && string(a) == string(b)
}

func updateProposalState(p *GovernanceProposal, now time.Time) {
	expired := false
	if n, err := unsigned(p.Expiration, 64); err != nil || n.Cmp(bigInt(now.UnixMilli())) < 0 {
		expired = true
	}
	confirmed, ready, collecting, blocked := 0, 0, 0, 0
	for i := range p.Routes {
		route := &p.Routes[i]
		if route.Receipt != nil && route.Receipt.State == "finalized" {
			route.State = "finalized"
			confirmed++
			continue
		}
		if route.Receipt == nil && (route.Anchor.ObservedAt.IsZero() || route.Anchor.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(route.Anchor.ObservedAt) > 30*time.Second) {
			route.State = "stale"
			route.Problem = "Revalidate current nonce, membership and finalized state before continuing."
		}
		if route.State == "submitted" || route.State == "failed" || route.State == "stale" {
			blocked++
			continue
		}
		if expired {
			route.State = "expired"
			blocked++
		} else if len(route.Approvals) >= route.Anchor.Quorum {
			route.State = "ready"
			ready++
		} else {
			route.State = "collecting"
			collecting++
		}
	}
	switch {
	case confirmed == len(p.Routes) && confirmed > 0:
		p.State = "finalized"
		p.Notice = "Every route is finalized."
	case confirmed > 0:
		p.State = "partially-finalized"
		p.Notice = "One chain finalized before the other. Revalidate the remaining route and resume only while its nonce, membership and expiry still match."
	case blocked > 0:
		p.State = "blocked"
		p.Notice = "At least one route requires review before submission can continue."
	case ready == len(p.Routes) && ready > 0:
		p.State = "ready"
		p.Notice = "Every route has current quorum; each chain still requires separate submission and finality."
	case ready > 0 || collecting > 0:
		p.State = "collecting"
		p.Notice = "Collect current-member approvals independently for each exact route payload."
	}
}

func bigInt(value int64) *big.Int { return new(big.Int).SetInt64(value) }

func (s *Store) GovernanceInventory(submissionEnabled bool, now time.Time) GovernanceInventory {
	s.governanceMu.Lock()
	defer s.governanceMu.Unlock()
	journal, err := s.readGovernanceJournal()
	notice := "Portable public proposal evidence; contract state remains authoritative and is re-read before signatures or submission."
	if err != nil {
		return GovernanceInventory{SchemaVersion: 1, Proposals: []GovernanceProposal{}, SubmissionEnabled: submissionEnabled, Notice: err.Error()}
	}
	for index := range journal.Proposals {
		updateProposalState(&journal.Proposals[index], now)
	}
	sort.Slice(journal.Proposals, func(i, j int) bool { return journal.Proposals[i].CreatedAt.After(journal.Proposals[j].CreatedAt) })
	return GovernanceInventory{SchemaVersion: 1, Proposals: journal.Proposals, SubmissionEnabled: submissionEnabled, Notice: notice}
}

func (s *Store) CreateGovernance(ctx context.Context, req CreateGovernanceProposal, observe func(context.Context, Binding) Observation, now time.Time) (GovernanceProposal, error) {
	if !slug.MatchString(req.ID) || len(req.ProfileIDs) != 2 || req.ProfileIDs[0] == req.ProfileIDs[1] {
		return GovernanceProposal{}, errors.New("proposal needs a unique lowercase id and two distinct deployment profiles")
	}
	expiry, err := unsigned(req.Expiration, 64)
	if err != nil || expiry.Cmp(bigInt(now.Add(5*time.Minute).UnixMilli())) < 0 || expiry.Cmp(bigInt(now.Add(24*time.Hour).UnixMilli())) > 0 {
		return GovernanceProposal{}, errors.New("expiration must be 5 minutes to 24 hours in the future")
	}
	proposal := GovernanceProposal{SchemaVersion: 1, ID: req.ID, CreatedAt: now, Action: "set_pause", Pause: req.Pause, Expiration: req.Expiration, Routes: []GovernanceRoute{}, History: []GovernanceEvent{}}
	families := map[string]bool{}
	for _, id := range req.ProfileIDs {
		binding, ok := s.Binding(id)
		if !ok {
			return GovernanceProposal{}, errors.New("unknown deployment profile")
		}
		if families[binding.Profile.Family] {
			return GovernanceProposal{}, errors.New("paired proposal requires one Koinos and one EVM deployment")
		}
		families[binding.Profile.Family] = true
		observation := observe(ctx, binding)
		if err := validateGovernanceObservation(binding, observation, now); err != nil {
			return GovernanceProposal{}, fmt.Errorf("%s: %w", id, err)
		}
		payload, err := EncodeAction(binding.Profile, Action{Kind: "set_pause", Pause: &proposal.Pause, Nonce: observation.Nonce, Expiration: req.Expiration})
		if err != nil {
			return GovernanceProposal{}, err
		}
		proposal.Routes = append(proposal.Routes, GovernanceRoute{Profile: binding.Profile, Payload: payload, Anchor: observationAnchor(observation), Approvals: []GovernanceApproval{}, State: "collecting"})
	}
	if !families["evm"] || !families["koinos"] {
		return GovernanceProposal{}, errors.New("paired proposal requires one Koinos and one EVM deployment")
	}
	proposal.Digest = proposalDigest(proposal)
	proposal.History = append(proposal.History, GovernanceEvent{At: now, Action: "proposal-created", Detail: proposal.Digest})
	updateProposalState(&proposal, now)
	s.governanceMu.Lock()
	defer s.governanceMu.Unlock()
	journal, err := s.readGovernanceJournal()
	if err != nil {
		return GovernanceProposal{}, err
	}
	for _, existing := range journal.Proposals {
		if existing.ID == proposal.ID {
			return GovernanceProposal{}, errors.New("proposal id already exists")
		}
	}
	if len(journal.Proposals) >= 100 {
		return GovernanceProposal{}, errors.New("governance journal full; reviewed archival required")
	}
	journal.Proposals = append(journal.Proposals, proposal)
	if err := s.writeGovernanceJournal(journal); err != nil {
		return GovernanceProposal{}, err
	}
	return proposal, nil
}

func findProposal(journal *governanceJournal, id string) (*GovernanceProposal, error) {
	for i := range journal.Proposals {
		if journal.Proposals[i].ID == id {
			return &journal.Proposals[i], nil
		}
	}
	return nil, errors.New("unknown governance proposal")
}

func findRoute(proposal *GovernanceProposal, profileDigest string) (*GovernanceRoute, error) {
	for i := range proposal.Routes {
		if proposal.Routes[i].Profile.Digest() == profileDigest {
			return &proposal.Routes[i], nil
		}
	}
	return nil, errors.New("signature or action targets the wrong proposal route")
}

func (s *Store) AddGovernanceSignature(ctx context.Context, envelope GovernanceSignatureEnvelope, observe func(context.Context, Binding) Observation, now time.Time) (GovernanceProposal, error) {
	if envelope.SchemaVersion != 1 || !slug.MatchString(envelope.ProposalID) || !hexHash.MatchString(envelope.ProfileDigest) || !hexHash.MatchString(envelope.PayloadDigest) || strings.TrimSpace(envelope.Signature) == "" {
		return GovernanceProposal{}, errors.New("invalid signature envelope")
	}
	s.governanceMu.Lock()
	defer s.governanceMu.Unlock()
	journal, err := s.readGovernanceJournal()
	if err != nil {
		return GovernanceProposal{}, err
	}
	proposal, err := findProposal(&journal, envelope.ProposalID)
	if err != nil {
		return GovernanceProposal{}, err
	}
	route, err := findRoute(proposal, envelope.ProfileDigest)
	if err != nil || route.Payload.Digest != envelope.PayloadDigest {
		return GovernanceProposal{}, errors.New("signature envelope does not match the exact proposal payload")
	}
	binding, ok := s.Binding(route.Profile.ID)
	if !ok || binding.Profile != route.Profile {
		return GovernanceProposal{}, errors.New("local deployment profile changed")
	}
	observation := observe(ctx, binding)
	if err := validateGovernanceObservation(binding, observation, now); err != nil {
		return GovernanceProposal{}, err
	}
	signatures := make([]string, 0, len(route.Approvals)+1)
	for _, approval := range route.Approvals {
		signatures = append(signatures, approval.Signature)
	}
	signatures = append(signatures, envelope.Signature)
	signers, ready, err := CheckApprovals(route.Profile, route.Payload, signatures, observation.Validators, observation.Nonce, now)
	if err != nil {
		return GovernanceProposal{}, err
	}
	signer := signers[len(signers)-1]
	route.Approvals = append(route.Approvals, GovernanceApproval{Signer: signer, Signature: envelope.Signature, AddedAt: now})
	route.Anchor = observationAnchor(observation)
	route.Problem = ""
	if ready {
		route.State = "ready"
	}
	proposal.History = append(proposal.History, GovernanceEvent{At: now, Action: "signature-accepted", ProfileID: route.Profile.ID, Detail: signer})
	updateProposalState(proposal, now)
	result := *proposal
	if err := s.writeGovernanceJournal(journal); err != nil {
		return GovernanceProposal{}, err
	}
	return result, nil
}

func (s *Store) SubmitGovernance(ctx context.Context, proposalID, profileID string, observe func(context.Context, Binding) Observation, executor GovernanceExecutor, now time.Time) (GovernanceProposal, error) {
	if executor == nil {
		return GovernanceProposal{}, errors.New("governance submission is unavailable; configure a reviewed local-chain executor")
	}
	s.governanceMu.Lock()
	defer s.governanceMu.Unlock()
	journal, err := s.readGovernanceJournal()
	if err != nil {
		return GovernanceProposal{}, err
	}
	proposal, err := findProposal(&journal, proposalID)
	if err != nil {
		return GovernanceProposal{}, err
	}
	var route *GovernanceRoute
	for i := range proposal.Routes {
		if proposal.Routes[i].Profile.ID == profileID {
			route = &proposal.Routes[i]
		}
	}
	if route == nil || (route.Receipt != nil && route.Receipt.State != "submitting") {
		return GovernanceProposal{}, errors.New("unknown or already submitted governance route")
	}
	binding, ok := s.Binding(route.Profile.ID)
	if !ok || binding.Profile != route.Profile {
		return GovernanceProposal{}, errors.New("local deployment profile changed")
	}
	observation := observe(ctx, binding)
	if err := validateGovernanceObservation(binding, observation, now); err != nil {
		return GovernanceProposal{}, err
	}
	signatures := make([]string, len(route.Approvals))
	for i, approval := range route.Approvals {
		signatures[i] = approval.Signature
	}
	if _, err := ValidateApprovals(route.Profile, route.Payload, signatures, observation.Validators, observation.Nonce, now); err != nil {
		route.State = "stale"
		route.Problem = err.Error()
		proposal.History = append(proposal.History, GovernanceEvent{At: now, Action: "submission-rejected", ProfileID: profileID, Detail: err.Error()})
		_ = s.writeGovernanceJournal(journal)
		return GovernanceProposal{}, err
	}
	if route.Receipt == nil {
		h := sha256.Sum256([]byte(proposal.Digest + ":" + profileID + ":" + route.Payload.Digest))
		attempt := GovernanceReceipt{TransactionID: "attempt-" + hex.EncodeToString(h[:]), State: "submitting", SubmittedAt: now, Message: "Durable submission intent recorded; retry uses the same attempt identity."}
		route.Receipt = &attempt
		route.State = "submitted"
		proposal.History = append(proposal.History, GovernanceEvent{At: now, Action: "submission-intent-recorded", ProfileID: profileID, Detail: attempt.TransactionID})
		if err := s.writeGovernanceJournal(journal); err != nil {
			return GovernanceProposal{}, err
		}
	}
	receipt, err := executor.Submit(ctx, binding, *proposal, *route)
	if err != nil {
		route.State = "failed"
		route.Problem = "The reviewed executor did not accept this route."
		proposal.History = append(proposal.History, GovernanceEvent{At: now, Action: "submission-failed", ProfileID: profileID, Detail: "executor rejected the reviewed route"})
		_ = s.writeGovernanceJournal(journal)
		return GovernanceProposal{}, errors.New("governance submission failed")
	}
	if receipt.TransactionID == "" || receipt.State != "submitted" || receipt.SubmittedAt.IsZero() {
		return GovernanceProposal{}, errors.New("governance executor returned an invalid receipt")
	}
	route.Receipt = &receipt
	route.State = "submitted"
	route.Problem = ""
	proposal.History = append(proposal.History, GovernanceEvent{At: now, Action: "route-submitted", ProfileID: profileID, Detail: receipt.TransactionID})
	updateProposalState(proposal, now)
	result := *proposal
	if err := s.writeGovernanceJournal(journal); err != nil {
		return GovernanceProposal{}, err
	}
	return result, nil
}

func (s *Store) ReconcileGovernance(ctx context.Context, proposalID string, executor GovernanceExecutor, now time.Time) (GovernanceProposal, error) {
	if executor == nil {
		return GovernanceProposal{}, errors.New("governance receipt reconciliation is unavailable")
	}
	s.governanceMu.Lock()
	defer s.governanceMu.Unlock()
	journal, err := s.readGovernanceJournal()
	if err != nil {
		return GovernanceProposal{}, err
	}
	proposal, err := findProposal(&journal, proposalID)
	if err != nil {
		return GovernanceProposal{}, err
	}
	for i := range proposal.Routes {
		route := &proposal.Routes[i]
		if route.Receipt == nil || route.Receipt.State == "finalized" {
			continue
		}
		binding, ok := s.Binding(route.Profile.ID)
		if !ok || binding.Profile != route.Profile {
			return GovernanceProposal{}, errors.New("local deployment profile changed")
		}
		receipt, err := executor.Reconcile(ctx, binding, *proposal, *route, *route.Receipt)
		if err != nil {
			return GovernanceProposal{}, errors.New("governance receipt reconciliation failed")
		}
		if receipt.TransactionID != route.Receipt.TransactionID || (receipt.State != "submitted" && receipt.State != "finalized" && receipt.State != "failed") {
			return GovernanceProposal{}, errors.New("governance executor returned a mismatched receipt")
		}
		route.Receipt = &receipt
		route.State = receipt.State
		if receipt.State == "failed" {
			route.Problem = receipt.Message
		} else {
			route.Problem = ""
		}
		if receipt.State == "finalized" {
			proposal.History = append(proposal.History, GovernanceEvent{At: now, Action: "route-finalized", ProfileID: route.Profile.ID, Detail: receipt.TransactionID})
		}
	}
	updateProposalState(proposal, now)
	result := *proposal
	if err := s.writeGovernanceJournal(journal); err != nil {
		return GovernanceProposal{}, err
	}
	return result, nil
}

func (s *Store) RevalidateGovernance(ctx context.Context, proposalID string, observe func(context.Context, Binding) Observation, now time.Time) (GovernanceProposal, error) {
	s.governanceMu.Lock()
	defer s.governanceMu.Unlock()
	journal, err := s.readGovernanceJournal()
	if err != nil {
		return GovernanceProposal{}, err
	}
	proposal, err := findProposal(&journal, proposalID)
	if err != nil {
		return GovernanceProposal{}, err
	}
	for index := range proposal.Routes {
		route := &proposal.Routes[index]
		if route.Receipt != nil {
			continue
		}
		binding, ok := s.Binding(route.Profile.ID)
		if !ok || binding.Profile != route.Profile {
			route.State = "stale"
			route.Problem = "The locally reviewed deployment profile changed."
			continue
		}
		observation := observe(ctx, binding)
		if err := validateGovernanceObservation(binding, observation, now); err != nil {
			route.State = "stale"
			route.Problem = err.Error()
			continue
		}
		signatures := make([]string, len(route.Approvals))
		for approvalIndex, approval := range route.Approvals {
			signatures[approvalIndex] = approval.Signature
		}
		_, ready, err := CheckApprovals(route.Profile, route.Payload, signatures, observation.Validators, observation.Nonce, now)
		if err != nil {
			route.State = "stale"
			route.Problem = err.Error()
			continue
		}
		route.Anchor = observationAnchor(observation)
		route.Problem = ""
		if ready {
			route.State = "ready"
		} else {
			route.State = "collecting"
		}
	}
	proposal.History = append(proposal.History, GovernanceEvent{At: now, Action: "proposal-revalidated", Detail: proposal.Digest})
	updateProposalState(proposal, now)
	result := *proposal
	if err := s.writeGovernanceJournal(journal); err != nil {
		return GovernanceProposal{}, err
	}
	return result, nil
}

func (s *Store) ImportGovernance(ctx context.Context, imported GovernanceProposal, observe func(context.Context, Binding) Observation, now time.Time) (GovernanceProposal, error) {
	if imported.SchemaVersion != 1 || !slug.MatchString(imported.ID) || !hexHash.MatchString(imported.Digest) || imported.Action != "set_pause" || len(imported.Routes) != 2 || imported.CreatedAt.IsZero() || imported.CreatedAt.After(now.Add(5*time.Second)) {
		return GovernanceProposal{}, errors.New("invalid portable governance proposal")
	}
	if imported.Expiration == "" {
		return GovernanceProposal{}, errors.New("portable proposal has no expiration")
	}
	clean := GovernanceProposal{SchemaVersion: 1, ID: imported.ID, CreatedAt: imported.CreatedAt, Action: "set_pause", Pause: imported.Pause, Expiration: imported.Expiration, Routes: []GovernanceRoute{}, History: []GovernanceEvent{}}
	families := map[string]bool{}
	for _, source := range imported.Routes {
		binding, ok := s.Binding(source.Profile.ID)
		if !ok || binding.Profile != source.Profile || families[source.Profile.Family] {
			return GovernanceProposal{}, errors.New("portable proposal does not match distinct local deployment profiles")
		}
		families[source.Profile.Family] = true
		observation := observe(ctx, binding)
		if err := validateGovernanceObservation(binding, observation, now); err != nil {
			return GovernanceProposal{}, err
		}
		expected, err := EncodeAction(binding.Profile, Action{Kind: "set_pause", Pause: &clean.Pause, Nonce: observation.Nonce, Expiration: clean.Expiration})
		if err != nil || !payloadEquivalent(expected, source.Payload) {
			return GovernanceProposal{}, errors.New("portable proposal payload is stale, changed or for another domain")
		}
		signatures := make([]string, len(source.Approvals))
		for i, approval := range source.Approvals {
			signatures[i] = approval.Signature
		}
		signers, _, err := CheckApprovals(binding.Profile, expected, signatures, observation.Validators, observation.Nonce, now)
		if err != nil {
			return GovernanceProposal{}, err
		}
		approvals := make([]GovernanceApproval, len(signers))
		for i, signer := range signers {
			approvals[i] = GovernanceApproval{Signer: signer, Signature: signatures[i], AddedAt: now}
		}
		clean.Routes = append(clean.Routes, GovernanceRoute{Profile: binding.Profile, Payload: expected, Anchor: observationAnchor(observation), Approvals: approvals, State: "collecting"})
	}
	if !families["evm"] || !families["koinos"] {
		return GovernanceProposal{}, errors.New("portable proposal must pair Koinos and EVM routes")
	}
	clean.Digest = proposalDigest(clean)
	if clean.Digest != imported.Digest {
		return GovernanceProposal{}, errors.New("portable proposal digest does not match its canonical public content")
	}
	clean.History = append(clean.History, GovernanceEvent{At: now, Action: "proposal-imported", Detail: clean.Digest})
	updateProposalState(&clean, now)
	s.governanceMu.Lock()
	defer s.governanceMu.Unlock()
	journal, err := s.readGovernanceJournal()
	if err != nil {
		return GovernanceProposal{}, err
	}
	for index := range journal.Proposals {
		existing := &journal.Proposals[index]
		if existing.ID == clean.ID {
			if existing.Digest != clean.Digest || proposalDigest(*existing) != clean.Digest {
				return GovernanceProposal{}, errors.New("proposal id conflicts with different public content")
			}
			for routeIndex := range existing.Routes {
				target := &existing.Routes[routeIndex]
				var source *GovernanceRoute
				for candidateIndex := range clean.Routes {
					if clean.Routes[candidateIndex].Profile.Digest() == target.Profile.Digest() {
						source = &clean.Routes[candidateIndex]
					}
				}
				if source == nil {
					return GovernanceProposal{}, errors.New("portable proposal route set changed")
				}
				seen := map[string]bool{}
				for _, approval := range target.Approvals {
					seen[approval.Signer] = true
				}
				for _, approval := range source.Approvals {
					if !seen[approval.Signer] {
						target.Approvals = append(target.Approvals, approval)
						seen[approval.Signer] = true
					}
				}
				combined := make([]string, len(target.Approvals))
				for approvalIndex, approval := range target.Approvals {
					combined[approvalIndex] = approval.Signature
				}
				if _, _, err := CheckApprovals(target.Profile, target.Payload, combined, source.Anchor.Validators, source.Anchor.Nonce, now); err != nil {
					return GovernanceProposal{}, errors.New("merged proposal contains an approval that is no longer valid")
				}
				target.Anchor = source.Anchor
			}
			existing.History = append(existing.History, GovernanceEvent{At: now, Action: "proposal-import-merged", Detail: clean.Digest})
			updateProposalState(existing, now)
			result := *existing
			if err := s.writeGovernanceJournal(journal); err != nil {
				return GovernanceProposal{}, err
			}
			return result, nil
		}
	}
	journal.Proposals = append(journal.Proposals, clean)
	if err := s.writeGovernanceJournal(journal); err != nil {
		return GovernanceProposal{}, err
	}
	return clean, nil
}

// ReadGovernanceProposal reads public portable evidence. Signing authority is
// established separately from current local configuration and chain state.
func ReadGovernanceProposal(path string) (GovernanceProposal, error) {
	var proposal GovernanceProposal
	if path == "" || !filepath.IsAbs(path) {
		return proposal, errors.New("governance proposal needs an absolute file path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
		return proposal, errors.New("governance proposal must be a regular file under 2 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return proposal, errors.New("governance proposal unreadable")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 2*1024*1024))
	d.DisallowUnknownFields()
	if d.Decode(&proposal) != nil || d.Decode(new(interface{})) != io.EOF {
		return GovernanceProposal{}, errors.New("governance proposal JSON is invalid or has unknown fields")
	}
	return proposal, nil
}

func containsGovernanceMember(profile Profile, members []string, signer string) bool {
	if _, err := addressBytes(profile.Family, signer); err != nil {
		return false
	}
	for _, member := range members {
		if profile.Family == "evm" {
			if strings.EqualFold(member, signer) {
				return true
			}
		} else if member == signer {
			return true
		}
	}
	return false
}

func (s *Store) reviewGovernanceSigning(ctx context.Context, proposal GovernanceProposal, profileID, signer string, observe func(context.Context, Binding) Observation, now time.Time) (GovernanceRoute, error) {
	if proposal.SchemaVersion != 1 || proposal.Digest == "" || proposal.Digest != proposalDigest(proposal) || proposal.Action != "set_pause" || len(proposal.Routes) != 2 {
		return GovernanceRoute{}, errors.New("portable proposal digest or schema is invalid")
	}
	var route *GovernanceRoute
	for i := range proposal.Routes {
		if proposal.Routes[i].Profile.ID == profileID {
			route = &proposal.Routes[i]
		}
	}
	if route == nil || route.Receipt != nil {
		return GovernanceRoute{}, errors.New("requested route is absent or already submitted")
	}
	binding, ok := s.Binding(profileID)
	if !ok || binding.Profile != route.Profile {
		return GovernanceRoute{}, errors.New("proposal route differs from the locally reviewed deployment")
	}
	observation := observe(ctx, binding)
	if err := validateGovernanceObservation(binding, observation, now); err != nil {
		return GovernanceRoute{}, err
	}
	expected, err := EncodeAction(binding.Profile, Action{Kind: "set_pause", Pause: &proposal.Pause, Nonce: observation.Nonce, Expiration: proposal.Expiration})
	if err != nil || !payloadEquivalent(expected, route.Payload) {
		return GovernanceRoute{}, errors.New("proposal payload is stale, changed or for another domain")
	}
	if _, _, err := CheckApprovals(binding.Profile, expected, nil, observation.Validators, observation.Nonce, now); err != nil {
		return GovernanceRoute{}, err
	}
	if !containsGovernanceMember(binding.Profile, observation.Validators, signer) {
		return GovernanceRoute{}, errors.New("local signing identity is not a current validator on this route")
	}
	copy := *route
	copy.Anchor = observationAnchor(observation)
	return copy, nil
}

// ReviewGovernanceSigning is the only signing preflight exposed to terminal
// commands. It reconstructs set_pause from the proposal and fresh chain state;
// callers never supply an arbitrary digest.
func (s *Store) ReviewGovernanceSigning(ctx context.Context, proposal GovernanceProposal, profileID, signer string, observe ObservationProvider, now time.Time) (GovernanceRoute, error) {
	if observe == nil {
		observe = Observe
	}
	return s.reviewGovernanceSigning(ctx, proposal, profileID, signer, observe, now)
}

func GovernanceSignature(route GovernanceRoute, signature string) (GovernanceSignatureEnvelope, error) {
	if _, err := RecoverSigner(route.Profile, route.Payload, signature); err != nil {
		return GovernanceSignatureEnvelope{}, err
	}
	return GovernanceSignatureEnvelope{SchemaVersion: 1, ProposalID: "", ProfileDigest: route.Profile.Digest(), PayloadDigest: route.Payload.Digest, Signature: signature}, nil
}
