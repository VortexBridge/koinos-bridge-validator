// vortex-operator is the private operator control plane without bridge signing keys. The legacy
// validator binary remains a separate process with a separate lifecycle.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/governanceexec"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/keyvault"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/managed"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/operator"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vortex-operator:", err)
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("vortex-operator", flag.ContinueOnError)
	dir := flags.String("data", "", "private operator state directory (required)")
	instance := flags.String("instance", "", "local instance slot; omitted uses default (serve and token-path use the root)")
	listen := flags.String("listen", "127.0.0.1:3021", "loopback listen address")
	origins := flags.String("origins", "http://127.0.0.1:5174", "comma-separated exact trusted operator-UI origins")
	workerBase := flags.String("worker-base", "", "private validator base directory for local registration")
	workerBinary := flags.String("worker-binary", "", "reviewed local validator executable")
	workerSHA := flags.String("worker-sha256", "", "reviewed validator executable digest")
	releaseFile := flags.String("release-file", "", "local signed release JSON")
	artifactFile := flags.String("artifact-file", "", "local artifact bytes to verify and stage")
	artifactPlatform := flags.String("artifact-platform", "", "platform named in signed release")
	candidateDigest := flags.String("release-digest", "", "exact staged release digest")
	checkerPath := flags.String("candidate-checker", "", "reviewed Linux candidate checker executable")
	checkerHash := flags.String("checker-sha256", "", "reviewed checker digest")
	backupFile := flags.String("backup-file", "", "absolute encrypted backup file path")
	restoreBase := flags.String("restore-base", "", "absolute new validator directory for restore")
	recipient := flags.String("recovery-recipient", "", "public age X25519 recovery recipient")
	identity := flags.String("recovery-identity-file", "", "private local age recovery identity file (restore only)")
	cryptoPath := flags.String("backup-crypto", "", "reviewed local backup crypto helper executable")
	cryptoHash := flags.String("backup-crypto-sha256", "", "reviewed backup crypto executable digest")
	backupDigest := flags.String("backup-digest", "", "exact recovered backup manifest digest")
	reviewNote := flags.String("review-note", "", "non-secret restore checkpoint/configuration review note")
	ethereumHeight := flags.String("review-ethereum-height", "", "exact restored Ethereum checkpoint in decimal")
	koinosHeight := flags.String("review-koinos-height", "", "exact restored Koinos checkpoint in decimal")
	participationFile := flags.String("participation-file", "", "private participation request or response array JSON")
	stageEvidenceFile := flags.String("stage-evidence-file", "", "private reviewed peer, API and operator-UI stage evidence JSON")
	participationID := flags.String("participation-id", "", "unique lowercase participation challenge ID")
	maintenanceFile := flags.String("maintenance-file", "", "private portable maintenance envelope JSON")
	maintenanceDigest := flags.String("maintenance-digest", "", "exact locally reviewed maintenance plan digest")
	maintenanceRevision := flags.String("maintenance-revision", "", "current local revision for endorsement")
	pilotClaimFile := flags.String("pilot-claim-file", "", "private reviewed pilot acceptance request JSON")
	pilotAcceptancesFile := flags.String("pilot-acceptances-file", "", "private array of three signed pilot acceptances")
	pilotPolicyDigest := flags.String("pilot-policy-digest", "", "exact reviewed pilot policy SHA-256")
	pilotExerciseFile := flags.String("pilot-exercise-file", "", "private reviewed pilot exercise request JSON")
	pilotReceiptsFile := flags.String("pilot-receipts-file", "", "private array of signed pilot exercise receipts")
	waveResultFile := flags.String("wave-result-file", "", "private signed maintenance wave-result JSON")
	waveResultID := flags.String("wave-result-id", "", "unique lowercase local wave-result ID")
	progressID := flags.String("progress-id", "", "completed local signing-progress window ID")
	governanceFile := flags.String("governance-file", "", "absolute portable governance proposal JSON")
	governanceProposalID := flags.String("governance-proposal-id", "", "durable governance proposal ID")
	governanceProfile := flags.String("governance-profile", "", "exact local deployment profile to sign")
	signingVault := flags.String("signing-vault", "", "absolute encrypted validator signing vault")
	expectedEVM := flags.String("expected-evm-signer", "", "reviewed EVM validator identity pinned to the vault")
	expectedKoinos := flags.String("expected-koinos-signer", "", "reviewed Koinos validator identity pinned to the vault")
	unlockFD := flags.Int("unlock-passphrase-fd", -1, "inherited pipe for the vault passphrase; omitted for a hidden terminal prompt")
	koinosReplica := flags.String("koinos-finality-replica", "", "private Koinos replica pinned to the live irreversible block")
	koinosMembershipSeed := flags.String("koinos-membership-seed", "", "one reviewed current Koinos validator address used to enumerate membership")
	payerVault := flags.String("payer-vault", "", "absolute encrypted two-chain transaction-payer vault")
	expectedEVMPayer := flags.String("expected-evm-payer", "", "reviewed EVM transaction-payer identity pinned to the payer vault")
	expectedKoinosPayer := flags.String("expected-koinos-payer", "", "reviewed Koinos transaction-payer identity pinned to the payer vault")
	governanceExecutorData := flags.String("governance-executor-data", "", "absolute mode-0700 directory for exact prepared governance transactions")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("--data is required; use a new private directory, separate from validator data")
	}
	command := "serve"
	if flags.NArg() > 0 {
		command = flags.Arg(0)
	}
	if flags.NArg() > 1 {
		return errors.New("provide one command; place all flags before it")
	}
	if command != "serve" && command != "status" && command != "token-path" && command != "worker-register" && command != "release-stage" && command != "release-adopt" && command != "candidate-test" && command != "backup-configure" && command != "backup-create" && command != "backup-restore" && command != "restore-review" && command != "instance-create" && command != "instances" && command != "doctor" && command != "worker-prepare" && command != "maintenance-init" && command != "maintenance-status" && command != "maintenance-verify" && command != "maintenance-endorse" && command != "pilot-accept" && command != "pilot-status" && command != "pilot-verify" && command != "pilot-record" && command != "pilot-audit" && command != "participation-begin" && command != "participation-respond" && command != "participation-verify" && command != "participation-status" && command != "participation-stage-record" && command != "wave-result-create" && command != "wave-result-verify" && command != "wave-results" && command != "governance-sign" && command != "governance-submit" && command != "governance-reconcile" {
		return errors.New("commands: serve, status, token-path, worker-register, release-stage, release-adopt, candidate-test, backup-configure, backup-create, backup-restore, restore-review, instance-create, instances, doctor, worker-prepare, maintenance-init, maintenance-status, maintenance-verify, maintenance-endorse, pilot-accept, pilot-status, pilot-verify, pilot-record, pilot-audit, participation-begin, participation-respond, participation-verify, participation-status, participation-stage-record, wave-result-create, wave-result-verify, wave-results, governance-sign, governance-submit, governance-reconcile")
	}
	s, err := operator.OpenStore(*dir)
	if err != nil {
		return err
	}
	defer s.Close()
	if (*koinosReplica == "") != (*koinosMembershipSeed == "") {
		return errors.New("Koinos finalized governance reads require both --koinos-finality-replica and --koinos-membership-seed")
	}
	observe := operator.ObservationProvider(operator.Observe)
	if *koinosReplica != "" {
		observe = managed.GovernanceObservationProvider(*koinosReplica, *koinosMembershipSeed)
	}
	if command == "instance-create" {
		created, err := s.CreateInstance(*instance)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"id": *instance, "operatorInstanceId": created.InstanceID(), "state": "created", "mode": "observation-only"})
	}
	if command == "instances" {
		return json.NewEncoder(os.Stdout).Encode(s.LocalInstances())
	}
	if *instance != "" && *instance != "default" {
		if command == "serve" || command == "token-path" {
			return errors.New("serve and token-path use the root operator; select an instance in the console")
		}
		selected, ok := s.LocalInstance(*instance)
		if !ok {
			return errors.New("unknown local instance; create it using instance-create first")
		}
		s = selected
	}
	if command == "governance-sign" {
		if *expectedEVM == "" || *expectedKoinos == "" || *signingVault == "" || *governanceProfile == "" {
			return errors.New("governance signing requires the proposal, exact profile, encrypted vault and both reviewed signer identities")
		}
		proposal, err := operator.ReadGovernanceProposal(*governanceFile)
		if err != nil {
			return err
		}
		binding, ok := s.Binding(*governanceProfile)
		if !ok {
			return errors.New("unknown governance deployment profile")
		}
		signer := *expectedEVM
		if binding.Profile.Family == "koinos" {
			signer = *expectedKoinos
		}
		route, err := s.ReviewGovernanceSigning(context.Background(), proposal, *governanceProfile, signer, observe, time.Now().UTC())
		if err != nil {
			return err
		}
		keys, _, err := keyvault.Unlock(*signingVault, *expectedEVM, *expectedKoinos, func() ([]byte, error) { return keyvault.ReadSecret(*unlockFD, "Validator vault passphrase") })
		if err != nil {
			return err
		}
		defer keys.Close()
		digest, _ := hex.DecodeString(route.Payload.Digest)
		var signature string
		if route.Profile.Family == "evm" {
			raw, err := crypto.Sign(digest, keys.EVM)
			if err != nil {
				return errors.New("cannot sign reviewed EVM governance payload")
			}
			raw[64] += 27
			signature = "0x" + hex.EncodeToString(raw)
			keyvault.Clear(raw)
		} else {
			key, _ := btcec.PrivKeyFromBytes(btcec.S256(), keys.Koinos)
			raw, err := btcec.SignCompact(btcec.S256(), key, digest, true)
			if err != nil {
				return errors.New("cannot sign reviewed Koinos governance payload")
			}
			signature = base64.URLEncoding.EncodeToString(raw)
			keyvault.Clear(raw)
		}
		envelope, err := operator.GovernanceSignature(route, signature)
		if err != nil {
			return err
		}
		envelope.ProposalID = proposal.ID
		return json.NewEncoder(os.Stdout).Encode(envelope)
	}
	if command == "governance-submit" {
		if *governanceProposalID == "" || *governanceProfile == "" || *payerVault == "" || *expectedEVMPayer == "" || *expectedKoinosPayer == "" || *governanceExecutorData == "" {
			return errors.New("governance submission requires proposal, exact profile, payer vault, both reviewed payer identities and private executor data")
		}
		now := time.Now().UTC()
		if _, err := s.ReviewGovernanceSubmission(context.Background(), *governanceProposalID, *governanceProfile, observe, now); err != nil {
			return err
		}
		keys, _, err := keyvault.Unlock(*payerVault, *expectedEVMPayer, *expectedKoinosPayer, func() ([]byte, error) { return keyvault.ReadSecret(*unlockFD, "Transaction-payer vault passphrase") })
		if err != nil {
			return err
		}
		defer keys.Close()
		executor, err := governanceexec.New(*governanceExecutorData, keys)
		if err != nil {
			return err
		}
		proposal, err := s.SubmitGovernance(context.Background(), *governanceProposalID, *governanceProfile, observe, executor, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(proposal)
	}
	if command == "governance-reconcile" {
		if *governanceProposalID == "" || *governanceExecutorData == "" {
			return errors.New("governance reconciliation requires proposal ID and private executor data")
		}
		executor, err := governanceexec.New(*governanceExecutorData, nil)
		if err != nil {
			return err
		}
		proposal, err := s.ReconcileGovernance(context.Background(), *governanceProposalID, executor, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(proposal)
	}
	if command == "participation-status" {
		return json.NewEncoder(os.Stdout).Encode(s.ParticipationState(time.Now().UTC()))
	}
	if command == "participation-stage-record" {
		if *stageEvidenceFile == "" {
			return errors.New("participation stage recording requires --stage-evidence-file")
		}
		evidence, err := s.RecordParticipationStageEvidence(*stageEvidenceFile, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"recorded": len(evidence), "state": "reviewed-local-evidence", "notice": "These short-lived operator attestations are signed with the next participation response; they are not remote host attestation."})
	}
	if command == "wave-results" {
		return json.NewEncoder(os.Stdout).Encode(s.WaveResultInventory())
	}
	if command == "wave-result-create" || command == "wave-result-verify" {
		envelope, err := operator.ReadMaintenanceEnvelope(*maintenanceFile)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if command == "wave-result-create" {
			revision, err := strconv.ParseUint(*maintenanceRevision, 10, 64)
			if err != nil {
				return errors.New("provide --maintenance-revision from current local status")
			}
			result, err := s.RecordWaveResult(operator.RecordWaveResultRequest{ID: *waveResultID, ExpectedRevision: revision, Envelope: envelope, ProgressID: *progressID}, now)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		result, err := operator.ReadSignedWaveResult(*waveResultFile)
		if err != nil {
			return err
		}
		policy, err := s.MaintenancePolicy(now)
		if err != nil {
			return err
		}
		verified, err := operator.VerifyWaveResult(result, envelope, policy, now)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(verified)
	}
	if command == "participation-begin" {
		envelope, err := operator.ReadMaintenanceEnvelope(*maintenanceFile)
		if err != nil {
			return err
		}
		revision, err := strconv.ParseUint(*maintenanceRevision, 10, 64)
		if err != nil {
			return errors.New("provide --maintenance-revision from current local status")
		}
		result, err := s.BeginParticipation(operator.BeginParticipationRequest{ID: *participationID, ExpectedRevision: revision, Envelope: envelope}, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "participation-respond" {
		var request operator.ParticipationRequest
		if err := operator.ReadParticipationInput(*participationFile, &request); err != nil {
			return err
		}
		result, err := s.ObserveParticipation(context.Background(), request)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "participation-verify" {
		var reports []operator.SignedParticipationObservation
		if err := operator.ReadParticipationInput(*participationFile, &reports); err != nil {
			return err
		}
		result, err := s.CheckParticipation(context.Background(), reports, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "maintenance-init" {
		member, err := s.InitializeMaintenance()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(member)
	}
	if command == "maintenance-status" {
		return json.NewEncoder(os.Stdout).Encode(s.MaintenanceState(time.Now().UTC()))
	}
	if command == "pilot-status" {
		return json.NewEncoder(os.Stdout).Encode(s.PilotState(time.Now().UTC()))
	}
	if command == "pilot-accept" {
		if *pilotClaimFile == "" {
			return errors.New("pilot acceptance requires --pilot-claim-file")
		}
		request, err := operator.ReadPilotAcceptanceRequest(*pilotClaimFile)
		if err != nil {
			return err
		}
		acceptance, err := s.RecordPilotAcceptance(request, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(acceptance)
	}
	if command == "pilot-verify" {
		if *pilotAcceptancesFile == "" || *pilotPolicyDigest == "" {
			return errors.New("pilot verification requires --pilot-acceptances-file and --pilot-policy-digest")
		}
		acceptances, err := operator.ReadPilotAcceptances(*pilotAcceptancesFile)
		if err != nil {
			return err
		}
		report, err := operator.VerifyPilotAcceptances(acceptances, *pilotPolicyDigest, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if command == "pilot-record" {
		if *pilotExerciseFile == "" {
			return errors.New("pilot exercise recording requires --pilot-exercise-file")
		}
		request, err := operator.ReadPilotExerciseRequest(*pilotExerciseFile)
		if err != nil {
			return err
		}
		receipt, err := s.RecordPilotExercise(request, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(receipt)
	}
	if command == "pilot-audit" {
		if *pilotAcceptancesFile == "" || *pilotReceiptsFile == "" || *pilotPolicyDigest == "" {
			return errors.New("pilot audit requires --pilot-acceptances-file, --pilot-receipts-file and --pilot-policy-digest")
		}
		acceptances, err := operator.ReadPilotAcceptances(*pilotAcceptancesFile)
		if err != nil {
			return err
		}
		receipts, err := operator.ReadPilotExerciseReceipts(*pilotReceiptsFile)
		if err != nil {
			return err
		}
		report, err := operator.VerifyPilotExercise(acceptances, receipts, *pilotPolicyDigest, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if command == "maintenance-verify" || command == "maintenance-endorse" {
		envelope, err := operator.ReadMaintenanceEnvelope(*maintenanceFile)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if command == "maintenance-endorse" {
			revision, err := strconv.ParseUint(*maintenanceRevision, 10, 64)
			if err != nil {
				return errors.New("provide --maintenance-revision from current local status")
			}
			result, err := s.EndorseMaintenanceEnvelope(operator.EndorseMaintenanceRequest{Envelope: envelope, Digest: *maintenanceDigest, ExpectedRevision: revision}, now)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		policy, err := s.MaintenancePolicy(now)
		if err != nil {
			return err
		}
		report, err := operator.VerifyMaintenance(envelope, policy, now)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if command == "worker-prepare" {
		preparation, err := s.PrepareWorker(*workerBinary, *workerSHA)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(preparation)
	}
	if command == "doctor" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		report := s.Doctor(ctx)
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
		if report.Status != "checks-passed" {
			return errors.New("preflight needs attention; see the diagnostic report")
		}
		return nil
	}
	if command == "backup-configure" {
		if err := s.ConfigureBackups(context.Background(), operator.BackupPolicy{SchemaVersion: 1, Recipient: *recipient, CryptoPath: *cryptoPath, CryptoSHA256: *cryptoHash}); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(s.ManagedBackups())
	}
	if command == "backup-create" || command == "backup-restore" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		provider := operator.CryptoProvider{Path: *cryptoPath, SHA256: *cryptoHash}
		var receipt operator.BackupReceipt
		if command == "backup-create" {
			receipt, err = s.CreateBackup(ctx, *workerBase, *backupFile, *recipient, provider)
		} else {
			receipt, err = operator.RestoreBackup(ctx, *backupFile, *restoreBase, *identity, provider)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(receipt)
	}
	if command == "restore-review" {
		evm, evmErr := strconv.ParseUint(*ethereumHeight, 10, 64)
		koinos, koinosErr := strconv.ParseUint(*koinosHeight, 10, 64)
		if evmErr != nil || koinosErr != nil {
			return errors.New("restore review requires both explicit decimal checkpoint heights")
		}
		result, err := operator.ReviewRestoreObservation(*workerBase, *backupDigest, *reviewNote, evm, koinos)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "candidate-test" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		result, err := s.TestCandidate(ctx, *candidateDigest, *artifactPlatform, *checkerPath, *checkerHash)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "release-stage" {
		release, err := operator.ReadSignedRelease(*releaseFile)
		if err != nil {
			return err
		}
		staged, err := s.StageRelease(release, *artifactPlatform, *artifactFile, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"digest": staged.Digest, "platform": staged.Platform, "artifactSha256": staged.Artifact.SHA256, "state": "artifact-verified", "installed": false})
	}
	if command == "release-adopt" {
		installed, err := s.AdoptInstalledRelease(*candidateDigest, *artifactPlatform, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(installed)
	}
	if command == "worker-register" {
		if *workerBase == "" || *workerBinary == "" {
			return errors.New("worker-register requires --worker-base, --worker-binary and --worker-sha256 before the command")
		}
		_, err := s.RegisterWorker(*workerBase, *workerBinary, *workerSHA)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(s.WorkerStatus(context.Background()))
	}
	if command == "status" {
		revision, profiles, events := s.Summary()
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"revision": revision, "profiles": profiles, "events": events, "mode": "observation-only"})
	}
	token, err := s.Token()
	if err != nil {
		return err
	}
	if command == "token-path" {
		p, err := filepath.Abs(filepath.Join(*dir, "access-token"))
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return errors.New("invalid listen address")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("management must bind a literal loopback address; use an SSH tunnel for remote access")
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer l.Close()
	api := operator.NewServer(s, token, l.Addr().String(), strings.Split(*origins, ","))
	api.SetObservationProvider(observe)
	server := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	fmt.Printf("Private operator API: http://%s\nMode: observation-only; no bridge signing keys loaded.\nAccess token file: %s\n", l.Addr(), filepath.Join(*dir, "access-token"))
	err = server.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
