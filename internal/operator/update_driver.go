package operator

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
)

// LocalUpdateDriver performs fixed local worker transitions. It accepts no
// executable path or command from HTTP. Signing workers must already be drained
// and locked through their protected terminal; observation workers can be
// stopped and restarted through the existing fixed worker controller.
type LocalUpdateDriver struct{ store *Store }

func NewLocalUpdateDriver(store *Store) *LocalUpdateDriver { return &LocalUpdateDriver{store: store} }

func updateEvidence(action, state, message, artifact, registration string) UpdateExecutionEvidence {
	return UpdateExecutionEvidence{At: time.Now().UTC(), Action: action, State: state, Message: message, ArtifactSHA256: artifact, RegistrationDigest: registration}
}

func (d *LocalUpdateDriver) Drain(ctx context.Context, operation UpdateOperation) (UpdateExecutionEvidence, error) {
	registration, err := d.store.registration()
	if err != nil || registrationDigest(registration) != operation.PriorRelease.RegistrationDigest {
		return UpdateExecutionEvidence{}, errors.New("registered worker differs from the pre-update release")
	}
	if registration.Mode == "signing" {
		lifecycle := d.store.ManagedLifecycle()
		if !lifecycle.Supported || !lifecycle.Installation.Verified || lifecycle.Signer.State != "locked" || lifecycle.Signer.UnfinalizedCount != 0 || lifecycle.Signer.ProcessEvidence != "no process holds the managed session lock" {
			return UpdateExecutionEvidence{}, errors.New("signing worker must be drained, locked, fully reconciled and process-fenced in the protected terminal")
		}
	}
	return updateEvidence("drain", "passed", "Retained operations are reconciled and the selected worker is eligible to stop.", registration.BinarySHA256, registrationDigest(registration)), nil
}

func (d *LocalUpdateDriver) Stop(ctx context.Context, operation UpdateOperation) (UpdateExecutionEvidence, error) {
	registration, err := d.store.registration()
	if err != nil {
		return UpdateExecutionEvidence{}, err
	}
	status := d.store.WorkerStatus(ctx)
	if registration.Mode == "signing" {
		lifecycle := d.store.ManagedLifecycle()
		if status.State == "running" || lifecycle.Signer.State != "locked" || lifecycle.Signer.ProcessEvidence != "no process holds the managed session lock" {
			return UpdateExecutionEvidence{}, errors.New("signing worker is not verifiably stopped and fenced")
		}
		return updateEvidence("stop", "locked", "The signing journal is locked and no prior managed session owns it.", registration.BinarySHA256, registrationDigest(registration)), nil
	}
	if status.State == "running" && status.Health != nil {
		if _, err := d.store.StopWorker(ctx, status.RegistrationDigest, status.Health.PID, status.Health.StartedAt); err != nil {
			return UpdateExecutionEvidence{}, err
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			status = d.store.WorkerStatus(ctx)
			if status.State != "running" {
				break
			}
			select {
			case <-ctx.Done():
				return UpdateExecutionEvidence{}, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	status = d.store.WorkerStatus(ctx)
	if status.State == "running" || status.State == "mismatch" || status.State == "invalid" {
		return UpdateExecutionEvidence{}, errors.New("worker did not reach a fenced stopped state")
	}
	return updateEvidence("stop", "locked", "The observation worker stopped and its reviewed registration remains fenced.", registration.BinarySHA256, registrationDigest(registration)), nil
}

func (d *LocalUpdateDriver) registrationPath(registration WorkerRegistration) string {
	if registration.BaseDir == filepath.Join(d.store.dir, "managed-worker") {
		return filepath.Join(d.store.dir, "managed-worker", "registration.json")
	}
	return filepath.Join(d.store.dir, "worker.json")
}

func (d *LocalUpdateDriver) installRelease(staged StagedRelease) (InstalledRelease, error) {
	registration, err := d.store.registration()
	if err != nil {
		return InstalledRelease{}, err
	}
	status := d.store.WorkerStatus(context.Background())
	if status.State == "running" || status.State == "mismatch" || status.State == "invalid" {
		return InstalledRelease{}, errors.New("worker must remain stopped during installation")
	}
	artifactPath := filepath.Join(d.store.dir, "releases", staged.Digest, staged.Platform, "artifact")
	if err := d.store.pinWorkerBinary(artifactPath, staged.Artifact.SHA256); err != nil {
		return InstalledRelease{}, err
	}
	registration.BinarySHA256 = staged.Artifact.SHA256
	rawRegistration, _ := json.Marshal(registration)
	path := d.registrationPath(registration)
	if err := atomicFile(filepath.Dir(path), filepath.Base(path), rawRegistration); err != nil {
		return InstalledRelease{}, errors.New("cannot publish updated worker registration")
	}
	manifest := staged.Release.Manifest
	installed := InstalledRelease{
		SchemaVersion: 1, InstanceID: d.store.InstanceID(), Digest: staged.Digest, Component: manifest.Component,
		Version: manifest.Version, Sequence: manifest.Sequence, Platform: staged.Platform, ArtifactSHA256: staged.Artifact.SHA256,
		SourceCommit: manifest.SourceCommit, ConfigSchema: manifest.ConfigSchema, DatabaseSchema: manifest.DatabaseSchema,
		SigningCodec: manifest.SigningCodec, MixedVersionsSafe: manifest.MixedVersionsSafe, RegistrationDigest: registrationDigest(registration),
		RegisteredConfigSHA256: registration.ConfigSHA256, RecordedAt: time.Now().UTC(), State: "installed",
	}
	if err := validateInstalledRelease(installed); err != nil {
		return InstalledRelease{}, err
	}
	rawInstalled, _ := json.MarshalIndent(installed, "", "  ")
	if err := atomicFile(d.store.dir, installedReleaseFile, rawInstalled); err != nil {
		return InstalledRelease{}, errors.New("cannot publish installed release identity")
	}
	return installed, nil
}

func (d *LocalUpdateDriver) Install(ctx context.Context, operation UpdateOperation, staged StagedRelease) (UpdateExecutionEvidence, error) {
	installed, err := d.installRelease(staged)
	if err != nil {
		return UpdateExecutionEvidence{}, err
	}
	return updateEvidence("install", "installed", "Exact staged bytes replaced the stopped worker registration; prior bytes remain retained for reviewed recovery.", installed.ArtifactSHA256, installed.RegistrationDigest), nil
}

func (d *LocalUpdateDriver) Verify(ctx context.Context, operation UpdateOperation) (UpdateExecutionEvidence, error) {
	current, err := d.store.CurrentRelease()
	if err != nil || current.Digest != operation.ReleaseDigest || current.ArtifactSHA256 != operation.CandidateArtifactSHA256() {
		return UpdateExecutionEvidence{}, errors.New("installed release or registration differs from the update journal")
	}
	registration, err := d.store.registration()
	if err != nil || registrationDigest(registration) != current.RegistrationDigest {
		return UpdateExecutionEvidence{}, errors.New("updated worker registration cannot be verified")
	}
	if registration.Mode == "observation-only" {
		if _, err := d.store.StartWorker(ctx, current.RegistrationDigest); err != nil {
			return UpdateExecutionEvidence{}, err
		}
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			status := d.store.WorkerStatus(ctx)
			if status.State == "running" && status.Health != nil {
				return updateEvidence("verify", "verified", "Updated observation worker restarted with its exact identity, configuration and fresh chain health.", current.ArtifactSHA256, current.RegistrationDigest), nil
			}
			select {
			case <-ctx.Done():
				return UpdateExecutionEvidence{}, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		return UpdateExecutionEvidence{}, errors.New("updated observation worker did not produce fresh verified health")
	}
	lifecycle := d.store.ManagedLifecycle()
	if lifecycle.Signer.State != "locked" || lifecycle.Signer.ProcessEvidence != "no process holds the managed session lock" {
		return UpdateExecutionEvidence{}, errors.New("updated signer is not locked and fenced for protected-terminal activation")
	}
	return updateEvidence("verify", "verified", "Exact signer bytes and registration verified while the signing journal remains locked and fenced; protected-terminal activation is still required.", current.ArtifactSHA256, current.RegistrationDigest), nil
}

func (d *LocalUpdateDriver) restorePrior(operation UpdateOperation) (InstalledRelease, error) {
	registration, err := d.store.registration()
	if err != nil {
		return InstalledRelease{}, err
	}
	status := d.store.WorkerStatus(context.Background())
	if status.State == "running" {
		return InstalledRelease{}, errors.New("updated worker must be stopped before recovery")
	}
	registration.BinarySHA256 = operation.PriorRelease.ArtifactSHA256
	if _, err := worker.ReadPrivateFile(filepath.Join(d.store.dir, "worker-bin", registration.BinarySHA256), 256<<20); err != nil {
		return InstalledRelease{}, errors.New("retained prior artifact is unavailable")
	}
	rawRegistration, _ := json.Marshal(registration)
	path := d.registrationPath(registration)
	if err := atomicFile(filepath.Dir(path), filepath.Base(path), rawRegistration); err != nil {
		return InstalledRelease{}, err
	}
	prior := operation.PriorRelease
	prior.RegistrationDigest = registrationDigest(registration)
	prior.RegisteredConfigSHA256 = registration.ConfigSHA256
	prior.RecordedAt = time.Now().UTC()
	prior.State = "installed"
	rawPrior, _ := json.MarshalIndent(prior, "", "  ")
	if err := atomicFile(d.store.dir, installedReleaseFile, rawPrior); err != nil {
		return InstalledRelease{}, err
	}
	return prior, nil
}

func (d *LocalUpdateDriver) Rollback(ctx context.Context, operation UpdateOperation) (UpdateExecutionEvidence, error) {
	prior, err := d.restorePrior(operation)
	if err != nil {
		return UpdateExecutionEvidence{}, err
	}
	current, err := d.store.CurrentRelease()
	if err != nil || current.Digest != prior.Digest || current.ArtifactSHA256 != prior.ArtifactSHA256 {
		return UpdateExecutionEvidence{}, errors.New("prior release failed verification after rollback")
	}
	return updateEvidence("rollback", "recovered", "The exact prior compatible artifact and registration were restored while the failed candidate remained fenced.", prior.ArtifactSHA256, prior.RegistrationDigest), nil
}

func (d *LocalUpdateDriver) ForwardRecover(ctx context.Context, operation UpdateOperation, staged StagedRelease) (UpdateExecutionEvidence, error) {
	installed, err := d.installRelease(staged)
	if err != nil {
		return UpdateExecutionEvidence{}, err
	}
	current, err := d.store.CurrentRelease()
	if err != nil || current.Digest != staged.Digest || current.ArtifactSHA256 != staged.Artifact.SHA256 {
		return UpdateExecutionEvidence{}, errors.New("forward recovery release failed exact verification")
	}
	return updateEvidence("forward-recover", "recovered", "A newer tested artifact for the migrated schema replaced the failed candidate; the pre-migration binary remains fenced.", installed.ArtifactSHA256, installed.RegistrationDigest), nil
}
