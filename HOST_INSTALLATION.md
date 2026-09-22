# Linux host bundle and managed signer boundary (Prompt 03, in progress)

This development implementation is **not the completed Prompt 03**. The host
bundle installs and runs the private observation service. The managed signer
library is exercised with encrypted synthetic keys and an in-process test
verifier; it is not wired into the transfer streamers or an operator activation
command. Public signing stays disabled. Do not use the legacy signer command to
bypass that boundary.

## Build and verify the bundle

Use Go 1.24.2 and the checked-in `go.mod`/`go.sum`. Dependencies must already be
available in the module cache. The builder runs `go mod verify`, disables module
network access and toolchain downloads, uses readonly modules, removes machine
paths/build IDs and writes a deterministic, sorted USTAR archive.

```sh
python3 packaging/build.py --arch arm64 --out /absolute/disposable/build-a
python3 packaging/build.py --arch arm64 --out /absolute/disposable/build-b
cmp /absolute/disposable/build-a/vortex-host-linux-arm64.tar /absolute/disposable/build-b/vortex-host-linux-arm64.tar
```

`amd64` is also a build target. The build report records source revision, dirty
state, compiler, module-lock hash, file hashes and archive hash. A development
build report is not publisher approval. Build twice from the reviewed clean
revision before issuing a release.

The archive contains the validator, operator, key tool, candidate checker, host
tool and a user-service template. Install using an independently verified host
tool. The archive must be described by a signed **operator-component** release
manifest, verified against separately maintained publisher trust, and approved
locally for this installation identity and time window. Its artifact hash is the
whole tar archive hash. Do not pass a bundle manifest to the existing
validator-executable staging/adoption commands: those hash a single executable.

## Install, inspect, upgrade and remove

Run as a dedicated non-root Linux account. Keep release, approval, trust and
archive files private (0600). The installation root and state directories are
0700. Paths below are placeholders; supply reviewed local artifacts.

```sh
vortex-host --root /absolute/private/host --instance my-validator \
  --bundle /absolute/private/bundle.tar \
  --release /absolute/private/release.json \
  --trust /absolute/private/publishers.json \
  --approval /absolute/private/approval.json install
vortex-host --root /absolute/private/host doctor
vortex-host --root /absolute/private/host --instance my-validator \
  --trust /absolute/private/publishers.json authorize
vortex-host --root /absolute/private/host run
```

`authorize` rechecks current local approval, its time window, publisher signatures
and the retained exact archive against the installed files. It still reports
managed signing unavailable. The archive is retained privately alongside extracted
files, so installed storage is larger than the download. Old installation records
without the signed release/approval and archive cannot authorize a managed signer.

`InstalledVerifier` joins these local checks to the running executable and exact
configuration bytes on every inspection, and caps evidence validity at approval
expiry. The chain/recovery verifier and candidate qualification remain separate
integration work; no dashboard or network response may assert release approval.

Installation never launches a process. `run` starts only the private operator
service, with no keys or automatically authorized signer. Its default API listens
on loopback port 3021. Configure observation instances through the existing
operator workflow. Stop the foreground service with SIGTERM; the host waits up
to 20 seconds before terminating an unresponsive child. On Linux the child also
receives SIGTERM if its supervisor dies. The service unit uses control-group
termination and does not automatically restart.

Running installation twice verifies the existing bytes and retains state. An
upgrade requires a newer signed sequence, an explicitly supported predecessor
version and unchanged configuration/database schemas and signing codec.
Incompatible migrations and downgrade recovery deliberately require separate
implementation and review. Stop the host before upgrading; install/uninstall
share an exclusive lock with the running host. Doctor remains read-only and can
inspect the active installation.

```sh
vortex-host --root /absolute/private/host uninstall
```

Uninstall disables future starts. It preserves operator data, vaults, release
files and installation history. It does not remove an independently registered
systemd unit; stop/disable that unit before uninstalling. Reinstalling the same
approved artifact can re-enable observation. No operation automatically deletes
key material or resets a database.

The supplied user-service template assumes the independently verified launcher
at `~/.local/bin/vortex-host` and installation at
`~/.local/share/vortex-host`. Review/copy it into the account's systemd user
configuration and explicitly enable it only after installation checks. This
milestone has exercised foreground supervision in containers, **not boot-time
systemd acceptance**. Journald owns log retention; the unit rate-limits messages.
Measured journal size/retention, firewall, patching, independent administration,
backups and emergency access remain host acceptance controls, not facts inferred
from a successful install.

## Managed signer protocol

`internal/managed` is a library, not an HTTP signing endpoint. A future reviewed
adapter must reconstruct operations from finalized chain data and independently
verify exact release approval, artifact/configuration digests, code provenance,
network identity, host policy and current membership. Dashboard booleans, saved
JSON and a process-health check are not valid implementations of that adapter.
There is currently no production adapter. Test adapters are confined to tests.

The state transitions are:

- Opening a new session produces `locked`.
- Activation requires fresh evidence, reconciliation of all retained operations,
  Linux key protections and manual vault unlock; it then rechecks evidence before
  entering `active`.
- Every operation is independently resolved by identifier. There is no external
  “sign this hash” command. The session rechecks authorization, persists the intent
  before signing and persists its result before returning a public signature.
- Stop clears keys and releases the same-user identity locks. An active session
  excludes another data directory using either identity, including the existing
  standalone signer's locks.
- Abrupt loss of an active process leaves a durable `recovery-required` record.
  Restart does not unlock automatically. Retained signatures are cryptographically
  checked, and reconciliation must complete before a fresh manual unlock.
- A verifier failure removes signing capability. Corrupt state, unknown state,
  changed operation digests, wrong identity, missing code/finality or stale
  authority cannot silently become readiness.

Only public operation identifiers, digests, signatures and checkpoints are
journaled. Private keys remain inside the session; vault input uses the existing
protected local mechanism. Passphrases never belong in arguments, environment,
ordinary files or the operator API. The agreed pilot policy is manual unlock;
no unattended restart/broker is approved or implemented.

## Transfer encoding and recovery

The managed path now encodes a typed transfer reconstructed by an independent
reader instead of accepting an opaque digest from a peer. EVM and Koinos vectors
are generated independently with ethers/protobufjs, including the unsigned 64-bit
boundary. The EVM codec avoids the legacy uint64-to-int64 conversion. This does
not change or approve the legacy transfer runtime.

`OperationVerifier` binds both reviewed local profiles, fresh finalized source
and destination roots, canonical transaction/operation identity and final
completion status. It rejects multiple bridge events in an EVM transaction when
the destination Koinos codec cannot distinguish their operation index. Recovery
checks every retained operation, rejects changed payloads or a completed-to-pending
regression, and binds the new checkpoint to the receipts it checked.

The reader interface still requires concrete chain adapters. Current reader tests
use synthetic receipt observations, not live chain proofs. The vectors verify
encoding agreement, not complete contract execution or public deployment safety.
Reproduce them from this repository using:

```sh
node scripts/generate-transfer-vectors.cjs /absolute/interface-bridge
go test -race ./internal/managed
```

## Replacement and fencing

A same-host stop is enforced by process/data locks and key disposal. These locks
cannot fence another server. For lost-host replacement, the policy requires new
EVM **and** Koinos identities and independently verified final retirement of both
previous identities. An unreachable server is not proof of retirement. One-chain
rotation is incomplete and blocks activation.

The old private key can still mathematically produce a signature after theft;
final membership retirement prevents it from being an authorized bridge signer.
A privileged administrator is outside the local process-lock threat boundary.
Never describe file locks, Tailscale, dashboard status or a copied journal as
cross-host cryptographic fencing. Future chain adapters must prove retirement
and test signature rejection at both actual destination verifiers.

The Linux tests demonstrate this policy using a synthetic membership transition,
including an old session still running when replacement is attempted. They do
not establish on-chain rotation finality or independent-host control.

## Remaining acceptance work (must not be skipped)

1. Implement reviewed live local-chain evidence/reconciliation adapters and wire
   this narrow boundary into a complete managed command and transfer lifecycle.
2. Join installed-artifact, candidate qualification and local approval checks;
   exercise those checks at activation with real adapter outputs, not test flags.
3. Run full install/observe/manual-unlock/activate/drain/stop/restart/replacement
   with actual synthetic transfers and receipt reconciliation across two clean
   development hosts. Current containers share one Docker host and do not prove
   independent administration or an end-to-end cross-host replacement.
4. Exercise boot-time service behavior, log retention and operational backups;
   verify all exports and backup formats omit keys/passphrases.
5. Re-run race/static/Linux checks after integration, publish sanitized evidence,
   and keep every unresolved public deployment in observation-only mode.
