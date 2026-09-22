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

`KoinosEVMReader` now implements the Koinos-to-EVM receipt adapter using standard
read-only RPC methods. A locator supplies only a block-height hint: the reader
checks network identity, the reported last irreversible height, a block fetched
on the reported ancestor branch, header hash, receipt/block identity, unique
transaction and event, successful execution, emitter, token mapping and route.
Destination code and completion status are read at the same finalized EVM block
hash with `requireCanonical`. The completion key matches an independent ethers
calculation. Endpoints are trusted read providers, not light-client proofs.

HTTP fixture tests exercise the actual request/response parsing, including
negative source and destination cases. No public RPC or real chain execution is
claimed by those tests. Historical receipt finality does **not** establish Koinos
code provenance or current validator membership. The inverse reader and a
separate irreversible Koinos state adapter are described below; their real-node
acceptance remains outstanding. The vectors verify
encoding agreement, not complete contract execution or public deployment safety.
Reproduce them from this repository using:

```sh
node scripts/generate-transfer-vectors.cjs /absolute/interface-bridge
go test -race ./internal/managed
```

## EVM-to-Koinos receipt reader

`managed.NewEVMKoinosReader` reads a successful EVM transaction receipt, checks
canonical block inclusion below the finalized height, and pins the reviewed
source contract code to that block. Every receipt log must have consistent block
and transaction positions. Exactly one bridge lock event is permitted, because
the reviewed Koinos completion codec binds the transaction hash without an event
index. This applies even if a second bridge event targets another destination.

Event ABI decoding is followed by exact re-encoding; amounts must fit unsigned
64-bit values, the event time must match the block time in milliseconds, and the
destination chain and configured token mapping must match. The reader derives
the signing expiry from that time and the locally configured lifetime. Completion
is read through `KoinosSnapshot`, then source canonicality, finality and network
identity are checked again. Providers remain trusted; this is not a light client.

Twenty-five HTTP receipt scenarios cover unsigned limits, malformed and ambiguous
events, source reorganization/finality regression and destination status handling.
These tests substitute typed destination evidence; the separate snapshot suite
tests its actual RPC parsing. Neither suite proves the combined flow against real
chains. Paused state and current membership still require activation-time checks;
this reader alone does not authorize a signature or submit a transaction.

## Irreversible Koinos read replica (development adapter)

`managed.NewKoinosSnapshot` reads code metadata, initialized bridge metadata,
complete validator membership, pause state and selected transfer completion
states from a separate replica pinned exactly at the live node's current last
irreversible block. It checks the replica height, block identity and state root
against the live branch's block receipt, verifies the canonical header hash,
then rechecks both nodes and the live anchor after the reads. Any mismatch or
advance requires a refreshed replica and retry. An ordinary node following the
head does not meet this requirement.

Membership enumeration requires a known current member as a seed. The reviewed
contract returns no members for an empty or absent seed. The adapter enumerates
both directions, checks ordering/uniqueness, and requires the resulting union to
match the contract's declared count. An unavailable seed blocks readiness; it is
never interpreted as proof that all previous validators were retired.

Only reviewed local profiles are accepted. Providers and their system-call
semantics remain trusted: matching a reported state root is not a cryptographic
proof of individual RPC results. Unsupported contract authority overrides and
malformed response fields fail closed. Twenty-eight HTTP fixture scenarios
exercise the adapter, including membership pagination and changing anchors.

This is a development library, not an installed replica service. Provisioning,
replaying/freezing and refreshing an actual isolated Koinos replica have **not**
been exercised. The managed activation command does not use this adapter yet.
Public-route readiness and independent-host acceptance remain blocked.

## Finalized EVM membership snapshot

`managed.NewEVMSnapshot` reads the reviewed contract's code, bridge chain ID,
nonce, pause state, validator count, indexed validator array and `isValidator`
authority flags. Every state call uses the same finalized block hash with
`requireCanonical`; canonicality, finality and network identity are rechecked
before returning evidence. The full unsigned 256-bit nonce is retained.

Callers can explicitly probe current and previous identities. Every listed
validator must have an active authority flag, and a probed identity absent from
the list must have an inactive flag. A list/mapping discrepancy blocks the read:
absence from the array alone is insufficient retirement evidence. Enumeration is
bounded to 256 validators and probes to 32 identities; unsupported counts fail
closed. These limits are development safeguards, not governance decisions.

Eighteen HTTP scenarios cover pinned reads, three-member enumeration, explicit
retirement probes, malformed results, inconsistent authority flags and changed
network/finality. Real-chain membership rotation and activation integration remain
unverified. This adapter reports chain state only; it does not establish host
security, candidate qualification, release approval or permission to sign.

## Installed candidate qualification

The installed verifier now requires an absolute path to private local
`CandidateQualification` evidence in addition to publisher trust and configuration.
The record contains schema version 1, the separately signed **validator** release,
and the operator candidate runner's result. The installed TAR is an **operator**
release; its archive hash must not be substituted for the tested executable hash.

Verification requires the validator release to pass current publisher trust and
expiry checks; its exact platform, executable hash and size must match the member
of the authenticated installed bundle. The checker hash must match the bundled
`vortex-candidate-check`. Only the current eight-check observation report and the
specified isolated execution mode are accepted. Tests must finish after release
creation and before local bundle activation approval. Qualification expiry also
caps the resulting readiness lifetime.

The record must be a private, bounded, owner-controlled local file. This is local
execution evidence, **not** a publisher signature over the test result or remote
host attestation. It must be produced from the actual isolated runner output;
manual declarations cannot replace execution. A user able to rewrite all local
approvals and trust files remains outside this boundary.

Fourteen new negative cases cover missing/insecure evidence, mismatched binaries,
checker/platform/release, unsigned manifests, incomplete reports and invalid
ordering. The fixture uses synthetic signed releases. The CLI workflow that
imports a real runner result into this installed record remains to be connected.
Candidate observation checks do not prove managed signing or two-host recovery.

## Joined chain evidence

`managed.NewChainVerifier` combines the EVM and Koinos finalized snapshots. Both
new identities must be current members, both bridges must be unpaused, and the
profile/code hashes and observation times must match. A replacement requires two
new identities and final retirement of both previous identities; a missing EVM
retirement probe is a failure, not evidence of removal.

The current activation adapter supports EVM development network `31337` only and
rejects known public Koinos mainnet/Harbinger identities even when relabeled local.
The existing codec vectors can still describe public network identities for pure
encoding tests; those vectors do not grant activation permission.

Chain evidence deliberately leaves host and release readiness false. It cannot
activate a session by itself, and its base operation method refuses untyped
requests. Use the typed operation verifier for recovery: the base checks the chain
anchor while the wrapper rechecks every retained transfer before returning a
combined checkpoint. A direct base reconciliation with retained operations fails.

Tests cover 14 joined-state scenarios, four relabeled public identities, and
retained-transfer reconciliation through the joined verifier. Snapshot outputs
are substituted in these composition tests; separate suites exercise RPC parsing.
No complete installed activation, actual rotation or two-host recovery is claimed.

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
