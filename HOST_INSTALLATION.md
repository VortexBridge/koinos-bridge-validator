# Linux host bundle and managed signer boundary (Prompt 03, in progress)

Prompt 03 remains incomplete. The packaged host now supports private observation,
manual managed activation against isolated development chains, both transfer
routes, fenced replacement after dual-identity retirement, and same-host artifact
upgrades preserving signatures. These paths have been exercised with synthetic
keys and actual chain processes on one physical Docker host. Public signing stays
disabled; never bypass this boundary through the legacy signer.

Two clean development hosts now run the same exact test-only approved artifact
as keyless observation services after real reboots. Native non-root Linux
synthetic signing tests passed independently on each. An encrypted synthetic
observation backup restored from the first host on a separate Mac and on the
second Linux host. The remaining acceptance is distributed **installed-runtime**
signing, host-loss fencing and recovery, plus accepted host security and durable
backup custody. Two containers are not two hosts, and two VPSs in one operator's
account do not establish independent operators. Production-chain authorization
is a separate decision.

Both real AMD64 development hosts now run the refreshed bundle as keyless,
loopback-only user services after reboots; the first also passed a compatible
update. A stopped synthetic observation worker on the first produced an encrypted
archive that was copied off-host and restored on a separate Mac and the second
Linux host, including a repeat Mac restore after the source fixture was removed.
The second-host restore required explicit configuration review before enabling
observation. This is not a signing-key recovery or cross-host signer test.

Later milestone sections retain dated laboratory evidence and its limitations.
The current status above supersedes their historical statements of pending work.

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

For disposable development-host observation checks only,
`scripts/host-acceptance-fixture.go` can make a short-lived synthetic publisher
signature, trust file and local approval for an exact AMD64 bundle. It requires
an instance name beginning with `synthetic-` and a new private output directory.
The private publisher key is discarded and cannot be used for later releases.
The output is never production provenance or permission to activate a signer.

```sh
go run scripts/host-acceptance-fixture.go \
  --bundle /absolute/disposable/build/vortex-host-linux-amd64.tar \
  --out /absolute/private/new-fixture-directory \
  --instance synthetic-host-a \
  --source-commit "$(git rev-parse HEAD)"
```

Verify the source tree is clean before running this command. Transfer
only the bundle, signed release, public trust and local approval to the test
host. Keep each file owner-only; verify the bundle hash again after transfer.
Do not transfer a real publisher private key or any validator signing key.
For a compatible update of an existing synthetic installation, pass the same
instance and `--sequence 2` (then increment for subsequent updates). A new
test-only publisher and approval are generated for the new exact archive. Stop
the user service before installation, retain the old release and state, and
replace its verified launcher only after the new installation passes `doctor`.
This fixture does not authorize an incompatible migration or public signing.

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
expiry. The chain/recovery verifier and candidate qualification are joined to this
boundary; no dashboard or network response may assert release approval.

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
configuration and explicitly enable it only after installation checks. On both
real AMD64 development hosts, the exact bundle was installed under a non-root
account with short-lived synthetic local approval; real reboots restarted their
keyless, observation-only services. The service unit rate-limits messages.
Provisional development journald and rsyslog bounds passed configuration checks,
and both hosts now use default-deny incoming UFW with SSH allowed. Log load,
production retention policy, SSH source restrictions, patching, independent
administration and emergency access still need host-specific acceptance. The
second Linux host restored a synthetic observation archive; this
does **not** prove managed signing-key recovery, signer fencing or permission
to sign.

## Managed signer protocol

`internal/managed` is used by the installed interactive host command, not an HTTP
signing endpoint. Its development adapters reconstruct finalized operations and
verify release approval, artifact/configuration digests, code provenance, network
identity, host policy and membership. Caller-supplied readiness booleans cannot
authorize signing. There is no enabled production signing adapter.

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
ordering. The fixture uses synthetic signed releases. The `vortex-host qualify` command imports the separately signed validator release
and the private runner result into `candidate.json` after validating all bindings.
Candidate observation checks do not prove managed signing or two-host recovery.

After running the isolated candidate suite, approving the operator bundle and
installing it, stop the observation service and import the actual local result:

```sh
vortex-host --root /absolute/private/installation --instance operator-local \
  --trust /absolute/private/publishers.json \
  --validator-release /absolute/private/validator-release.json \
  --candidate-result /absolute/private/candidate-result.json qualify
```

Flags precede the command. Both input files must be private local records. The
command holds the installation lock, rechecks the installed archive and current
approval, then atomically writes `candidate.json`. Repeated valid imports are
safe; a rejected import preserves the previous record. Output explicitly reports
`managedSigning: false`. Import does not execute tests or unlock keys. Never
replace actual runner output with a hand-written success declaration.

Linux acceptance invokes the compiled command twice using synthetic signed
releases/results, then rejects an incorrect checker hash and verifies the previous
record survived. A fresh fixed-checker → approved bundle → install/import/observe/stop/uninstall
exercise has now passed in two clean containers using real built executables and
synthetic publisher signatures. The acceptance test invokes the checker and
imports its actual eight-check report. The combined harness has no host mounts
or external network, but uses executable temporary installation storage and
different resource limits from the standalone candidate runner. Both containers
share one Docker host. Managed signing activation, real-chain execution and
independent-host replacement remain outstanding.


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

## Authenticated host review and live process protection

`managed.NewHostVerifier` combines a separately pinned Ed25519 reviewer public key,
a signed host review and private local control records with live Linux process
protection. The review binds the instance, executable/configuration digests and a
hash of the Linux machine ID, boot ID and service UID. Its initial development
validity limit is 24 hours; reboot, expiry or changed configuration requires a new
review. This conservative implementation limit is not evidence of operator
acceptance or production enrollment.

The standard profile requires evidence for patched service setup, administrative
access/firewall, private management, encrypted storage/vault, hibernation and
hypervisor policy, patch response, monitoring, log retention, off-host backup and
restore, release maintenance and emergency access. The restricted profile also
requires overlay grants and device posture evidence. Every record is a bounded
private `<control>.txt` file whose digest is covered by the reviewer signature.
The raw 32-byte reviewer public key is also locally pinned in a private file.

These records require actual human inspection. A signature authenticates the
review and its contents; it does not remotely attest disk encryption, firewall
rules, hypervisor behavior or independence of administrators. The software checks
record integrity and separately enforces non-root operation, no swap or whole
process memory locking, zero core limits and a non-dumpable process. Root or a
hypervisor can subvert local identity and memory; this is not hardware attestation.

Fifteen validation scenarios reject changed, incomplete, stale or unauthenticated
reviews. Linux integration applies real memory/core protections with synthetic
host/reviewer evidence. CLI review issuance, actual host review, policy enrollment
and complete installed activation remain outstanding. The wrapper grants no
release approval and cannot replace finalized chain membership checks.

## One managed session for both directions

`managed.NewBidirectionalVerifier` connects both typed transfer readers to the
same signer session. Operation identifiers include `evm-to-koinos/` or
`koinos-to-evm/` followed by the canonical transaction and operation identifier.
The prefix belongs to local routing/journaling; destination contract digests are
unchanged. Identical transaction identifiers on different chains remain separate.

Recovery validates every journal entry's direction, record ID and signing family,
then reconciles both route partitions before producing a combined checkpoint.
Failure on either side blocks recovery. Legacy unqualified journals are rejected;
there is no implicit rewrite that guesses the source chain.

Synthetic Linux acceptance covers encrypted-vault signatures in both directions,
public-key recovery, colliding transaction identifiers, close/reopen, identical
retained signatures after recovery, and completion on one side. Route/receipt
inputs are fixtures in this exercise. It is not real-chain execution or a lost-host
replacement test, and the complete installed command remains unwired.

## Manual unlock timing and fresh recovery checks

Managed activation uses separately bounded live checks before and after secret
entry. Time spent typing is not charged against the ten-second RPC verification
window. The caller's cancellation or deadline still applies. After successful
vault decryption, current approvals and all retained operations are checked again;
the persisted activation checkpoint comes from this second reconciliation.

A revoked approval, changed pending operation or cancelled activation closes the
unlocked keys and releases identity leases before returning. No active state is
persisted. Linux synthetic-vault tests exercise an eleven-second entry delay,
revocation, reconciliation failure and cancellation, including a fresh retry after
rejection. The CLI registers SIGINT, SIGTERM and SIGHUP cancellation. A non-root
Linux terminal test interrupts a partial synthetic passphrase and verifies that
entry stops, echo is restored, and queued secret bytes are discarded. This is
local terminal evidence, not the complete installed CLI lifecycle on two hosts.

## Remaining acceptance work (must not be skipped)

1. Run the complete **installed-runtime** manual-unlock/activate/stop/crash/
   recovery/replacement exercise across the two real development hosts. Both
   currently run the same exact approved test artifact in keyless observation;
   separate synthetic Linux test binaries pass on each, while the earlier
   installed signer laboratory used one physical Docker host.
2. Accept actual host controls, including administrator recovery, firewall source
   restrictions and emergency access. Boot-time systemd and provisional log
   limits passed on both hosts, and encrypted observation state restored across
   them; synthetic reviewer records do not prove these controls or signing-key
   recovery.
3. Verify logs, exports, backups and retained disks after the distributed signer
   exercise. Current known-secret scans cover selected test logs, user journals
   and ciphertext, not all persistence layers.
4. Refresh reproducibility and target checks for any further artifact change
   before independent-host acceptance. Keep public deployments observation-only.

## Runtime composition

`managed.PrepareRuntime` reads a strict private `RuntimeConfig` and connects the
finalized chain readers, bidirectional reconciliation, installed candidate/release
checks and authenticated host review into one locked session. It does not unlock
or start it. The supervisor must retain the installation lock for its lifetime.
No configuration readiness flags are accepted. Public identities rejected by the
chain gate cannot create a managed session.

The configuration digest binds the exact bytes parsed, preventing a later file
read from accidentally approving a different configuration. Koinos block hints
are locator inputs only; the receipt reader independently verifies inclusion and
finality. Token mappings must be unambiguous in both directions. Runtime changes
require renewed review and explicit reconciliation; no implicit journal migration
is performed.

Composition passes negative configuration and race checks. The installed
interactive path has also signed actual development-chain operations in both
directions. Preparation alone still grants no signing authority.

## Interactive managed activation command

The host command now connects the composed runtime to manual terminal unlock:

```sh
/absolute/private/installation/releases/BUNDLE_HASH/vortex-host \
  --root /absolute/private/installation \
  --config /absolute/private/runtime.json \
  --trust /absolute/private/publishers.json activate
```

Use the exact privately installed executable; all review/artifact bindings apply.
The installation lock remains held for the process lifetime. The password is read
from the local terminal with echo disabled, before the command reader starts.
There are no password arguments, password environment variables or unattended
unlock flags. After activation, enter `status`, `sign DIRECTION/TRANSACTION:INDEX`,
or `stop`. Signing returns public signatures only and does not submit a transfer.
EOF, stop, cancellation or output failure closes keys and the session; shutdown
persistence errors propagate to the caller. Unlocking again requires an explicit
new invocation. No automatic signer restart is enabled.

Linux tests drive the command-loop function with synthetic encrypted keys and
verified fixture operations in both directions, then test cancellation with a
blocked input pipe. Separate installed-command exercises now cover actual RPC nodes, terminal
unlock, crash recovery and fenced replacement in the single-host laboratory.
Full two-host and boot-time service acceptance remain outstanding.

## Permission changes during transfer reads

Each signing request rechecks live readiness after reconstructing the transfer,
before either returning a previously stored signature or creating a new one. A
new signature requires another readiness check after durable intent persistence.
Changed approval, membership, host readiness or expiry locks the session. A failed
last check leaves an unsigned pending intent for later reconciliation.

Nine Linux synthetic-vault cases cover revocation during receipt reconstruction
for both new and retained signatures, plus final-permit failure after intent
persistence. This is a local freshness boundary, not an atomic guarantee against
later chain changes; destination contracts still enforce current authority when a
transfer is submitted. Full real-chain acceptance remains outstanding.

## Prepare a host review request

After creating the private control records, invoke the exact installed host tool:

```sh
/absolute/private/installation/releases/BUNDLE_HASH/vortex-host \
  --root /absolute/private/installation \
  --config /absolute/private/runtime.json \
  --trust /absolute/private/publishers.json \
  --host-profile standard review-request
```

This holds the installation lock and verifies the current installed release,
then writes private `host-review-request.json`. It contains the review body and
`canonicalHex`, the exact canonical bytes to be independently inspected and signed.
It contains no signature and cannot be used as `SignedHostReview`. Missing records
are errors; the command does not generate success declarations. Keep the request
and actual host binding private, outside repository evidence.

The reviewer must inspect the control records and matching review body before
signing. After verification, the separate signed review uses only `review` and
`signature` fields; its public key must match the locally pinned reviewer key.
Preparing or signing this review is not operator enrollment, release approval or
permission to bypass chain checks. End-to-end Linux command/reviewer/activation
acceptance remains outstanding; current tests cover canonical payload binding,
unsigned-request rejection and missing evidence.

### Actual Koinos replica compatibility check

The managed snapshot reader uses `chain.invoke_system_call` / `get_object` to
read kernel contract metadata (system space 3, empty zone, contract-address key).
For pause storage it supplies the contract's `user_mode` caller context and reads
space 100002. An absent pause object is the reviewed contract's unpaused state;
malformed object responses still reject activation. The native
`get_contract_metadata` thunk is not available on the tested Koinos 1.5.2 node.
The JSON-RPC descriptors must expose `invoke_system_call` and `caller_data`;
the tested node build uses koinos-proto 2.6.0. Old 1.0.0 descriptors do not suffice.

`TestIsolatedKoinosAcceptance` is opt-in with `-isolated-koinos-acceptance` and
expects the documented Prompt 03 synthetic chain, bridge and irreversible height
194 (the delivery checkpoint). It reads live RPC at `127.0.0.1:18081` and replica RPC at `127.0.0.1:18082`.
In the isolated Docker laboratory, same-container loopback forwarders connect
those ports to the separate live/replica JSON-RPC services on the internal network.
This preserves the endpoint policy; ordinary HTTP remote endpoints remain rejected.
The test performs no mutations and uses no keys. It intentionally fails if the
fixture's chain, code, membership or height changes. It is actual reader coverage,
not evidence of independent hosts or a completed managed signer lifecycle.

The companion `TestIsolatedEVMAcceptance` opt-in check uses
`-isolated-evm-acceptance` and a loopback forwarder at `127.0.0.1:18083`. It
verifies the fixed Prompt 03 reviewed EVM deployment, current membership and
finalized code/state through the actual managed reader. The laboratory runs
Hardhat 2.22.6 / EDR 0.4.1 with network ID 31337, no public ports and no forks.
Its finalized tag is a local development-node behavior, not public consensus.
The reviewed runtime is 27,908 bytes; this lab explicitly permits oversized
contracts. This does not establish deployability under the public EVM size limit.

With both isolated-chain flags, `TestIsolatedEVMTransferRead` reads the fixed
synthetic deposit recorded in the Prompt 03 evidence. One mock WETH is escrowed
on Ethereum and reconstructed as 100,000,000 bridge units (8 decimals), with
zero relayer payment. The reader also queries irreversible Koinos completion
status and reconstructs the destination digest. The synthetic destination token was deployed and approved separately at the
height-132 checkpoint. This reader check does not independently enforce token
support or prove signature issuance or completed delivery on Koinos.

`TestLinuxBundleCLIInstallRunStop` optionally accepts `-host-review-request` to
exercise review drafting with the exact privately installed executable. It
checks installed artifact/configuration/control hashes, unsigned output and
preservation of the previous draft when a control record disappears. A valid
Linux machine ID is required. The Docker acceptance run supplies an explicitly
synthetic machine ID and synthetic control records; it does not establish actual
host-security approval, candidate qualification, unlock or signer activation.

### First actual installed signing exercise

The Prompt 03 laboratory has now exercised `activate` from the exact installed
bundle against both actual development chains. The candidate checker ran with
no network and no host mounts before publisher/local approvals were assembled
from synthetic reviewer identities. A separate runtime container used that
qualified installation, a synthetic encrypted vault, and a signed synthetic
host review. The review exercises the software gate; it is not a review of real
operator infrastructure.

Minimal containers need a writable private user configuration directory for
same-user signer locks. In this fixture, `XDG_CONFIG_HOME` points inside the
private installation directory. It contains lock files, not the vault password.
An absent/unwritable user configuration path rejects activation before unlock.

The actual terminal exercise required hidden manual unlock, signed the verified
EVM-to-Koinos pending operation, stopped cleanly, then required another manual
unlock on restart. One operation was retained and the same signature returned.
A concurrent activation on the same installation was rejected. Independent
koilib recovery identified the expected Koinos signer from that public signature.

This proves one installed-container activation/sign/stop/restart path. It does
not prove host-loss recovery, two independent hosts, production host controls,
secret-free backup/restore, destination execution or fenced replacement.

### Actual two-validator delivery in one development laboratory

Two separately installed synthetic validators with distinct EVM/Koinos identities
have manually unlocked and signed the same actual pending deposit. The destination
bridge rejected one signature and accepted both, delivering 100,000,000 units to
the intended recipient. At Koinos live height 254, delivery block 194 is
irreversible and the pinned replica matches its ID/state root. The actual reader
reports completion. Restarting the first installed signer reconciled its retained
operation to `completed`; the command returned its existing signature and generated
no new signature. Both signing processes are stopped.

Submission used the pinned bridge.proto, because the historical scripts' ABI
contains obsolete complete-transfer field numbers. The separate protobufjs
preimage check also omits default-zero fields to match the reviewed contract and
Go protobuf serialization. Neither correction changes the reviewed bridge Wasm.

Both containers share the same physical Docker host and synthetic host controls.
This is transfer/lifecycle evidence, not independent operators, host-loss recovery
or fenced replacement acceptance.

## Retired-identity journal migration

`vortex-host recover-retired` now provides a locked migration path when a lost
host is replaced with new identities on both chains. This closes a gap in which
`Open` correctly rejected the old policy digest but no supported import path
existed. It does not authorize reusing the old keys on a second host.

Preserve the original backup and its exact `managed.Policy` JSON (public identity,
instance and artifact/configuration hashes). Prepare a fresh replacement
installation, candidate qualification, local release approval, configuration and
host review. Set `previousEvm` and `previousKoinos` to the retired identities and
use a new encrypted vault. Never remove a live journal to force import.

Pass absolute private paths before the command:

```sh
vortex-host --root /private/replacement --config /private/replacement/runtime.json \
  --trust /private/replacement/trust.json \
  --previous-policy /private/backup/policy.json \
  --previous-journal /private/backup/session.json recover-retired
```

The command holds the installation lock, accepts only a fresh locked session,
checks source policy integrity and retained signatures, verifies finalized
retirement of both identities, rereads every operation and reconciles the new
checkpoint. Changed digests and completed-to-pending regressions are rejected.
Old signatures are excluded from the replacement journal; the original backup
is untouched. A final live check precedes persistence. No vault password is
requested. Subsequent interactive activation repeats all gates and reconciliation.

Automated coverage includes partial retirement, retirement changing during
import, invalid signatures, changed operations, completion regression, checkpoint
failure and refusing a second import. Installed-artifact acceptance of this new
command and full independently hosted replacement remain outstanding.

## Installed retired-key recovery acceptance (development laboratory)

The clean-source `d3be5df` Linux ARM64 bundle was built twice with identical SHA256
`595e1786bb2f96303d6f075e235621113fe80e4c184516a07e96b52475d27a7c`.
Its actual isolated checker passed before a fresh synthetic local release approval.
A third container with another synthetic machine identity installed that bundle.

An active old signer journal contained one completed transfer and one newly
signed pending transfer. After preserving its encrypted backup, the entire old
runtime container was killed. The replacement uses new EVM and Koinos identities.
Installed `recover-retired` rejected attempts before rotation, after EVM-only
rotation and before finalized Koinos rotation/replica agreement. Once both prior
identities were retired and the replacement enrolled, it imported two public
operations while leaving the vault locked. Interactive activation then signed
the pending operation with the replacement identity.

Koinos rejected delivery using the retired signature plus a current validator
(`is not a validator`). The installed replacement and second validator signatures
completed delivery at block 319. After finality and replica agreement, restarting
the replacement reconciled completion and retained its own signature. Both
signing processes were then stopped. Actual snapshot/transfer/rotation reader
checks passed; the retired policy was rejected against finalized memberships.

These containers share one physical Docker host and synthetic control reviews.
This proves the installed recovery path on actual development chains, not two
independently administered hosts or complete secrecy/backup acceptance. Reverse
route and independent-host lifecycle exercises remain required.

## Mutable, non-authoritative Koinos receipt hints

The runtime checks pinned `blockHints` first, then reads the private installation
file `operation-hints.json` for new receipts. The file is a JSON map from canonical
`transaction-id:event-sequence` strings to positive block heights, without the
`koinos-to-evm/` prefix. Update it atomically with owner-only permissions. It must
not exceed 512 KiB or 4096 entries; duplicate keys and invalid heights are rejected.

These hints only locate source receipts. Every receipt, transaction ID, event,
block hash, network, destination and irreversible anchor is still independently
checked. Changing a hint grants no authority and does not modify the approved
runtime configuration or journal policy. Missing or incorrect hints reject the
operation. This permits new Koinos transfers without repeated configuration and
host-review changes.

## Reverse-source acceptance and token fixture correction

The actual Koinos source transfer is irreversible at block 383, event sequence 3,
with normalized amount 100000000 and destination bridge chain 1. The real reader
rejected a wrong block hint and reconstructed the expected EVM signing digest
`db1bcb2dbc150f7f7746e5a15cc112230e5924f092a4052fc616d92be488ba85`.
Installed reverse signing and destination delivery remain pending.

The synthetic wrapped-token fixture required an additional correction before
this source exercise: its `approve` event dereferenced `callArgs`, which the token
class and generated entrypoint never initialized. Without allowance the source
transfer was rejected; adding approval trapped. Initializing `callArgs` with
`System.getArguments()` in the temporary token copy allowed approval and transfer.
The development token was updated at block 382, retaining supply 200000000. Its
new Wasm SHA256 is `08e5af270038c36010be25a30424ed344cd31611379e99e87a4056ff4143912e`.
The reviewed bridge Wasm and original contract repository are unchanged. This
fixture correction is not evidence that an unmodified deployed token works.

## Installed reverse signature and EVM delivery

Bundle `f30d36a2cfb8d015d532fd5a00eb38e7adfe6df5e1612b062c195f9555ba902d`
(source `189c6d3`) passed the actual isolated candidate checker before fresh local
approval. A fresh third synthetic validator installed it, manually unlocked and
signed the irreversible Koinos operation at block 383, event 3. The runtime read
its location from private `operation-hints.json` without changing policy.

An independent ethers reconstruction matched the managed EVM digest and recovered
validator `0x90F79bf6EB2c4f870365E785982E1f101E93b906`. One signature was rejected
by `callStatic` with quorum not met. The actual two-signature delivery succeeded
at EVM block 11; recipient balance change plus gas was exactly 1 ETH and bridge
escrow fell from 2 WETH to 1 WETH. The second signature came from a published
Hardhat fixture account, not a second installed runtime. Therefore this does not
claim two-installed-validator reverse acceptance.

Restarting the third installed validator reconciled completion and retained the
same signature. It was then stopped. All five actual-chain reader checks passed.
The checkpoint-specific acceptance test now expects Koinos irreversible height
383 and completed reverse delivery. Source token fixture correction and local
EVM finality/contract-size limitations continue to apply.

## Same-host artifact upgrade with retained managed journal

`upgrade-state` is a narrow transition between approved executable hashes. Stop
signing before installation, preserve the old public `managed.Policy` JSON and
its signed host review, then install the compatible release using the normal
publisher signatures and local approval. Obtain the new signed host review and
candidate qualification. Keep configuration bytes, identities, instance and
previous-retirement identities unchanged. Complete this transition on the same
machine, boot and dedicated user; host replacement uses `recover-retired` instead.

```sh
vortex-host --root /private/validator --config /private/validator/runtime.json \
  --trust /private/validator/trust.json \
  --previous-policy /private/upgrade/previous-policy.json \
  --previous-host-review /private/upgrade/previous-host-review.json upgrade-state
```

The supervisor holds the installation lock; the transition requires an existing
locked journal and takes its session lock. The old review must have a valid
signature from the currently pinned reviewer and bind the previous artifact and
configuration to this exact machine/boot/user. An expired historical review can
prove continuity only: it never grants new release or host approval. The current
artifact must independently pass fresh release, host, network, final membership
and provenance gates, including retirement gates when applicable.

Every retained operation is reread under the new artifact. Changed digests,
changed families and completed-to-pending regressions are rejected. Public
signatures are retained because both identities remain identical. A fresh
checkpoint and final live gate precede atomic journal replacement. No keys are
unlocked. Repeating the completed command rechecks continuity and current gates
without repeating migration. Activate separately through manual unlock.

Automated tests cover signature retention/reopen, completion, altered config,
instance, identities and retirement policy, active signer refusal, wrong host,
tampered prior review, missing or revoked approval, changed operation digest and
checkpoint failure. Installed old-to-new package acceptance remains pending.

## Installed same-host upgrade acceptance

The existing second synthetic validator upgraded from the 0.3.0 bundle
`fb9db50e…f21120` to qualified 0.3.1 / sequence 2 bundle
`379f547b5f94a1e5af479646f1dda3af0c41b6e802a737ca99c31ab1cbd42944`
(source `6e9e010`). The old installed host command performed installation twice;
the new installed `upgrade-state` ran twice. Both retained operations and their
exact public signatures survived, and the vault remained locked throughout.

The new executable then manually unlocked, activated against both actual chains
and returned the existing completed operation with its identical pre-upgrade
signature. After stopping, activation using the retained old executable failed
before password input because the journal no longer matched its policy.

Fixture scope: the laboratory generated a fresh synthetic reviewer and renewed
the old-artifact review before installation, then used that same reviewer for the
new review. The fixture also enrolled a fresh synthetic publisher trust record.
This is not a production reviewer/publisher rotation procedure. Machine, boot,
user, configuration bytes, signing identities and encrypted vault were retained.
The runtime still shares the single physical laboratory host; independent-host
acceptance and a new reverse transfer signed by two installed runtimes remain.

## Two installed validators complete the reverse route

A new synthetic Koinos transfer at irreversible block 444, event 3 was read and
signed independently by installed validators two and three after manual unlock.
The second validator used the upgraded 0.3.1 bundle; the third used its qualified
0.3.0 bundle with mutable receipt hints. Both reconstructed digest
`d55874027e88de997abd1732026d2fe35cbdd4ca26f2a7b2c61b28aae4f85a38`.
No fixture helper produced either signature for this delivery.

EVM `callStatic` rejected one signature. The actual delivery with both installed
signatures succeeded at block 12, releasing exactly one development ETH and
reducing bridge escrow to zero. The second runtime reconciled completion while
active; the third reconciled it after stop and manual restart. Both retained
their original signatures and were stopped afterwards. All five actual-chain
reader checks passed at Koinos irreversible height 444.

This closes the helper-signature limitation for the local reverse-route test.
It does not establish independently administered machines or general mixed
version compatibility; only these exact artifact hashes and operation were
exercised in the single physical laboratory.

## Two separate Linux development hosts: chain reads and candidate import

The exact AMD64 test bundle `f5e24524db413588ab3b4f249c21ea0c26cb1f362c5ee68d4aa9c78360c9bc23`
from source `aac1a66` is installed on two separate rebuilt Ubuntu hosts under a
dedicated non-root user. Temporary loopback-only reverse tunnels let both hosts
read the actual isolated Koinos and EVM test chains. Each passed the five opt-in
chain acceptance tests: irreversible Koinos membership, finalized EVM membership,
EVM transfer read, retired-identity rejection and reverse transfer read. These
tests used separate binaries built from the unchanged runtime source.

The test-only fixture generator `scripts/validator-acceptance-fixture.go` creates
a short-lived signed validator release from an exact bundle using an ephemeral
synthetic publisher identity. Its private key is never written to the fixture.
On a real AMD64 Docker engine, the actual candidate checker passed all eight
observation and negative checks with `--network none`, a read-only filesystem,
no host mounts and non-root UID 65532. The result digest was
`cb61f9ab75261675e396b51d475e7715c27e081cc851c02aa978a32cbbe510a8`.
The temporary Docker installation was then removed from that host.

Fresh short-lived synthetic operator approvals updated the first installation
from sequence 2 to 3 and the second from 1 to 2. Both imported that same exact
candidate result; their keyless loopback observation services remain active and
`managedSigning` is false. The installed `activate` command rejected an old
retired signer identity on each host before asking for a vault secret. A separate
fresh installation on the second host rejected a current signer configuration
without signed host review; `review-request` required the private host control
records. An earlier attempt to change the main installation's policy was also
rejected by its retained journal, which was left intact.

These checks establish installed fail-closed gates and actual candidate import,
not an installed signer session on either physical host. Host control review,
manual unlock, distributed signing, host-loss fencing and signing-key recovery
remain open. Both hosts are controlled by one operator and one hosting account.
