# Private operator service (implementation in progress)

This branch adds a separate `vortex-operator` command without bridge signing keys. Optional
maintenance endorsements use a separate local scheduling identity. The `cmd/koinos-bridge-validator` runtime now supports keyless observation and
a private control socket. Do not interpret an operator dashboard connection as
a running or enrolled validator.

Implemented: durable private deployment configuration, read-only EVM/Koinos
observations, governance payload encoding, signature verification primitives,
signed release-manifest verification, per-instance local approval/revocation,
independently running observation workers with locally reviewed executable and
configuration hashes, and read-only attachment to an independently started
signing worker for maintenance key-possession proofs.
Pending: managed signing and cross-host fencing, complete host provisioning, transfer
history integration, governance collection/submission/finality,
backup/restore packaging, complete candidate regression coverage and coordinated rollout.
Local artifact staging and a restricted observation smoke runner are implemented.

## Local build and service

The development verification used Go 1.24.2 and the existing `go.mod`/`go.sum`.
These commands do not deploy a bridge or load signing keys:

```sh
go build -trimpath -o /tmp/vortex-operator ./cmd/vortex-operator
/tmp/vortex-operator --data "$HOME/.local/share/vortex-operator" serve
```

The command creates its directory with mode 0700; an existing directory must
already have private permissions. Choose a directory separate from the legacy
validator's `.koinos` directory. An exclusive lock prevents concurrent operator
processes using the same state directory. This is local process exclusion, not
proof that signing identities are fenced across hosts.

Management binds `127.0.0.1:3021` and only accepts the matching HTTP Host. The
default trusted browser origin is `http://127.0.0.1:5173`; use `--origins` to set
an explicit comma-separated list. Non-loopback management binds are rejected.
Use an SSH tunnel for a remote operator. Do not expose this port through the
public validator proxy.

The private `access-token` file is generated on first start. Enter its contents
into the local UI's **Operator access token** field. It is not printed by the
service, included in status responses or saved in browser storage. `instance-id`
identifies this operator instance for local release approvals and must be
preserved with operator state. Do not clone an approved instance into a second
active operator as a deployment shortcut.

Flags precede the command. Supported commands include `serve`, `status`, `token-path`,
`worker-register`, `release-stage`, `release-adopt` and `candidate-test`; `token-path` prints only the file path. The current offline CLI
opens the same exclusive state lock, so stop this operator service before using
`status`, `token-path`, `worker-register`, `release-stage`, `release-adopt` or `candidate-test`. A running instance's authenticated HTTP API can read
status without stopping it. Stop the service with SIGTERM/Control-C.

## UI and synthetic integration fixture

From `interface-bridge`, install using its committed npm lock and start Vite:

```sh
npm ci --legacy-peer-deps --ignore-scripts
npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open `http://127.0.0.1:5173/operate`. Existing bridge/redeem routes are preserved.
The ignored lifecycle scripts cause image-optimizer warnings during builds;
this is a recorded development baseline, not a reproducible production release.

An optional **synthetic RPC**, which does not execute EVM contracts, is available:

```sh
node scripts/operator-rpc-fixture.cjs
```

In the UI, add an EVM/local deployment with actual network ID `31337`, internal
bridge ID `2`, contract `0x1111111111111111111111111111111111111111`, and RPC
`http://127.0.0.1:18545`. This fixture returns three synthetic validator addresses
and a quorum of two. It proves UI/API/read-adapter integration only. It is not
an end-to-end bridge or independent-host test. Stop it when finished.

## Independent validator process

### Guided initial configuration

An empty instance can now create its first observation worker from saved EVM
and Koinos deployments. First stop the operator service and prepare a locally
reviewed executable for that instance (replace the paths and digest below):

```sh
/tmp/vortex-operator --data "$HOME/.local/share/vortex-operator" \
  --instance my-route instance-create
/tmp/vortex-operator --data "$HOME/.local/share/vortex-operator" \
  --instance my-route --worker-binary /absolute/path/to/reviewed-validator \
  --worker-sha256 REVIEWED_SHA256 worker-prepare
```

Skip `instance-create` for an existing empty slot. Flags precede the command.
`worker-prepare` privately copies and checks the exact executable bytes; it does
not establish publisher provenance or approve a release. It refuses an existing
preparation or registered worker. Restart the operator service, select the slot
in the interface, and save both deployments through **Add deployment**. Their
environments must match and their protocol chain IDs must differ.

In **Validator**, select the two deployments, set explicit first scan blocks,
confirmation distance and a separate loopback API port, and enter known token
pairs and peers. Review **Configuration preview** and select **Create observation
worker**. The preview distinguishes actual network IDs from bridge protocol IDs,
includes the public mappings and exact configuration hash, and can be exported.
RPC and peer URLs stay in local private configuration; they are excluded from
the public preview and creation receipt. EVM mapping addresses are canonicalized
to the checksum form expected by the legacy runtime.

Creation binds to the configuration revision and preview digest. Editing a field
requires another preview. A retry of the exact creation request returns the
same durable receipt, including after an operator restart; changed requests
cannot replace an existing worker. Reload setup can recover a completed request
whose response was lost. A failure before publication may leave a history intent
and require a fresh preview. The bundle is published at the selected instance's
`managed-worker` directory with private configuration, registration, observation
mode, network binding and receipt together. Existing directories are never
adopted or overwritten by setup. Registration of an independently prepared
existing directory remains available through `worker-register`.

Setup opens no databases, starts no process and configures no signing keys.
Run preflight and review its results, then start observation as a separate action.
The current defaults are three-second polling and batches of at most 100 blocks
on both chains. Start blocks must be positive exact decimal integers no larger
than 2^53−1; confirmation distance is 1–100000, and API port is 1024–65535 on
127.0.0.1. Up to 256 token pairs and peers are accepted, subject to the bounded
configuration size. Empty mappings are allowed for initial observation, but do
not establish useful transfer interpretation or peer participation.

Start heights, token pairs and peers still require route-specific reconciliation.
Saved profiles and syntactically valid mappings do not prove deployed contract
correspondence, finality, membership or independent custody. Boot bundles, host
installation and policy-controlled signing remain separate unfinished work.

### Runtime lifecycle

The validator supports `--observe-only` or `bridge.observation-only: true`.
In this mode it never opens configured key files, decodes keys, creates transfer
signatures, renews signatures or broadcasts to peers. `/SubmitSignature` returns
403. Observed transfers retain the legacy gathering-signatures status with empty
signature arrays; a new transaction schema/history UI is still pending.

Each validator directory holds its own Badger stores and private
`bridge/.operator` directory. A process lease excludes a second local process;
Badger synchronous writes persist transaction records before batch checkpoints.
An incomplete Koinos block batch or invalid EVM log range cannot advance the
checkpoint. Existing start heights no longer rewind a nonzero checkpoint on
every restart. An abrupt-exit test verifies that a saved EVM range is not replayed.
This retains the legacy streamer's confirmation/RPC trust model; it does not
resolve source-level transfer verification or reorganization findings.

The private Unix socket exposes authenticated health and graceful stop. Stop
requests bind the current PID and start timestamp; no arbitrary PID signaling
endpoint exists. The dashboard and operator may exit while the validator keeps
running. Health describes observation freshness, not quorum or signing readiness.
For control paths of 100 bytes or more, the socket uses a hash of the canonical
control directory under `/tmp/vortex-control-<uid>`. That parent must be a real,
private directory owned by the current UID; sockets remain mode 0600. The token
and process lease remain in persistent worker state. Short paths keep their
existing socket location. Do not remove the temporary socket directory while
workers run: doing so interrupts management access even though the worker and
its persistent process lease may remain active. This change addresses native
Unix-socket path limits; it is not a host service installer.
The `data-mode` marker prevents silently turning observation checkpoints into
signing history, or adopting existing signing data as observation data. Use
separate candidate directories; a mode-migration workflow is not yet implemented.

For the legacy standalone signing command, `ethereum-pk-file` and `koinos-pk-file`
accept local regular files with no group/world permissions; symlinks are refused.
Do not supply both inline and file values for a key. Local per-public-address
leases under the OS user's configuration directory exclude accidental duplicate
signers on that user account. These locks do not fence cloned keys on another
host or another OS account. Managed signing remains disabled.

### Register a reviewed worker

Build and review the local validator executable, prepare a private base directory
with a mode-0600 `config.yml`, and give it a stable `bridge.instance-id`. The
configuration must contain no inline keys and must not request a database reset.
With no existing `data-mode` marker, registration creates an observation-worker
record. An existing private `data-mode` marker may instead identify a `signing`
worker that was already started through an independently reviewed host service.
That signing configuration must reference both keys through external key files;
inline keys are refused. The operator records the file paths as part of the
configuration digest but never opens the key files. Stop the operator service
first; registration does not stop an independently running validator.

```sh
go build -trimpath -o /tmp/vortex-validator ./cmd/koinos-bridge-validator
shasum -a 256 /tmp/vortex-validator
/tmp/vortex-operator --data /absolute/private/operator-directory \
  --worker-base /absolute/private/validator-directory \
  --worker-binary /tmp/vortex-validator \
  --worker-sha256 REVIEWED_SHA256_FROM_PREVIOUS_COMMAND worker-register
```

The command snapshots the executable into a private hash-named location and pins
the configuration digest. Restart the operator, open **Validator** in the panel,
and start an observation worker. Changes to the reviewed configuration or binary
are refused at startup. A registered signing worker cannot be started by the
operator; start it through its reviewed host service, then reload the panel. The
panel can observe it, request the fixed maintenance proof from that same process,
and issue a reviewed graceful stop, but it cannot provide executable paths, shell
commands or key material. Stop requires review of the currently observed process.
Start and stop intents are recorded durably; an intent is not proof of completion.

This initial registration is not a security-update installer or an OS boot service.
Replacing a registered binary/configuration, automatic recovery after host reboot,
log rotation, backups and approved release activation remain implementation work.
Do not edit registration files as a routine update mechanism.

For disposable local UI testing, run `node scripts/operator-worker-fixture.cjs`
from this validator repository. It exposes synthetic empty-chain heads on
`127.0.0.1:18546` and rejects all other RPC methods. Set both worker RPC URLs to
that endpoint and its public API to a free loopback port. This is a runtime smoke
test, not contract execution. The standalone test suite additionally runs two
separate real validator processes, verifies signature refusal, crash recovery,
independent shutdown and operator restart/adoption against synthetic RPC.

## Observations and governance boundaries

EVM reads use a finalized block, check network and contract bridge IDs, hash the
runtime code, read membership/nonce/pause and recheck the block hash afterward.
Failed reads are incomplete, not zero-valued healthy state. Observations expire
after 30 seconds; configuration changes invalidate cached observations.

Koinos reads bracket metadata/membership with head snapshots. They do not yet
pin irreversible state or attest Wasm. The reviewed source has no pause getter;
the UI displays unknown. Koinos governance readiness is therefore disabled.
Production governance is disabled for every profile in this build.

Profiles distinguish actual network ID from protocol chain ID. The legacy
signing format binds the protocol ID and contract, but not the actual RPC/wallet
network ID. Changing off-chain profile metadata cannot repair that contract-level
limitation. Deployment-domain review remains required before signing enablement.

The pure codec supports the reviewed source versions. Koinos token registration
does not include a fee; fee changes are separate actions. Wrapped Koinos fee
claims are rejected because the reviewed verifier uses the ordinary fee-claim
action ID. All payloads returned by HTTP are unsigned drafts, not approvals.

## Release verification and approval

Install a **reviewed local public-key policy** as a mode-0600 `release-trust.json`
file in the operator directory. There is no HTTP trust-root editing endpoint:

```json
{
  "schemaVersion": 1,
  "requiredSignatures": 2,
  "publishers": {
    "publisher-a": "REPLACE_WITH_REVIEWED_32_BYTE_ED25519_PUBLIC_KEY_HEX",
    "publisher-b": "REPLACE_WITH_ANOTHER_REVIEWED_PUBLIC_KEY_HEX"
  }
}
```

This example is intentionally not a usable trust policy. Required signatures
are operator policy; aliases for the same public key cannot count twice. Release
signatures cover the exact bytes returned by `CanonicalRelease` in
`internal/operator/release.go`, whose ordered JSON schema is the current v1
format. Unknown HTTP fields are rejected. A general cross-language canonical
JSON standard and release-authoring CLI remain pending; do not independently
reserialize arbitrary manifest objects and assume equivalent signatures.

Release verification checks signatures, validity dates, source/artifact metadata
and bounds. It does not establish the truth of the publisher's test claims.
Artifact bytes must separately pass verification. The local `release-stage` CLI
streams the selected platform artifact into private storage, checking signed
length and SHA-256. It rereads current publisher policy and rehashes bytes before
candidate execution. No artifact is downloaded or executed by the HTTP routes.

Approval records bind the manifest digest, component, sequence, local operator
instance and activation window. They survive restart and can be revoked. The
release sequence remains recorded after revocation to prevent replay/downgrade.
Re-approving an old sequence or extending an expired approval currently requires
a future reviewed recovery workflow; it is not silently allowed. The future
installer must reload current approval and publisher policy and enforce
`CheckActivation` immediately before changing a process, alongside compatibility,
backup and quorum checks. An approval response is not an installation receipt.

For UI verification only, `interface-bridge/scripts/operator-release-fixture.cjs`
creates a public, deliberately insecure test publisher policy and a signed
non-executable artifact manifest. It only accepts a temporary directory whose
name starts `vortex-operator-dev.` and refuses to replace existing fixture files.
Never use its keys or policy in an operational deployment.

## Local candidate staging and isolated smoke check

Stage already obtained, reviewed release metadata and artifact bytes with the
operator stopped. The service currently limits staging to 16 manifest digests
and 256 MiB per artifact; reviewed retention tooling is still pending.

```sh
/tmp/vortex-operator --data /absolute/private/operator-directory \
  --release-file /absolute/signed-release.json \
  --artifact-file /absolute/validator-linux-arm64 \
  --artifact-platform linux-arm64 release-stage
```

A staged release is neither approved nor installed. Metadata listing does not
rehash large artifacts; the actual test/activation path must reverify bytes.
Changing current publisher policy can block previously staged manifests.

Before evaluating future updates, bind the already registered worker to its
exact current signed release. This is a one-time local bootstrap action per
operator instance:

```sh
/tmp/vortex-operator --data /absolute/private/operator-directory \
  --release-digest EXACT_STAGED_CURRENT_MANIFEST_DIGEST \
  --artifact-platform linux-arm64 release-adopt
```

The command re-verifies publisher policy and staged artifact bytes, then requires
the artifact SHA-256 to equal the operator's pinned worker binary. It also
rehashes the registered configuration. It writes a private current-release
identity and does not install, start or stop software. Repeating the exact action
is idempotent; adoption cannot replace an existing identity. Restore a damaged
identity from reviewed local evidence instead of adopting a different release.

The Updates page rechecks the pinned binary, registration and configuration
before showing that identity. Every staged validator is then compared with the
recorded sequence, predecessor versions, configuration and database schemas,
signing codec, and signed mixed-version declaration. Only an exact compatible
set is labeled eligible for further rolling qualification. This compatibility
label does not replace candidate testing, local approval, backup, participation,
activation, verification or recovery gates. The installer remains disabled.

The console can record a point-in-time **update readiness receipt** for a selected
staged release. Supply the ID of a completed encrypted backup and the fresh signed
participation-response array collected for the reserved maintenance plan. The
operator rechecks the exact current and candidate bytes, current publisher policy,
version/schema/codec compatibility, the current version-2 candidate report,
local approval window, fresh bound worker observations, post-approval backup
integrity, reservation, authenticated participation and wave order together.
Each pass, block or unknown result is retained in the private
`update-readiness/` history and can be exported from the interface.

Readiness receipt IDs are immutable: an exact retry returns the original receipt,
while different evidence needs a new ID. Receipts expire after at most 30 seconds
and always remain non-authorizing in this implementation. Signed worker telemetry
can now carry a domain-separated proof that the responding process possesses both
bridge keys mapped in local maintenance policy. The participation report excludes
the updating operator and evaluates both contract-stage key thresholds. This does
not prove current on-chain membership, productive bridge signing or the
peer/API/frontend stages, so signing quorum remains blocked. Later waves also
require the immediately preceding operator's signed result. The
install/verify/recovery state machine remains missing, `installerEnabled` stays
false, and no receipt permits stopping or replacing a validator.

The fixed `cmd/vortex-candidate-check` program can be built for the local Docker
engine's native Linux architecture with `CGO_ENABLED=0`. Review its source and
hash independently of the release being tested. Invoke the local smoke runner:

```sh
/tmp/vortex-operator --data /absolute/private/operator-directory \
  --release-digest EXACT_STAGED_MANIFEST_DIGEST \
  --artifact-platform linux-arm64 \
  --candidate-checker /absolute/reviewed-checker-linux-arm64 \
  --checker-sha256 REVIEWED_CHECKER_SHA256 candidate-test
```

The build context contains only a fixed scratch Dockerfile, the digest-verified
artifact and the reviewed checker. No Docker build RUN commands are used. Before
executing the candidate, the runner inspects the created container: native local
Unix-socket Docker engine, no network, read-only root, non-root UID, all Linux
capabilities dropped, no new privileges, no host mounts and bounded resources.
Work data is disposable tmpfs. The candidate cannot access the operator directory,
production configuration, Docker socket or signing keys through this container.
Only resources with this invocation's randomly generated names are removed.

The report binds exact artifact/checker hashes and records keyless startup, chain
observation, signature refusal, duplicate-process exclusion, crash/checkpoint
recovery, graceful shutdown and disallowed RPC attempts. Its scope is explicitly
`isolated-observation-smoke-v1`. It does not establish malicious-binary attestation,
transfer correctness, contract compatibility, migration safety or readiness for a
signing-quorum rollout. Full regression suites, test promotion, approvals and the
staged installer remain separate required gates.

## Multiple local bridge instances

One operator console can manage the existing `default` instance plus up to 16
named instances. Each named instance keeps separate configuration, history,
release trust/approvals, artifact staging and worker registration under the
operator directory. The validator data directories must also be separate, and
each worker needs a distinct `instance-id` and API port. Registration rejects a
directory or worker identity already owned by another local instance, including
concurrent registration attempts.

All instances in this console share the same local operator and host privileges.
They are useful for separate bridge routes, not evidence of independent validators
or failure domains. Independent operators need their own hosts, credentials and
operator stores. Managed signing remains unavailable.

Stop the local operator API before offline CLI changes; running validators keep
their independent processes. Create a named slot and register its locally reviewed
observation worker, using the same binary-review procedure described above:

```sh
/absolute/vortex-operator --data /absolute/private/operator \
  --instance koinos-ethereum instance-create

/absolute/vortex-operator --data /absolute/private/operator \
  --instance koinos-ethereum \
  --worker-base /absolute/private/koinos-ethereum-validator \
  --worker-binary /absolute/reviewed-validator \
  --worker-sha256 REVIEWED_BINARY_SHA256 worker-register

/absolute/vortex-operator --data /absolute/private/operator instances
/absolute/vortex-operator --data /absolute/private/operator \
  --instance koinos-ethereum status
```

Start `serve` on the root operator directory and connect using its root access
token. Choose **Local bridge instance** in the existing Operate page. Deployment
forms, observations, drafts, worker actions, updates and history use that selection.
Switching unmounts the previous workspace and clears its unsaved forms/drafts;
already requested operations remain bound to their original instance. It does
not stop workers or cancel actions already submitted. Reload the selected instance
to refresh the inventory after offline CLI changes.

`--instance NAME` also scopes release staging/testing and backup creation to that
instance's operator state. Backup commands still require explicit local worker
paths; inspect those paths before running them. A scoped release publisher policy
belongs in `instances/NAME/release-trust.json`; a root policy is not implicitly
inherited. Approval identities are distinct and persist across restarts. Trust or
approval records are not copied from another instance.

The root API remains compatible with the existing `/v1/status`, `/v1/worker`, and
other routes for `default`. Authenticated `GET /v1/instances` lists local slots;
`/v1/instances/NAME/status`, `/worker`, `/worker/start`, `/worker/stop`, `/updates`
and other existing suffixes address a named slot. Unknown slots, nested scopes
and path traversal are refused. HTTP cannot create slots or register arbitrary
filesystem paths. The root token grants access to this operator's local slots;
there is no per-slot multi-user access-control claim.

Instance creation prepares a complete private store before publishing its directory.
Missing/replaced stored identities, invalid descriptors or symlinked slots stop
startup rather than recreating release-approval authority. Interrupted `.creating-`
directories are not activated or shown as slots; inspect them locally before cleanup.
There is no automatic slot deletion or identity migration command in this build.

This supplies local instance management. Assisted route-to-worker configuration,
key provisioning and the installation wizard remain separate work.

## Observation preflight

The Validator page's **Run preflight checks** action diagnoses the selected
instance. Failures appear first. The equivalent local command is:

```sh
vortex-operator --data /absolute/private/operator --instance route-a doctor
```

As with other offline CLI commands, stop the operator API before opening its
store through the CLI; stopping the API does not stop its workers. The console
can run the same check while the API is serving. The CLI writes a sanitized JSON
report and exits nonzero when checks need attention. HTTP exposes it through
authenticated `POST /v1/instances/NAME/worker/doctor` with an empty JSON object.
It accepts no filesystem paths or ad hoc RPC endpoints.

The check verifies the registered configuration and binary bytes, directory
permissions, local ownership conflicts, explicit loopback API, observation data
marker and outstanding restore review. Both worker contract/RPC pairs must each
match exactly one saved deployment in the selected instance. RPC strings are
compared exactly, including credentials/trailing slashes, without displaying them.
It then performs fresh allowlisted contract reads against those bindings. Wrong
network identity, protocol chain ID, pinned code mismatch, unavailable RPCs and
configuration changes during the check produce failures. The two chain reads run
concurrently with a bounded deadline. Key files are never opened, binaries are
never executed and the check does not create worker directories or open databases.

`checks-passed` means these observation checks passed at the reported time. It is
not a start permit, release approval or signing readiness. The actual worker
acquires process/database ownership at startup; the doctor does not reserve
ports or locks. Peer/token reconciliation,
disk capacity, old-signer fencing and finality/source verification remain separate
work. Koinos head reads explicitly remain insufficient for code or irreversible
finality attestation. The report always sets `signingReady` to false. A successful
doctor exit cannot enable signing.

## Pin a worker route to its actual networks

New observation routes can pin both RPC network identities in their private
`config.yml`, alongside the two explicit contract addresses:

```yaml
bridge:
  ethereum-network-id: '31337' # Synthetic local EVM example; use the reviewed network ID.
  koinos-network-id: 'EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==' # Synthetic example only.
```

Supply both IDs or neither. EVM uses a canonical positive decimal network ID;
Koinos uses the canonical padded base64url SHA-256 multihash returned by its RPC.
These are **not** the Vortex protocol chain IDs used by contract signatures.
Doctor requires both IDs to match the selected instance's saved deployment
profiles; no pin is inferred from whatever an RPC happens to report.

The worker persists `bridge/.operator/network-binding.json` before opening new
databases. Restart refuses changed network IDs, changed contracts, missing IDs
after binding, or damaged markers. Existing unbound checkpoints cannot be adopted
under newly supplied IDs without a reviewed migration. Use a new route directory;
do not delete markers, reset state or overwrite registration to bypass review.
Case-only changes to a valid EVM contract address do not change its identity.

For explicitly bound workers, each chain reads its network ID before and after
the head read and again after fetching a batch, before processing events or
advancing checkpoints. Wrong, malformed or unavailable identity responses pause
that chain's ingestion and report `network-unverified` through the private health
socket. The other chain can continue observation. The affected chain resumes from
its retained checkpoint when the expected identity returns; no replacement
worker is launched. Identity and data requests use the same redirect-refusing
HTTP client. Identity checks have a five-second deadline; other bound reads time
out after ten seconds. Bound Koinos responses are limited to 32 MiB and its
transport only allows identity/head/block reads. Bound EVM RPC errors are
sanitized before logging private endpoint failures.

This detects inconsistent or misconfigured endpoints, not a dishonest RPC that
lies consistently about its identity and data. Contract-code attestation,
cross-provider verification and the existing chain-specific finality/reorg work
remain required. It does not repair legacy signature-domain omissions or enable
managed signing. Legacy configurations without either ID retain their old
streaming behavior; health omits the binding, the panel shows a warning, and
doctor fails the missing runtime binding check. Previously pinned executable
snapshots are not upgraded by changing the operator binary or UI.

## Verification commands

Encrypted offline backup and observation recovery are documented in
[BACKUP_RECOVERY.md](BACKUP_RECOVERY.md). Each operator keeps its own recovery
identity; active approvals and signing authority are not restored from an archive.

```sh
go test -count=1 -race ./internal/operator ./internal/worker ./internal/streamer
go test -count=1 ./...
go vet ./...
```

With the existing dependencies cached, prepend `GOPROXY=off GOSUMDB=off` to prevent
dependency downloads. For the backup test, first build its separate-module helper
and pass `VORTEX_BACKUP_CRYPTO_TEST_BINARY` as described in the recovery guide.
Governance vectors are generated independently with ethers
and protobufjs, using the actual Koinos protobuf source:

```sh
node scripts/generate-governance-vectors.cjs /absolute/interface-bridge /absolute/koinos-bridge-contract
```

The fixture generator normalizes protobuf defaults to match the checked-in
AssemblyScript encoder. Vector agreement is not yet proof that the calls pass a
real contract VM. The audit's existing source/deployment and accounting concerns
remain open. Do not advertise this branch as production-ready.

## Maintenance schedule exchange

The Updates panel and local CLI support portable operator-endorsed maintenance
plans. See [MAINTENANCE.md](MAINTENANCE.md) for local identity/policy setup,
reservation semantics, CLI exchange and synthetic reproduction. Schedule consent
does not install a release or replace fresh rollout preflight.

## Process-scoped transfer activity

Private worker health now includes separate `evm-to-koinos` and `koinos-to-evm`
activity summaries, displayed on the Validator panel. Tracking begins before the
worker starts streaming. Each summary records successful writes, new records,
changed signatures attributed to the configured local address, other changed
signatures, and transitions into the stored completed status. It includes its
tracking start and last successful-write timestamps. Counters are decimal JSON
strings, preserving the full uint64 range in browser consumers.

The transaction store compares the prior durable record with the exact serialized
bytes written successfully. Identical writes and signature reordering do not
create new-record/signature/completion counts. Failed writes are excluded. If the
prior record cannot be read or interpreted, signature shape is ambiguous, or a
counter saturates, the summary stays incomplete for that process. Telemetry read
failure does not veto a write that the existing storage path can still commit.
No payload IDs, signature bytes or private endpoints are exported in activity.

These are in-memory counters, not totals across the database. Restart starts a
new tracking interval; existing durable records are not automatically recounted.
Repeated initialization cannot reset the current interval or change its local
address attribution. Compare only snapshots from the same instance, PID, process
start, tracking start and reviewed artifact/configuration before drawing progress
conclusions. The two directions are sampled separately and do not form a globally
atomic transaction snapshot.

Stored signatures attributed to a local address do not prove that this process
created or cryptographically validated them. A stored completion transition is
not an independent receipt/finality check. The counters retain the legacy event,
signature and status semantics, including their unresolved verification risks.
They establish recorded activity beyond empty block polling; they do not prove
current quorum, peer/API/frontend participation, safe signing or update readiness.
Older workers omit activity; consumers must treat that as unknown rather than zero.

## Durable progress observation windows

In the Validator panel, **Observe progress over time** captures two observations
from the selected worker's authenticated local control socket. Start a window of
30–86,400 seconds with both pinned chains reporting fresh observations. Keep the
same process running, then choose **Finish progress window** after the minimum
duration and before the five-minute finishing allowance expires. Closing the
browser or restarting the operator service preserves the baseline. Finishing is
explicit; no background installer or scheduler runs from this panel.

The operator hashes the registered executable and configuration before each
capture. The comparison requires unchanged registration, artifact, configuration,
process ID/start time, mode, public signing addresses, network/contract binding and
activity tracking start times. Both chain observations must be no older than 30
seconds when sampled. Regressing heights, counters, or timestamps, missing activity,
and incomplete tracking invalidate the window. A stopped/replaced worker or an
expired window records failure. A completed receipt is historical: retrying finish
returns the same result and never refreshes its evidence.

Results distinguish new records, local-address and other signature changes,
completion transitions and successful writes for both directions. Empty polling or
identical writes yield `no-recorded-progress`. `recorded-progress` means at least
one derived store counter changed. Separate booleans identify recorded changes and
local-address signature changes in both directions. These are telemetry, not
independent signature verification, chain finality, current quorum or permission
to activate a release. `activationReady` remains false. The two samples do not
prove uninterrupted availability between them, and an operator-controlled host or
executable can falsify telemetry. Full candidate qualification and authenticated
stage participation checks remain separate prerequisites.

Authenticated API routes (also available under the selected instance prefix):

- `GET /v1/worker/progress`: current window and operator revision.
- `POST /v1/worker/progress/start`: `{ "id": "operator-chosen-slug", "expectedRevision": 12, "minimumSeconds": 300 }`.
- `POST /v1/worker/progress/finish`: `{ "id": "operator-chosen-slug" }`.

Requests cannot supply snapshots, counters, file paths or readiness claims. Retry
the same ID/settings after an uncertain start response. A different active window
cannot replace the collecting baseline. Finish an expired window to record its
failure before beginning another. Starting a new window archives the preceding
completed receipt under the instance's private `progress-history/<id>.json`;
`progress-window.json` stores the active/latest receipt. Archived IDs cannot be
reused, existing receipts cannot be overwritten with different content, and a
64-receipt bound stops further starts pending local retention review. The UI
exports the current receipt; archived receipts are retained on disk. There is no
automatic deletion or archive browser yet. These local JSON records are not signed
remote attestations or protection against restoration of old operator state.

## Transfer signature evidence at the legacy peer boundary

The legacy validator now verifies each successful peer reply against the configured
peer's destination-chain address and the exact digest of the transfer sent. It
refuses redirects, closes reply bodies, caps replies at 256 bytes and sends only
one request per configured peer URL, including on errors. A nonempty HTTP 200
response alone is no longer accepted as a signature. Broadcasting also rejects
expired transfers and malformed or unverified attached signature arrays.

`SubmitSignature` checks distinct configured signers and matching signature arrays
before storage. EVM address case aliases and alternate signature encodings cannot
increase the signer count. It bounds request bodies to 1 MiB and requires a
nonexpired transfer plus an authenticated envelope expiring within two minutes.
The broadcaster's existing one-minute envelope fits this limit. Invalid amount,
payment, chain and signature inputs return an error rather than entering the
legacy hash helper with malformed numeric input. A peer cannot set a locally
stored transfer to completed or supply its completion transaction ID. A completed
record already held locally retains its completion status.

Both source-event handlers and both renewal handlers validate signature evidence
before writing it. After a broadcast, they recheck replies against the current
stored digest under the transaction lock. If another request renewed the transfer
while HTTP was in progress, replies for the prior digest cannot enter the renewed
record. Corrupt retained arrays are refused rather than indexed or silently
repaired. EVM-to-Koinos renewal also preserves the ordinary transfer path's handling
of empty recipient/relayer fields.

Compatibility follows the reviewed EVM source's `recoverSigner` behavior:
65-byte signatures, recovery IDs 0/1 or 27/28 and both valid high-S and low-S
values. The existing signer still emits 27/28 and low-S. Duplicate detection uses
the recovered address, so equivalent representations cannot add votes. Koinos
continues using canonical URL-base64 compact signatures and its existing address
derivation. No protobuf schema, transfer hash preimage, threshold formula or
contract authority changed. These are source-level checks; deployed bytecode and
mixed-version interoperability still require their own qualification evidence.

Existing corrupt or formerly accepted invalid records need local investigation.
The peer API returns HTTP 409 for invalid retained signature evidence. Streamer
rejections log the error and preserve the stored record; there is no automatic
repair, replay queue or new operator incident view. Existing public transaction
reads and process activity counters are not retroactive cryptographic verification
of every stored record. Do not use them as a rollout quorum permit.

Remaining gates include inconsistent legacy threshold formulas, fresh on-chain
membership and source/finality verification, and the legacy EVM transfer hash
helper's signed `int64` conversion for unsigned values at or above 2^63. This
change does not fix those protocol issues or enable managed signing. Safe rollout
still needs the full qualification, installation and recovery workflow described
in the implementation specification.

Regression tests use fresh synthetic keys, in-memory stores and loopback HTTP:

```sh
go test -count=1 -race ./internal/api ./internal/util ./internal/streamer
go test -count=1 ./...
go vet ./...
```

They cover valid API/broadcaster exchange in both directions, invalid peer replies,
wrong signer and digest, redirects, body bounds, duplicate identities, malformed
stored evidence, peer-asserted completion, concurrent renewal during the network
round trip and valid/refused renewals through both actual event handlers.

## Create and inspect encrypted backups from the console

Configure the encryption helper and **public** age X25519 recovery recipient once
on the operator host, before starting the service. Keep the recovery identity in
operator-owned recovery storage. For a named local instance, also pass
`--instance <slot>` before the command. This policy is separate from release trust
and cannot be changed through HTTP.

```sh
vortex-operator --data /absolute/operator-directory \
  --backup-crypto /absolute/reviewed/backup-crypto \
  --backup-crypto-sha256 <reviewed-helper-sha256> \
  --recovery-recipient <public-age1-recipient> backup-configure
```

The command hashes the helper and checks the recipient by encrypting a fixed
non-secret message. The console exposes the recipient and policy digest, never
helper paths or recovery identities. Changing the helper on disk invalidates its
reviewed digest and makes subsequent jobs fail. Each new job retains its original
public recovery recipient, so rotating the policy cannot relabel an older
archive. Older job records without recipient metadata are explicitly identified
as needing their original local policy.

In **Validator → Encrypted backups**, stop the worker gracefully, choose a unique
backup ID and create the snapshot. The job verifies the exact registered
configuration, obtains the process lease and all three database locks, and uses
the existing consistent encrypted backup format. An unavailable health socket is
not proof of shutdown: a live process lease or legacy Badger writer still blocks
the snapshot. The action does not stop or restart a worker automatically.

Creation returns a job immediately. Closing the browser or timing out does not
restart it. Poll the inventory or retry the same ID and digests to recover its
original result; the same ID cannot authorize changed inputs or overwrite an
archive. One job runs per local instance. Up to 32 jobs are retained; retention
requires local review and there is no automatic deletion. A clean operator
shutdown cancels and waits for its active backup before releasing store ownership.
After an abrupt interruption, a running record becomes `recovery-required` for
inspection. It never silently resumes or claims completion from an existing file.
A failure to persist the terminal receipt also leaves the job uncertain.

Archives are stored at `backups/<ID>/archive.age` beneath the selected operator
state directory. Copy them to independent recovery storage. **Check archive
integrity** rehashes the ciphertext against its receipt; it does not decrypt it,
prove the recovery identity is available, or approve a restored signer. **View
backup receipt** exposes read-only JSON for copying, with an optional browser
JSON download. Checkpoints are decimal strings to preserve uint64 values in
browsers; older numeric receipts remain readable. Test restore with the local
`backup-restore` procedure. Console restore, off-host copy, automatic retention,
key recovery, signing reconciliation and cross-host fencing remain separate work.

Private scoped endpoints are `GET /v1/worker/backups`,
`POST /v1/worker/backups/create` (ID, registration digest and policy digest), and
`POST /v1/worker/backups/verify` (ID only). Browser requests cannot provide a
source/destination path, executable, recipient or recovery identity. HTTP
instance scoping applies to the policy, jobs and archive locations.

A reproducible console fixture is available after building local binaries:

```sh
go run scripts/operator-backup-fixture.go \
  --operator /absolute/local/vortex-operator \
  --validator /absolute/local/koinos-bridge-validator \
  --crypto /absolute/local/backup-crypto
```

It prints a fresh private fixture directory, creates synthetic stopped-validator
state and a test-only recovery identity, and exercises `backup-configure` through
the compiled CLI. It starts no worker or RPC and contains no production data.
