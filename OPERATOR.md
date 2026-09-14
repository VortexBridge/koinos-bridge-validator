# Private operator service (implementation in progress)

This branch adds a separate, keyless `vortex-operator` command. The `cmd/koinos-bridge-validator` runtime now supports keyless observation and
a private control socket. Do not interpret an operator dashboard connection as
a running or enrolled validator.

Implemented: durable private deployment configuration, read-only EVM/Koinos
observations, governance payload encoding, signature verification primitives,
signed release-manifest verification, per-instance local approval/revocation,
and independently running observation workers with locally reviewed executable
and configuration hashes.
Pending: managed signing and cross-host fencing, assisted provisioning, transfer
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

Flags precede the command. Supported commands are `serve`, `status`, `token-path` and
`worker-register`, `release-stage` and `candidate-test`; `token-path` prints only the file path. The current offline CLI
opens the same exclusive state lock, so stop this operator service before using
`status`, `token-path`, `worker-register`, `release-stage` or `candidate-test`. A running instance's authenticated HTTP API can read
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
The `data-mode` marker prevents silently turning observation checkpoints into
signing history, or adopting existing signing data as observation data. Use
separate candidate directories; a mode-migration workflow is not yet implemented.

For the legacy standalone signing command, `ethereum-pk-file` and `koinos-pk-file`
accept local regular files with no group/world permissions; symlinks are refused.
Do not supply both inline and file values for a key. Local per-public-address
leases under the OS user's configuration directory exclude accidental duplicate
signers on that user account. These locks do not fence cloned keys on another
host or another OS account. Managed signing remains disabled.

### Register an observation worker

Build and review the local validator executable, prepare a private base directory
with a mode-0600 `config.yml`, and give it a stable `bridge.instance-id`. The
configuration must contain no inline keys and must not request a database reset.
The registration command only supports observation mode. Stop the operator first;
registering does not stop an independently running validator.

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
and start the observation worker. Changes to the reviewed configuration or binary
are refused at startup. The panel cannot provide executable paths, shell commands
or key material. Stop requires review of the currently observed process. Start and
stop intents are recorded durably; an intent is not proof of completion.

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
