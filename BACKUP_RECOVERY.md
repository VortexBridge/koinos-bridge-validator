# Local encrypted backup and observation recovery

This workflow backs up a **stopped** validator and restores into a **new**
directory. Recovery preserves both saved chain checkpoints and pending records.
It never enables signing from recovered state. Signing recovery still requires
the separate reconciliation and old-signer fencing workflow in the implementation
specification; that workflow is not implemented yet.

Each operator owns its recovery identity and approves its local tools. No shared
database, central recovery key, dashboard session or publisher can decrypt an
operator's backup or authorize recovered signing.

## Build the tools

Build the operator with the main module's documented Go toolchain. The crypto
helper has a separate Go module, pinned age v1.3.2 and Go 1.27.0 toolchain, so it
does not replace the validator's legacy dependency graph:

```sh
go build -trimpath -o /absolute/private/bin/vortex-operator ./cmd/vortex-operator
GOTOOLCHAIN=go1.27.0 go -C tools/backup-crypto build -trimpath \
  -o /absolute/private/bin/vortex-backup-crypto .
```

Review the helper source and build provenance, then record its SHA-256 using
`shasum -a 256 /absolute/private/bin/vortex-backup-crypto` on macOS or `sha256sum`
on Linux. The operator copies through one descriptor and verifies that digest
before executing the helper. This is a locally trusted tool, not an untrusted
release candidate; the browser cannot select executables or recovery key paths.
The private operator directory (backup) and restored directory's parent (restore)
must permit executing that reviewed helper copy. A `noexec` filesystem is rejected;
the tool does not bypass mount restrictions or fall back to an unverified binary.

The helper implements standard age X25519 recipient encryption through the
[age Go API](https://pkg.go.dev/filippo.io/age). Its dependency is pinned to
[age v1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2).
Only X25519 recipients and a single private identity file are supported here;
plugins, password prompts and remote key services are not enabled.

## Create a recovery identity and backup

Use an existing operator-owned private directory (0700) for the recovery identity.
The following command creates a new 0600 file and prints only the public recipient:

```sh
/absolute/private/bin/vortex-backup-crypto \
  --identity-file /absolute/private/recovery/identity.txt keygen
```

Keep that private identity under the operator's separate recovery procedure.
It is an archive decryption key, not a validator signing key. The create command
needs only its public `age1...` recipient. Losing the private identity prevents
recovery; sharing it shares access to the archived state.

Stop the selected validator cleanly first. Stop the local operator API before
using its offline CLI, which takes the same exclusive operator-store lock.
Other independently running validator instances remain separate.

```sh
/absolute/private/bin/vortex-operator \
  --data /absolute/private/operator \
  --worker-base /absolute/private/validator \
  --backup-file /absolute/private/backups/validator.age \
  --recovery-recipient PUBLIC_AGE_RECIPIENT \
  --backup-crypto /absolute/private/bin/vortex-backup-crypto \
  --backup-crypto-sha256 REVIEWED_HELPER_SHA256 backup-create
```

All flags precede the command. The destination must not exist. The JSON receipt
contains the ciphertext hash, manifest hash, size, time and both checkpoints.
Keep the receipt with the operator's backup inventory and check it during recovery.
Encryption authenticates ciphertext integrity; anyone knowing a public recipient
can encrypt a different archive to it. The receipt and operator-owned inventory
establish which backup was intended. The tool does not infer trusted provenance
from successful decryption.

The snapshot holds the worker's local process lease and the actual read-only
locks for all three Badger directories throughout export. A running legacy writer
is also rejected through Badger's directory locks. A database that needs crash
recovery must first be recovered using its reviewed runtime and cleanly stopped.
There is no reset, lock bypass, concurrent live snapshot or automatic shutdown.

## Restore and review

```sh
/absolute/private/bin/vortex-operator \
  --data /absolute/private/recovery-operator \
  --backup-file /absolute/private/backups/validator.age \
  --restore-base /absolute/private/recovered-validator \
  --recovery-identity-file /absolute/private/recovery/identity.txt \
  --backup-crypto /absolute/private/bin/vortex-backup-crypto \
  --backup-crypto-sha256 REVIEWED_HELPER_SHA256 backup-restore
```

The restore authenticates the entire stream before parsing or loading a database.
It validates the archive allowlist, types, lengths and hashes, then validates
Badger frame lengths and protobuf record limits before calling the pinned loader.
Only a complete restore is published. Existing directories are never selected
for replacement, and two competing restores cannot both publish the same target.

Compare both receipt hashes and checkpoints against the saved inventory. Inspect
the recovered public configuration and historical operator export. The restored
validator gets a new instance ID and is marked `review-required`; the actual
runtime refuses to start at this point.

Edit the recovered `config.yml` locally to set explicit Ethereum and Koinos RPC
URLs and a loopback `api-url`, such as `127.0.0.1:13001`. RPC URLs require HTTPS
or literal-loopback HTTP, without embedded user credentials. Preserve contracts,
tokens, validator identities, confirmation policy and other public configuration.
Keep `observation-only: true`, `reset: false`, zero start-height overrides, and
empty signing-key fields. Review network identity and recovered checkpoints
against independent chain evidence; this CLI review is not an on-chain finality
check and does not prove that an old signer on another host has stopped.

```sh
/absolute/private/bin/vortex-operator \
  --data /absolute/private/recovery-operator \
  --worker-base /absolute/private/recovered-validator \
  --backup-digest EXACT_RECOVERED_MANIFEST_SHA256 \
  --review-ethereum-height EXACT_SAVED_ETHEREUM_HEIGHT \
  --review-koinos-height EXACT_SAVED_KOINOS_HEIGHT \
  --review-note 'Describe the local checkpoint and configuration review; no secrets.' \
  restore-review
```

The review verifies the backup digest, actual database heights and unchanged
public configuration, then pins the exact local configuration file. Changes after
review require another review. Even after review the restored directory remains
restricted to observation. Register its reviewed validator executable using
`worker-register` in a fresh operator store, then use the existing Validator panel
to start/stop it, or run the reviewed validator with `--basedir` and `--observe-only`.
The operator registration also pins the config, so finalize review before registration.

## Contents and current boundaries

- Logical exports of `metadata`, `ethereum_transactions` and `koinos_transactions`;
  pending public signatures are preserved, with no automatic replay or broadcast.
- Typed public configuration: inline signing keys, signing-key paths, global
  overrides, RPC URLs, peer URLs and local API address are excluded. Restored
  configuration forces observation and disables reset/start-height overrides.
- Historical public operator profiles/events, exported only for review. Access
  tokens, active release approvals, executable registrations and private publisher
  policy files are not restored as authority. User-entered public names and review
  notes are preserved; do not put secrets into those fields.
- No validator signing-key recovery is included. Temporary plaintext is created
  only in private directories and removed on normal success/failure; this is not
  a secure-erasure guarantee for the host filesystem or an interrupted process.
- Current limits: 256 MiB per exported file, 1 GiB plaintext archive, 128 MiB per
  Badger frame, 100,000 records per frame, 64 KiB keys and 4 MiB values. Creation
  checks the same database limits as restoration. Larger data requires a reviewed
  extension, not an unbounded loader fallback.
- This is a local CLI recovery workflow. Guided backup/recovery UI, scheduled
  rotation, off-host storage, retention, signing reconciliation and independent-host
  acceptance are still pending. Restore guards are software checks in this runtime,
  not protection against an operator deliberately altering the code or local state.

## Tests

The integration test builds the helper in its separate module and the actual
validator binary. First-time helper builds require its pinned toolchain/modules.
For a fully cached/offline run, build it first and pass its absolute path:

```sh
VORTEX_BACKUP_CRYPTO_TEST_BINARY=/absolute/private/bin/vortex-backup-crypto \
  GOPROXY=off GOSUMDB=off go test -count=1 -race \
  ./internal/operator ./internal/worker ./internal/streamer
```

Tests use only disposable state, generated recovery identities, synthetic public
signatures and loopback RPC fixtures. They cover credential exclusion, damaged
ciphertext, wrong/private/symlink identity handling, concurrent publication, active
and legacy writer rejection, malicious tar/database frames, checkpoint and pending
record preservation, refused unreviewed startup, reviewed observer start/stop,
refused signature exchange and configuration drift.

For an isolated Linux test, the prebuilt test executable accepts
`VORTEX_BACKUP_TEST_VALIDATOR`, `VORTEX_BACKUP_TEST_OPERATOR` and
`VORTEX_BACKUP_CRYPTO_TEST_BINARY` as fixed fixture executable paths. This avoids
installing Go inside the test container. Its disposable `/tmp` must explicitly
permit execution of the reviewed helper copy. This requirement belongs to this
backup test; the separate release-candidate smoke runner retains its existing
`noexec` temporary mounts.
