# Local encrypted signing keys

This branch provides `vortex-keys` and an encrypted-vault option for the existing
standalone validator. Use these commands on a reviewed Linux host as the operator's
dedicated non-root service user. The operator API and hosted interface never
request the vault password or open the vault. The separate installed managed
signer is described in `HOST_INSTALLATION.md`; it has synthetic manual-unlock
and fenced-replacement evidence. Unattended managed unlock is not approved,
and public-chain signing remains disabled.

## Prepare the host

Keep each operator's host administration, cloud recovery, key recovery and update
approval under that operator's control. Require private administrative access,
patched software, restricted inbound ports, SSH keys and multi-factor protection
of administrative accounts. Keep public transaction-query services separate from
the private management service. A shared Tailscale administrator or recovery
account remains a shared control domain; network access is not key isolation.

The key commands and encrypted validator startup enforce:

- A non-root effective user.
- A readable Linux swap inventory. If swap is active, successful
  `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)` before input or decryption.
  This covers copies made by Go and crypto libraries, including future mappings.
- Zero soft and hard core-dump limits and `PR_SET_DUMPABLE=0`.
- A bounded, regular, non-symlink vault file with exact mode 0600.
- An explicit pair of public signer identities in the runtime configuration.

With swap, the service needs a memlock limit large enough for the whole process's
mapped address space. Go reserves more address space than resident RAM, so a small
memlock allowance can refuse startup even when RAM is available. An operator-owned
service may use `LimitMEMLOCK=infinity` with a separately measured service memory
limit; the validator itself needs no root permission or extra Linux capability.
The local container acceptance uses an unlimited memlock allowance, a 1500 MiB
container memory limit, no network, no capabilities and a non-root user. This is
test configuration, not measured production sizing.

Locking future mappings can also cause later allocations to fail if their limit
is exceeded. Observe capacity under realistic load before rollout. Disable
hibernation and memory-bearing VM snapshots in host policy: they can persist RAM
despite memory locks. A privileged host/hypervisor compromise or a malicious
authorized binary can still read or misuse active keys. Buffer wiping is best
effort in Go and is not a claim that every copy is erased.

See the primary Linux documentation for [memory locking and its limits](https://man7.org/linux/man-pages/man2/mlock.2.html)
and [process dumpability](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html).
macOS and other platforms refuse secret-loading commands until equivalent
protections are implemented. Keyless observation remains available there.

## Create or import

Build `./cmd/vortex-keys` alongside `./cmd/koinos-bridge-validator` from the same
reviewed revision. In an already created operator-owned mode-0700 directory:

```sh
vortex-keys --vault /absolute/private/bridge-keys.vault generate
```

The local terminal asks for a strong passphrase and confirmation with echo
disabled. Use a randomly generated password or a sufficiently strong multi-word
passphrase, at least 16 bytes. Keep its recovery copy separately from the encrypted
vault. The output contains only the two public addresses and the vault SHA-256.
An existing destination is never overwritten.

To retain existing identities, use `import` instead of `generate`. It asks through
the same hidden terminal for the EVM hexadecimal key and the Koinos WIF key. Never
paste real keys into chat, the hosted interface, command arguments or environment
variables. Import does not delete existing plaintext copies, stop an old signer
or authorize membership changes. Review and remove legacy plaintext storage
through the operator's recovery procedure after testing the encrypted copy;
deleting a file does not prove that snapshots or storage remnants are erased.

Confirm that the saved vault can be unlocked and yields the intended identities:

```sh
vortex-keys --vault /absolute/private/bridge-keys.vault inspect
```

This verifies decryption and prints public data only; it never exports plaintext
keys. Copy the encrypted vault into operator-owned recovery storage and verify
the copied file with `inspect` in an isolated recovery exercise. A lost passphrase
and all recovery copies mean the vault cannot recover the keys.

## Managed signer backup boundary

The observation-worker backup deliberately excludes signing keys. A managed
signer recovery needs its encrypted `keys.vault`, public
`managed-session/session.json`, the exact public policy derived from the
reviewed runtime, and any public Koinos receipt-location hints. Back up the
runtime and artifact digests needed to verify that policy. Do not reuse a
source host's signed host review or local release approval on a replacement
machine.

The vault is AES-GCM encrypted, but the journal and runtime metadata are
public only in the cryptographic sense: they can reveal operational activity.
For a real operator, wrap the complete recovery package in reviewed
client-side encryption **before** writing it to off-host storage. Keep the
decryption identity or passphrase separately from the ciphertext and from
the source host. Record a readback hash, retention schedule and restore test.
The destination, redundancy, recovery-secret custody and retention have not
yet been accepted for the pilot.

The active-host-loss exercise copied a consistent signed journal after the
signature was persisted, then recovered it from a separate local disk after
dual-chain retirement. That manual copy does not guarantee that a later
operation will be in the latest backup. Until a durable freshness mechanism
is accepted and tested, treat backup age and any unrecorded pending operation
as explicit recovery limits. A replacement uses fresh signing identities,
imports only verified public operations without old signatures, and remains
locked until both old identities are retired on the reviewed contracts and
manual unlock succeeds.

## Configure and unlock the validator

Set the following fields in the reviewed private `config.yml`, using the two
public addresses printed by the key tool:

```yaml
bridge:
  signing-vault-file: /absolute/private/bridge-keys.vault
  ethereum-signer-address: '<expected public EVM address>'
  koinos-signer-address: '<expected public Koinos address>'
```

Retain the route's existing reviewed network, contract, peer and token settings.
Remove `ethereum-pk`, `koinos-pk`, `ethereum-pk-file` and `koinos-pk-file` from this
configuration: combining a vault with any legacy key source is refused. Start
the independently authorized standalone validator through its local terminal;
it requests the passphrase without echo. On every restart it requires a new
unlock. No password is retained in operator configuration. Incorrect passwords,
damaged files, mismatched public addresses or failed host protections stop startup
before opening transaction databases. Existing process and signing-identity locks
continue to apply, with their same-user/same-host scope.

An independently reviewed local secret broker can instead supply the passphrase
through an inherited anonymous pipe/socket at descriptor 3 or above, selected by
`--unlock-passphrase-fd 3`. The key tool accepts `--passphrase-fd 3` for the same
purpose. Regular files and descriptors 0, 1 and 2 are rejected. The broker must
protect its own memory and control who can launch the child. A pipe alone does
not establish trusted custody. An automatic unlock service is not supplied by
this milestone. Observation-only mode never reads the vault or unlock descriptor.

The operator doctor reports legacy plaintext-key configuration as requiring
attention. A configured encrypted vault remains `unknown` for custody: configuration
cannot prove the remote host protections or independent recovery ownership.
Operational backups exclude the vault, its path and unlock inputs. Key recovery
is a separate operator-owned procedure. Restored workers remain keyless and
observation-only until the existing recovery checks and separate signing decision.

## Failure and recovery

1. If unlock fails, inspect the public configuration, file ownership/mode and
   selected binary. Do not automatically generate replacement keys or overwrite
   the existing vault. Recheck the encrypted copy and passphrase locally.
2. If the service cannot lock memory, review its limit or the host's swap policy.
   Do not make it run as root or revert to plaintext to bypass the failure.
3. If the host may be compromised, stop/fence the signer and its administrative
   access using the team's incident procedure. Coordinate any pause or key removal
   under the actual per-chain governance threshold. Vault encryption does not
   make a compromised active key trustworthy again.
4. Recover on a clean independently controlled host. Verify the encrypted backup,
   public identities, durable state and old-signer fencing before authorizing
   signing. Never use a lost dashboard connection as proof that the old host stopped.
5. For a security update, use the exact reviewed artifact and existing local
   approval/maintenance workflow. The new process needs a fresh local unlock;
   a release coordinator receives neither passwords nor general host credentials.

## File format and verification

Version 1 is 139 bytes: `VORTEX-KEYS-V1\0`, random 32-byte salt, random 12-byte
nonce, then AES-256-GCM ciphertext and 16-byte authentication tag for two 32-byte
secp256k1 scalars (EVM first, Koinos second). The whole header is authenticated
as associated data. The password KDF is [scrypt](https://pkg.go.dev/golang.org/x/crypto/scrypt),
fixed at N=131072, r=8, p=1, 32 output bytes (approximately 128 MiB workspace).
Files cannot request weaker or arbitrarily expensive parameters. New formats
require explicit version support. This is a Vortex bundle, not a Web3 keystore.

Tests cover authenticated round trips and tampering, malformed sizes/scalars,
password bounds, private files/symlinks, independent Node/OpenSSL interoperability,
Linux secret-pipe validation, actual terminal import without echo, both runtime
signing proofs, core/memory protection, clean stop, wrong-password refusal before
database opening, observation-only non-consumption, backup redaction and secret
absence in fixture files/logs. These are isolated local tests with synthetic keys;
independent security review and separate-host acceptance remain required.
