# Portable maintenance reservations

This implementation coordinates planned maintenance through portable signed
schedules. A coordinator can distribute a proposed plan; each operator endorses
the exact plan through its own private service or offline CLI. No coordinator
credentials, shared database or bridge signing keys are required. The current
implementation records schedule consent; installation and fresh activation
preflight are still unfinished.

## Local identity and policy

Stop the operator service before offline CLI operations, which acquire the same
exclusive state lock. Initialize a scheduling identity for the selected instance:

```sh
vortex-operator --data /private/operator --instance my-route maintenance-init
```

This creates a random Ed25519 scheduling key and reservation journal together
under the private `maintenance` directory. Output contains only the operator
instance ID and public key. This identity cannot sign bridge transfers, governance
payloads or release manifests. Repeating initialization returns the same public
identity and validates its journal; missing/corrupt history is not reset. Keep
identity and history together. Do not clone the directory to another active host,
restore an older journal, or rotate the key to bypass outstanding reservations.
Host/administrator compromise and historical rollback are outside the guarantees
of a local file journal.

Each operator independently installs a private `maintenance-policy.json`. It has
schemaVersion 1, an ID and expiry, and an identical ordered roster of 2–32 members
with distinct `instanceId` and Ed25519 `publicKey` values. Include 1–32 routes,
each with its ID, full existing EVM/Koinos deployment profiles, a public review
evidence reference and five stage declarations:

- `evm-contract`
- `koinos-contract`
- `peer`
- `api`
- `frontend`

Each stage has a positive integer `required` and a distinct list of participant
operator instance IDs. List every applicable stage, including stricter client or
peer requirements. Do not derive all stages from one contract's quorum formula.
The policy is locally reviewed configuration, not evidence of current membership,
progress or independent administration. Participants represent declared operator
instances; verify how actual validator keys and deployment roles map to them.
Unsupported or uncertain mappings must not be represented as verified readiness.

The policy digest binds its complete typed JSON, including roster, route identities,
thresholds, evidence and expiry. Changing a policy or even its array order changes
the digest and requires a new plan. Policies cannot be installed by an HTTP plan
request. Policy changes do not clear previously reserved intervals.

## Review and exchange

A portable envelope contains `plan` and `endorsements`. The plan has schemaVersion 1,
a lowercase ID, `policyDigest`, `createdAt`, and 1–32 ordered `windows`. Each window
binds `instanceId`, exact signed `releaseDigest`, `start` and `end` timestamps.
An instance can appear only once. Windows cannot overlap, may last at most 24 hours,
and must end within seven days of plan creation and before policy expiry. Include
adequate verification time in the reviewed schedule; time passing alone cannot
prove a successful wave.

A planned outage must leave the declared participant count at or above every
route's five thresholds. Before an operator endorses its own outage, its local
release approval must cover that exact validator release and the entire window.
Endorsing someone else's outage never authorizes installation on the endorser.
An operator can endorse only before the first window begins; an identical recorded
request can be recovered later while the plan remains valid.

In **Updates → Coordinate maintenance**, paste the envelope, review the decoded
routes, thresholds, windows and exact digest, then select the reservation consent
and **Endorse schedule locally**. Export the resulting envelope to exchange it
with other operators. The console also exports each recorded local endorsement.
It sends no messages automatically. A guided schedule editor and authenticated
coordinator transport remain pending; current exchange uses JSON envelopes.

The offline equivalent uses a private JSON file (mode 0600):

```sh
vortex-operator --data /private/operator --instance my-route \
  --maintenance-file /private/plan.json maintenance-verify
vortex-operator --data /private/operator --instance my-route maintenance-status
vortex-operator --data /private/operator --instance my-route \
  --maintenance-file /private/plan.json \
  --maintenance-digest REVIEWED_PLAN_SHA256 \
  --maintenance-revision CURRENT_LOCAL_REVISION maintenance-endorse
```

The final command outputs an envelope with the local endorsement added. Pass that
envelope to the next operator, retaining each preceding endorsement. Verification
reports the exact digest, endorsed members and missing members. All members must
endorse before the state becomes `reserved`; `activationReady` remains false.
Use a fresh verify call when reopening a saved plan: endorsements shown in the
browser are a dated inspection and may outlive policy or plan validity.

Signature bytes are Ed25519 over ASCII `VORTEX-MAINTENANCE-PLAN-V1`, a newline,
and Go `encoding/json` serialization of the `MaintenancePlan` struct in declared
field order. The plan digest is SHA-256 of that JSON without the prefix; the prefix
separates this signing domain from other messages. Use the typed CLI/API to obtain
and verify the digest instead of hashing arbitrary JSON formatting. Endorsements
bind instance ID, plan digest and signature; duplicate, unknown and invalid votes
are rejected. Strings, timestamps and ordered arrays are part of the payload.

## Persistence and failure behavior

The service signs only after checking local policy, identity, the full plan,
current approval and revision. It stores the complete plan and its local signature
before returning that signature. An exact retry returns the persisted signature;
concurrent conflicting requests cannot both obtain a vote. A durable history
intent precedes journal publication; a failure at that boundary may require a
fresh revision, but no unrecorded signature is returned.

The reservation covers the entire interval from the first window's start through
the last window's end, including gaps. A different overlapping plan is refused
until that interval no longer overlaps the new plan. This conservative version
has no cancellation/early-release or automatic compaction protocol. Revoking a
release approval stops consent to activate it, but does not free a schedule that
other operators may still hold. Journals are bounded to 256 plans and 2 MiB;
retention and safe cancellation require a separately reviewed protocol.

Requiring every roster member plus each honest member's durable conflict refusal
prevents a coordinator from obtaining two conflicting fully endorsed plans for
that roster. Split votes can block both plans, a deliberate availability tradeoff.
Unanimous schedule consent is separate from bridge signature quorum. It does not
prove independent hosts or uncompromised keys. Different trust rosters, malicious
endorsers, incorrect clocks or rolled-back journals need additional operational
controls. Fresh local verification remains mandatory before each activation.

Before any installer stops a worker it must check current local approval and
publisher trust, current reservations, observed participation at every stage,
previous-wave success and meaningful progress, exact tested artifact, compatible
persistent state, backup and recovery/fencing. Unknown or stale coordination must
block new automatic activations while existing workers continue. No active worker
is affected by this reservation implementation, including when the coordinator
or console disappears. A reserved plan alone must never be accepted as a start
permit or proof of available quorum.

## Synthetic reproduction

From the validator repository:

```sh
go test -count=1 -race ./internal/operator -run TestMaintenance
go run scripts/operator-maintenance-fixture.go
```

The fixture generator creates three disposable local stores, fresh scheduling
identities, test-only publisher approval, a declared 2-of-3 policy and a plan
already endorsed by two members. It prints the temporary base directory. Start
the locally built operator against its `operator-0` subdirectory, connect the
console with that directory's synthetic access token, and import its `plan.json`
to review and add the remaining endorsement. The fixture starts no workers or
RPC services and does not execute contracts. Never install its policy live.

Tests exercise changed plans, duplicate/forged signatures, missing members,
threshold violations, stale revisions, local revocation, concurrent coordinator
forks, restart recovery, damaged history, scoped HTTP authentication and actual
compiled CLI exchange across three separate stores. These tests establish local
protocol behavior, not the specification's separate-host rollout acceptance.
