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

## Fresh authenticated operator responses

The Updates panel now provides a portable challenge/response exchange after a
fully endorsed plan is reviewed. This is an input to the remaining rollout
preflight, not signing-quorum verification or an activation permit. It can run
before the scheduled window for inspection; an installer must separately enforce
the actual activation window and all release, recovery and stage requirements.

The requesting operator must own a window in the plan and retain both its durable
reservation and a current local approval covering that window. Only its latest
validator approval is eligible; revocation or a superseding sequence invalidates
local verification. A challenge binds the exact plan, policy, requester, release,
a random 256-bit nonce and a lifetime of at most two minutes, ending no later than
the maintenance window. It is signed with the local scheduling identity under a
separate domain. One active challenge is retained in the private
`maintenance/participation.json`. Exact retries survive restart. A new ID cannot
replace an active challenge, and a damaged stored signature is refused rather
than silently reset. Expired challenges can be replaced with a new ID/nonce.

Each responding operator verifies the request against its independently installed
policy and its own durable reservation. The response endpoint captures fresh
local worker state itself: callers cannot provide snapshots, paths or assertions
of readiness. Missing registration, changed artifact/configuration, unavailable
worker, stale chain observations or incomplete activity produce a signed
unavailability reason. A valid worker snapshot is bound to the request and must
match a route declared for that operator. No bridge signing keys are accessed.

Verification accepts each roster identity once and rejects altered signatures,
wrong domains/plans/releases/nonces, duplicate or unknown responders, future times,
expired challenges, and responses at least 30 seconds old. The embedded snapshot
must follow challenge issuance, have internally fresh/complete data, and precede
the outer response time by no more than five seconds. A missing response remains
missing; an authenticated unavailable or observation-only response is never
upgraded to signing readiness. The browser marks inspections stale automatically
at the earliest response or challenge expiry.

In Updates, create and export a participation request for the reviewed plan.
Other operators import its JSON, choose **Capture and sign local observation**,
and export their response. On the requesting operator, **Use local response in
collection** adds its own response without manual copying. Collect responses in a
JSON array and choose **Import and verify responses file**, or paste the array
and verify it. File imports are bounded to 1 MiB. Exchanges must be quick enough
to meet the 30-second freshness limit; automated authenticated collection is still
pending. Nothing sends messages or contacts other operator endpoints automatically.

Offline CLI equivalents (stop only the management API before CLI use; the worker
can continue running):

```sh
vortex-operator --data /private/operator --instance my-route \
  --maintenance-file /private/endorsed-plan.json \
  --maintenance-revision CURRENT_REVISION --participation-id check-one \
  participation-begin
vortex-operator --data /private/operator --instance my-route participation-status
vortex-operator --data /private/other-operator --instance my-route \
  --participation-file /private/participation-request.json participation-respond
vortex-operator --data /private/operator --instance my-route \
  --participation-file /private/responses.json participation-verify
```

All input files must be private regular JSON files. CLI output contains public
request/response data; keep any saved files mode 0600 for subsequent CLI import.
Authenticated scoped HTTP routes are GET `/v1/maintenance/participation` and POST
`/v1/maintenance/participation/begin`, `/respond`, `/verify` beneath that prefix.
Begin accepts `{id, expectedRevision, envelope}`; respond accepts the exported
`{envelope, probe}` package; verify accepts the response array and checks against
the requesting operator's retained challenge, not a supplied replacement.

Signature domains are ASCII `VORTEX-MAINTENANCE-PROBE-V1` for the typed challenge
and `VORTEX-MAINTENANCE-OBSERVATION-V1` for the typed observation, followed by a
newline and Go `encoding/json` serialization in struct field order. Probe digests
are SHA-256 of typed challenge JSON without the prefix. The domain separation
prevents schedule endorsements from being reused as observations or vice versa.
Scheduling keys now authenticate these observations as well as reservations;
they still cannot sign bridge transfers, governance actions or release manifests.

Signatures establish which configured operator reported a snapshot, not that an
operator-controlled host or executable told the truth. They do not prove actual
validator-key ownership, current on-chain membership, valid transfer signatures,
contract finality, independent failure domains or satisfaction of peer/API/frontend
thresholds. `allResponded` only describes response collection;
`activationReady` remains false. Current publisher trust, exact tested artifacts,
previous-wave progress, stage-specific verification, installation and recovery
remain required. Restored journals, compromised scheduling keys and clock faults
remain outside this local protocol's guarantees.

For a fresh participation-only fixture with all three schedule endorsements:

```sh
go run scripts/operator-maintenance-fixture.go --full-consent
```

Use its three operator directories for CLI response exchange and its `plan.json`
for the UI. This generator creates no worker or RPC. The runtime evidence in the
root implementation folder additionally records a separately built observation
worker against a loopback synthetic RPC; its reported network identifiers are
fixture inputs, not live deployment evidence.
