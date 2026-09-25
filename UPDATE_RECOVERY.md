# Validator update and recovery runbook

This runbook describes the private, operator-controlled update path implemented by `vortex-operator`. It applies to synthetic development deployments until the project records a separately reviewed production decision. It does not authorize production activation.

## Authority boundaries

Four authorities remain separate:

1. Release publishers sign provenance for a manifest and exact artifact digests. They cannot approve or install a release.
2. Each validator operator stages the bytes, reviews the release, runs the isolated candidate suite and records a local approval window.
3. The maintenance group agrees on an ordered plan and returns fresh signed participation, bridge-key, contract-membership and route-stage evidence. A coordinator can transport this evidence but cannot create it.
4. The selected operator starts and advances the local update journal. Every phase is a separate authenticated action. No remote request supplies an executable path or command.

The registry is a distribution source only. Once an artifact is staged, every transition reopens the locally retained artifact and checks its signed identity and SHA-256 digest. A registry or coordinator outage cannot stop an already running validator. It also cannot create a new readiness receipt or start a wave.

## Compatibility matrix

| Mode | Required relationship to current release | Recovery | Mixed validator versions |
| --- | --- | --- | --- |
| `rolling` | Same validator component, newer sequence, exact current version in `compatibleFrom`, unchanged config/database schemas and signing codec, `mixedVersionsSafe: true` | Exact prior artifact | Allowed only inside the reviewed maintenance plan |
| `migration` | Same validator component, newer sequence, exact current version in `compatibleFrom`, at least one schema or signing-codec change, `mixedVersionsSafe: false` | Forward only | Not assumed safe; operator must explicitly confirm forward-only recovery |
| `emergency` | Signed `emergency` channel and otherwise rollback-compatible rolling relationship | Exact prior artifact | Same quorum and one-operator-at-a-time limits as rolling mode |

The first release after a migration must retain the new config schema, database schema and signing codec. A forward-recovery release must be newer than the failed candidate and list that candidate version in `compatibleFrom`. It must be staged, pass the isolated candidate suite and receive a fresh local approval. The update journal then verifies it again before progress can complete the wave.

The current emergency policy narrows which releases qualify: only the explicit emergency channel and rollback-compatible artifacts are accepted. It does not remove publisher signatures, local approval, exact-byte checks, backup, maintenance reservation, participation, quorum, candidate testing or post-update progress. There is no emergency coordinator override. This conservative policy can be relaxed only through a separately reviewed specification and tests.

## Normal operation

1. Stage the signed release and artifact locally with `release-stage`.
2. Run the isolated candidate suite. The candidate environment has no network, production keys or host mounts.
3. Review and locally approve the exact release digest for a bounded activation window.
4. Create and verify a post-approval encrypted backup.
5. Import the fully endorsed maintenance plan. Record fresh peer, authenticated API and private UI probe digests with `participation-stage-record`. These files contain no endpoints or credentials.
6. Collect fresh signed participation responses. Verify both bridge-key possession and finalized contract membership. The validator being updated never counts toward its own threshold.
7. For every wave after the first, import the immediately preceding operator's signed installed-release and two-direction progress result.
8. Record an update readiness receipt. All checks must pass and the receipt expires after at most 30 seconds.
9. In the private operator application, start the exact release and mode. Starting writes the durable journal but performs no external action.
10. Advance one phase at a time: `drain`, `stop`, `install`, and `verify`. Every intent is persisted before the action, so retry after interruption repeats only the same idempotent phase.
11. Keep the managed signer locked and process-fenced until protected-terminal activation. The browser never unlocks a vault or signs bridge traffic.
12. Record fresh post-update progress. Both transfer directions and both local-signature counters must change after verification before the wave becomes complete.
13. Export the signed wave result for the next operator, then archive the terminal local update record.

## Failure and rollback

Drain or stop failures enter `halted`; later phases must not start. Investigate the worker and archive the terminal record only after review.

Install or verification failures for a rolling or emergency release enter `failed` with recovery `rollback`. Choose **Restore exact prior release** in the private UI. The installer restores the retained prior artifact and registration while the failed candidate stays fenced. It does not automatically restart signing. Verify process ownership and current-release identity before any protected-terminal activation.

Never use rollback after a migration has changed a database schema, configuration schema or signing codec. Such failures enter `failed` with recovery `forward`. Stage, test and approve a newer recovery release for the migrated format, then use **Install reviewed forward recovery**. The operation returns to post-install verification and still needs new two-direction progress.

## Interruption and outage handling

`update-operation.json` records intent before each host action. After process or host restart, inspect the journal in the private UI and retry the same phase. Do not edit the journal. A different operation cannot start until the active operation reaches a terminal state and is explicitly archived under private bounded history.

If the registry is unavailable after staging, continue only if the local staged artifact still verifies. If maintenance or participation evidence expires, do not start a new wave. A validator already running its reviewed release continues independently of those services.

If the old process still holds the managed session lock, stop. The drain/stop gates and fixed local installer refuse installation. If the new process cannot verify its exact release and registration, recover while both old and new signing paths remain fenced.

## Operator UI and relayer scope

The operator UI is a separate `vortex-operator-ui` artifact. Its manifest currently declares operator API `v1`. The client checks the API version before showing a workspace and fails closed on a missing or incompatible version. Updating or rolling back this static artifact changes only the loopback UI release/symlink; it does not restart the validator. The public Bridge/Redeem build has no operator code, credentials or update controls.

The private relayer is excluded from this release scope because its source, cursor migration, funding policy and independently controlled submission-key custody have not been reviewed. It must become a separate signed component and authority before it can share a release plan.

## Evidence to retain

- Signed release manifest, publisher verification and exact artifact SHA-256
- Candidate report and checker SHA-256
- Local approval, encrypted backup verification and maintenance reservation
- Fresh signed participation, contract membership and external stage evidence
- Readiness receipt and every update journal step
- Failure, rollback or forward-recovery evidence
- Post-update progress and signed wave result

Do not record private keys, unlock material, credentials, IP addresses or private endpoints in portable evidence.
