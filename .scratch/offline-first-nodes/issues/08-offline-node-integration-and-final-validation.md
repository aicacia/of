# 08 Real offline-Node integration and final validation

Status: ready-for-agent
Type: task
Work status: open
Blocked by: 01, 02, 03, 04, 05, 06, 07; [ofdb 05](../../../../ofdb/.scratch/storage-sync/issues/05-local-regression-qualification.md), [offs 03](../../../../offs/.scratch/filesystem-sync/issues/03-iroh-extraction-offline-reconnect.md)
Not blocked by: [ofdb 06](../../../../ofdb/.scratch/storage-sync/issues/06-consumer-integration-handoff.md) (documentation/evidence handoff consumes of 02/03 results, not a prerequisite for this final gate)

## What to build

Prove equal-Node domain authorization integration through existing public seams, then run final `of` validation. Question: do independently running full Nodes on this host meet the accepted partition/restart semantics without relying on shared repositories or mock authorization?

## Scope and acceptance criteria

Qualification follows the [machine-local policy](../spec.md#machine-local-qualification-policy): independent full Nodes run as isolated instances on this Ubuntu host. Real authorization, authenticated transport, partition/reconnect and persisted restart are required; physical multi-device/WAN, foreign-platform, exhaustive GUI/provider/fault and deployment matrices are follow-ups, not gates. Use representative deterministic cases for the behaviors below, reusing owner and earlier-ticket evidence rather than multiplying complete test matrices.

- [ ] Link ofdb 05 local qualification and offs 03 extraction/reconnect/final qualification evidence, including their concrete prerequisite results (ofdb 01–04 and offs 01–02). Validate generic integrity, catalog/index atomicity, complete-row batching, rollback/prior progress, recovery/Tombstones, cancellation and writer progress without duplicating owner harnesses. Verify whole-resource cleanup evidence separately through of 05; do not infer it from stage cleanup alone. Do not require ofdb 06 closure or entire owner-map completion.
- [ ] Use isolated full-Node stores, actual local IdP/Management services, public HTTP/TLS owner APIs, restricted local setup commands and real authenticated Iroh. No shared context repositories, permissive adapters, stub policy server or mocked authorization counts as full acceptance.
- [ ] Create and join via a trusted reachable peer; deny unpermitted/forged approval. Disconnect peers, restart completed Nodes and prove independent identity/policy/resource mutations and user/client issuance from persisted trusted state. Incomplete/untrusted/corrupt local state does not gain readiness.
- [ ] Partition Nodes and demonstrate accepted temporary policy/revocation divergence and absence of global OAuth single-use guarantee. Prove durable local consumption/rotation and reconnect reconciliation, independent private signers and locally known approved JWKS/issuer checks. No freshness/promotion/designated-writer gate remains.
- [ ] After learning revocation/restriction, deny the next SQL/KV/filesystem apply and queued write on existing connections, without relying on reconnection or handshake-only allowlist enforcement. Explicit gates observe committed first batch and authorized in-flight completion; later denial preserves prior/source data and owner cleanup releases resources. Remote peer outage alone leaves valid local decisions usable.
- [ ] Exercise Device permissions/ownership, restriction APIs, selection/deselection, learned transfer cleanup, local-copy removal integration, local Residency, CRUD/socket namespace isolation, Tombstones/restart, reconnect, cancellation and shutdown. Forged descriptors/headers, wrong audiences and service principals cannot impersonate Users or approve Devices without permission.
- [ ] Compose one local Node listener and one shared `iroh-chain` endpoint/router, independent admission, persisted endpoint identity, disconnected trust restoration, learned approval/revocation, pairing isolation, representative secure-store/TLS failures and retry/reset using focused production-seam evidence from04/07. Verify managed runtime ordinary shutdown/cleanup and record detached owner-task limits. Do not repeat the deferred GUI/platform/deployment matrix or claim callbacks prove live process exit/provider availability.
- [ ] Verify protocol-specific `of` adapters consume public `ofdb`/`offs` sync APIs and reuse `ofnet` mechanics, with no duplicate networking layer or leaked domain policy in generic owners. Keep direct protocol-stream acceptance separate from mesh Broadcast/Direct Message tests; neither proves transparent multihop DB/FS sync. Use [existing interfaces and ofnet vocabulary](../../../docs/design.md#networking-composition-and-trust), not invented API guarantees.
- [ ] Audit code/config/API/client/documentation ownership and obsolete centralized assumptions; report cross-workspace gaps to owners. No blanket `ofnet` rewrite, new networking framework or new mandatory tracker is part of this gate. Resolve implementation and real acceptance before final validation.
- [ ] From `of`, run applicable changed-file/package formatting checks, focused Clippy and relevant unit/integration/client tests for the supported Linux features exercised by this effort; run `just boundary-check` when boundaries changed. Record literal package/feature/test filters, source provenance, exit statuses and existing warnings/failures. Use bounded single-job Rust commands; full-workspace/all-platform/feature-powerset and CRAP sweeps are excluded unless separately authorized. Consume owner workspaces' focused local gates, not duplicate their suites.
- [ ] Preserve dirty work, lockfile, caches and data; distinguish failures/timeouts/pre-existing issues. Never claim unrun checks passed.

## Verification and completion

Assess complexity/risk/priority before harness changes. This ticket is a future implementation gate: no tests/builds execute during the documentation migration. Record reproducible fixtures/results, not historical numeric budgets, custom quotas/deadlines, or inferred memory guarantees.

## Comments

2026-10-11 — User-approved machine-local scope: this is a bounded Ubuntu same-host full-Node integration gate, not cross-platform/deployment certification or an exhaustive sweep. All locally testable authorization/integrity/partition/reconnect semantics remain required.04/07 are audited under their revised local criteria, with GUI/platform/provider/deployment follow-ups retained explicitly. Dependencies/status remain unchanged; existing mocks or deferred evidence are not upgraded to successful integration.

Replaces old 19/20 umbrella acceptance/final validation and retains domain integration from 05/18. Owner maps/tickets were reviewed: the final external gates are exactly ofdb 05 and offs 03. Ofdb 06 receives of 02/03 evidence downstream; offs 03 co-delivers extraction with of 02 without reciprocal completion gates; detailed authorization evidence follows in of 03 and is required here, not before offs 03 extraction acceptance. [Spec](../spec.md), [coverage map](../map.md).
