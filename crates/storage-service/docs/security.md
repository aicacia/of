# Storage security and transport

[Storage design](design.md) defines resource isolation; [system design](../../../docs/design.md) defines equal offline-first Nodes and owner boundaries. This is the confirmed target contract, not verified implementation behavior. Acceptance requires results recorded against the active tickets; no tests were rerun for this documentation migration.

## Local authorization

Storage API tokens authorize API actions, not mesh synchronization. Iroh endpoint keys identify transport peers, not Users or resource grants. No Device-key delegation, folder ACLs, or cross-user permissions are introduced.

Every Node hosts IdP, Management, and Storage with persistent trusted local state. IdP owns Device lifecycle; Management owns selections, restrictions, and admission policy. Storage uses locally checked owner-service decisions, not a live central authority. Context repositories remain separate. Restart restores local trust without a freshness lease or peer contact; invalid/missing local evidence fails closed, while a partition alone does not.

Derive local endpoint identity from the Node's endpoint and remote identity from the authenticated Iroh connection. Do not trust handshake owner/endpoint/selection claims or actor headers. Verify Installation, locally approved Devices and owners, both selections, restrictions, resource kind/ID, and subject/Application namespace. Discovery is not possession or permission. `of` restores persisted locally trusted approved/non-revoked membership into the shared `iroh-chain` endpoint allowlist and updates it on learned changes. `ofnet`'s connection/handshake allowlist enforcement is not resource authorization; purpose-specific pairing is not general access or domain approval.

Selection starts empty; concurrent deselection wins, and a causally later selection may restore sync. Revocations and restrictions block subsequent operations when learned locally. Temporary partition divergence is accepted; there is no immediate global revocation or remote erasure guarantee. Transfer/reset/deselection cleanup gates local reuse once learned, not an unaware offline peer's decisions.

## Execution boundaries

Authorize before each actual apply operation through the generic execution hook exposed by the persistence/sync owner. This requirement does not prescribe a new trait. Admission, send/receive checks, and queued bytes do not authorize later mutation. Check API/resource reads, outbound writes, and queued socket writes at execution as well. Both peers independently check their local policy. An already-authorized in-flight operation may finish; newly learned denial blocks the next operation, even on an existing connection. Allowlist removal or another handshake is not a substitute for these checks. Failed local evaluation denies without mutation. Remote Management/IdP unreachability must not invalidate a Node's usable local trusted state.

Do not add custom quotas, timers, deadlines, periodic authorization polling, or a 30-second freshness rule. Historical 5/10/30-second wrappers and numeric memory/frame/stage limits are observations of an older implementation, not requirements of this architecture. Retain owner protocol integrity validation, actionable rejection, atomicity, source/local data preservation, and cancellation cleanup.

## Ownership and acceptance

- `ofnet`/`iroh-chain` owns reusable endpoint/mesh/pairing mechanics, endpoint allowlist enforcement, and generic connections/routing; it does not own Installation/Device or resource policy.
- `of` owns domain identity, policy, catalogs/namespaces, Installation/Device endpoint trust, local authorization, protocol-specific transport adapters wiring `ofdb`/`offs`, and runtime composition. It integrates local authorization with public execution seams, not internal persistence transactions.
- `ofdb` owns SQL/KV persistence, CRDT sync, staging, batching, and cleanup. Consume public `ofdb-sql` and `ofdb-kv` only, never backend/internal crates.
- `offs` owns filesystem persistence and synchronization, including managed-copy lifecycle, not transport. Do not retain a parallel filesystem transport in `offs` to support the old architecture.

A Node uses one shared `iroh-chain` endpoint/router with persisted endpoint identity and local membership, not separate per-context networking stacks. Reuse existing `ofnet` APIs during filesystem adapter extraction; move genuinely generic missing pieces only on demonstrated need. Domain/protocol integration stays in `of`, with no blanket rewrite or new mandatory networking tracker. Mesh messages and direct byte streams are distinct; mesh forwarding does not authorize or establish transparent multihop SQL/KV/filesystem sync. A forwarded message's claimed source must not be confused with the authenticated connection peer. See [ofnet vocabulary and existing source interfaces](../../../docs/design.md#networking-composition-and-trust).

Persistence owners test generic integrity, complete catalog/index atomicity, failed-batch rollback, prior valid progress, exact recovery, Tombstones, reconnect, cancellation cleanup, and writer progress. Network waits must not hold write transactions. `of` tests authorization integration through real local owner APIs and authenticated Iroh: learned revocation between receive/apply and enqueue/write, permission failure after a proven committed batch, allowed in-flight completion, offline restart, accepted partition divergence, and rejected impersonation. No global OAuth single-use partition guarantee is asserted.

[Active tickets](../../../.scratch/offline-first-nodes/map.md) track cutover. Generic database work is blocked on `ofdb/.scratch/storage-sync/map.md`; generic filesystem work is blocked on `offs/.scratch/filesystem-sync/map.md`. Those external handoff targets are not verified by this migration. Old transport-only checks, stub outages, and historical freshness tests do not prove this contract.
