# Offline-first equal Nodes

Status: ready-for-agent

## Goal and confirmed decisions

Each Node runs IdP, Management, and Storage and can independently mutate identity, policy, and resources after checking actor permissions against persistent trusted local state. There is no designated writer, authority/replica role, promotion, central authorization dependency, or 30-second freshness lease. Completed Nodes remain usable offline and after restart. Revocations become effective when learned; temporary divergent decisions are accepted.

Nodes retain independent local private signers and one Installation Canonical Issuer. Approved public signer and other allowlisted domain data can synchronize. Private keys, raw passwords, and raw secrets remain local. Authenticate peer provenance, reject forged identity/actor claims, and distinguish token subject, signer, and endpoint identity. A join requires a trusted reachable peer and authorized approval, but ongoing operation does not. Retire Storage-only and privileged replica joins rather than preserving role compatibility.

All Nodes can issue user/client tokens and locally authorize code/refresh lifecycle operations. Consumption is durable and atomic locally. Partitioned Nodes have no global single-use guarantee; do not require global coordination to pretend otherwise. Token and mutation checks still enforce issuer, audience, use, lifetime, client, scope, active locally known Principal/signer, and exact actor/action/target permission. Missing or invalid local evidence denies; remote disconnection alone does not.

## Ownership and implementation constraints

- `ofnet`/`iroh-chain`: reusable Iroh endpoint/mesh/pairing mechanics, endpoint allowlist enforcement, and generic connections/routing. Reuse existing machinery; no blanket rewrite, new networking framework, or new mandatory tracker is required.
- `of`: identity, policy, resource catalogs/namespaces/lifecycle, domain trust binding endpoints to Installation Devices, local authorization, protocol-specific transport adapters wiring public `ofdb`/`offs` APIs, and host composition.
- `ofdb`: SQL/KV persistence, CRDT sync, staging, batching, cleanup, and generic tests. `of` uses public `ofdb-sql` and `ofdb-kv` only, with no backend/internal crate dependencies.
- `offs`: filesystem persistence/sync, local-copy cleanup, and generic tests; no transport ownership.
- Keep context repositories/data roots separate. Do not add cross-context repository access, alternate authentication, compatibility wrappers, or parallel local staging/transport layers.
- Use existing owner APIs and public persistence seams. A generic execution hook checks authorization before each apply operation; this spec does not prescribe a new trait. Domain policy stays in `of`.
- `of` loads persisted locally trusted approved/non-revoked membership into the endpoint allowlist at startup and updates it when changes are learned. Endpoint handshake admission is not resource authorization; pairing is purpose-specific exchange, not general access or domain approval.
- Receiving/enqueueing bytes is not apply authorization. Check actual API/read/write/apply operations, including on existing connections; an authorized in-flight operation may finish, but subsequent operations use newly learned revocations/restrictions. Allowlist removal alone is insufficient.
- No custom quotas, timers, deadlines, freshness caches/leases, fragmentation protocol, migrations, or global grant-consumption guarantee. Protocol integrity validation remains required; historical numeric limits are not new acceptance requirements.

## Required user-visible behavior

Restricted local setup creates explicit initial grants and stable retry identities. Joining uses purpose-specific authenticated approval through any trusted reachable peer and binds Installation, Device, endpoint, and independent signer. All contexts become locally ready; partial setup stays incomplete. Trust, policy, endpoint identity, signing capability, and completion survive restart without live peer contact. Secure storage/TLS failure does not silently fall back; reset is explicit, local, retry-safe, and allowed offline.

Resource isolation remains `(User subject, Application)` with stable kind-specific IDs, non-unique display names, selected-resource discovery, and no cross-user grants. Device mutation permissions, locally trusted IdP owner binding, administrator restrictions, and selection rules remain distinct. Selection starts empty; concurrent deselection wins. Unknown locally unverified resources cannot be selected; offline use of trusted local resources is allowed. Transfer/deselection cleanup affects runtime-managed local copies, not global resource deletion or remote erasure. A Node that learns a transfer must finish cleanup/reset before new-owner use; an unaware offline Node may temporarily continue under its prior local view. Full/Passthrough Residency remains local, with Passthrough requiring an authorized reachable Full peer for content and prohibiting writes.

Persistence owners preserve integrity, complete catalog/index atomicity, dependency-ready complete-row batches, rollback of a failed batch, earlier valid progress, recovery completeness, Tombstones, and source/local data on rejection. Network waits must not hold write transactions. Cancellation/error/shutdown cleans staging, handles, queues, streams, and tasks without harming unrelated resources. Frames are not commit units; source multi-row atomicity is not promised without protocol evidence.

Desktop retains one HTTPS listener, prefixes once, persistent port, explicit CA trust, secure local keys, one shared `iroh-chain` endpoint/router with persisted endpoint identity and local trusted membership, independent handler admission, and one shutdown. Identity administration goes directly to IdP. Existing least-privilege local service relationships must not become a remote authorization requirement.

Mesh Broadcast/Direct Message routing and direct Iroh connections/byte streams are distinct. Existing mesh forwarding does not establish transparent multihop SQL/KV/filesystem sync. Protocol-specific adapters must explicitly wire and authorize their exchange; forwarded message source claims are not authenticated connection identity. See [networking composition, source interfaces, and ofnet glossary](../../docs/design.md#networking-composition-and-trust).

## Workspace split and blockers

This effort replaces the umbrella tracker; it is not 20 renamed implementation steps. Its tickets cover only `of` work. Generic owner work is handed off to:

- [ofdb storage-sync](../../../ofdb/.scratch/storage-sync/map.md): public SQL/KV facades, native staging, pre-apply checks and local qualification in tickets 01–05; consumer-evidence handoff in 06.
- [offs filesystem-sync](../../../offs/.scratch/filesystem-sync/map.md): generic admission/content integrity in tickets 01–02; coordinated Iroh extraction/reconnect and final qualification in 03.

Both owner maps and all their tickets now exist and were reviewed. Exact prerequisite links are recorded in [the map](map.md) and affected tickets. Of 02 requires ofdb 01–05 and offs 01–02, not entire owner efforts. Ofdb 06 depends downstream on of 02 facade-consumer and of 03 real authorization evidence; it cannot block those producers or of 08.

Co-deliver filesystem Iroh extraction/consumer cutover between of 02 and offs 03 without reciprocal resolved-ticket prerequisites. Of 02 records the domain/protocol adapter destination in `of`, reuse of existing `ofnet` machinery, any genuinely generic missing piece justified by actual need, and coordinated consumer-cutover evidence; of 03 supplies real local authorization evidence. Do not mechanically relocate reusable endpoint/mesh/pairing/routing machinery into `of`. Offs 03 final acceptance then gates of 08, together with ofdb 05 local qualification. Tracker existence is verified, not implementation completion. Do not absorb external work into `of` or infer public whole-resource removal guarantees from stage-cleanup evidence.

## Machine-local qualification policy

User-approved scope, 2026-10-11: all eight `of` tickets and the linked `ofdb`/`offs` owner tickets close on reproducible, bounded evidence from this Ubuntu Linux x86_64 machine. This narrows qualification, not the identity, authorization, confidentiality, integrity, persistence or ownership contracts above. It supersedes broader current completion gates and historical lists of remaining platform qualification; historical results retain their original meaning.

- Use focused relevant package/test filters, changed-source provenance, applicable formatting/Clippy and boundary checks. One resource-bounded Rust build at a time; record exact commands, failures, timeouts and pre-existing diagnostics. Full Cargo Hack feature powersets, full-workspace/all-platform sweeps and CRAP are not completion gates and must not run without renewed authorization.
- Multiple Nodes are isolated stores/processes/endpoints on this host, with independent signers and actual local IdP/Management authorization. Controlled peer disconnection/reconnection and persisted reopen can qualify partition/offline semantics; they do not certify air-gapping, WAN/NAT/relay behavior or physical multi-device deployment. No live external authority is required.
- Use representative deterministic failure/interruption checkpoints for each distinct durable owner transition and cleanup path, not every instruction/private write or an exhaustive crash/power-loss matrix. Preserve fail-closed partial readiness, stable identities, rejection without repair, cleanup and subsequent-operation denial requirements. A real local bug remains a blocker even if a larger matrix is deferred.
- Linux desktop qualification may combine existing native observations, focused frontend checks and real TLS/runtime/owner tests. A callback or mock is evidence only for that seam, never proof of actual GUI approval, OS-process exit or secure-provider behavior. The already deferred GUI approval loop stays deferred; actual authenticated join/completion/offline-reopen is still required through the production join seam. No profile/keyring reset or system CA change is implicit in this scope update.
- Supported local secure-provider evidence is scoped to this session/provider and Unix protection. Fault-injection checks can prove refusal/cleanup, not real provider availability. Recovery acceptance covers stopped current-format filesystem restore on the same Node with retained protected credentials/provider, identity verification and invalid-state denial; it does not imply credential export/import or lost-provider recovery.

### Deferred qualification follow-ups (not ticket closure gates)

| Follow-up                                                          | Qualification trigger and present limit                                                                                                                                               |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows/macOS key protection and desktop lifecycle                 | Run on those platforms before claiming their support; Ubuntu checks do not establish equivalent ACL/keychain behavior.                                                                |
| Headless/unattended and container deployment                       | Qualify the exact intended provider, built image/binary, TLS/networking and persistence environment before advertising that deployment. Static recipe tests are not runtime evidence. |
| Physical multi-device, WAN/NAT/relay and GUI end-to-end matrices   | Run when that environment is available or the deferred native test is explicitly resumed. Same-host protocol tests are not these deployment certifications.                           |
| Provider loss, populated-content and crash/stale-snapshot recovery | Require a separately supported backup/provider procedure and representative content/fault fixtures; retained-provider filesystem recovery grants no such claim.                       |
| Exhaustive fault/concurrency/feature matrices                      | Follow-up assurance work, not bounded implementation-ticket gates. Do not hide known failures, leaked managed resources or missing task ownership behind this deferral.               |

Owner trackers retain their own API and generic integrity responsibilities. Statuses, prior checkboxes and dependencies are not automatically changed by this policy; unresolved tickets need an audit against their revised local criteria before closure. [Current ticket map](map.md).

## Acceptance and evidence

Generic integrity/atomicity/cleanup/restart/progress tests belong in `ofdb` and `offs`. `of` tests domain integration using real local IdP/Management services, public owner APIs, authenticated Iroh, and isolated Node stores. Prove offline restart, independent mutation/issuance, locally atomic grant consumption, accepted partition divergence, learned revocation before the next apply/write on an existing connection, endpoint allowlist restoration/update, pairing isolation, in-flight completion, impersonation rejection, join retry, cleanup integration, and reconnect. Loss of a remote authority is no longer a denial test; failed local permission evaluation still denies safely.

No code, test execution, commits, branches, or cross-workspace writes are part of this documentation migration. Future implementation tickets assess complexity/risk/priority and record exact focused and final commands/results. Final `of` validation follows implementation and real integration acceptance, not this migration.

[Map and all 20 old-ticket destinations](map.md). [Current system design](../../docs/design.md). [Current operations requirements](../../docs/operations.md).
