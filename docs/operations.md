# Node operations

These are current operational requirements for the confirmed [offline-first Node design](design.md), not a tested deployment runbook. [Ticket 07](../.scratch/offline-first-nodes/issues/07-node-operations-and-runtime-lifecycle.md) must verify executable procedures, platforms, images and recovery.

## Deployment and readiness

Every Node runs IdP, Management and Storage with separate context data roots and one shared host `iroh-chain` endpoint/router with persisted endpoint identity and local trusted membership. There is no Storage-only, designated-authority or privileged-replica deployment mode. Keep Canonical Issuer/audiences separate from transport addresses and mount service prefixes once.

Create an Installation through restricted local setup with stable retry IDs and explicit initial administrator permissions. Join through a trusted reachable peer with authorized purpose-specific approval, approved endpoint/public signer binding, local secure signing capability and trusted shared state. Partial setup remains incomplete. After completion, trusted identity/policy and endpoint/completion state survive offline restart; readiness is not a 30-second lease and does not require the joining peer to remain reachable.

Authenticate owner-service calls even on loopback. Desktop uses one HTTPS listener, persistent port, explicit CA trust and certificate verification. Require TLS for remote HTTP. Secure-store/TLS failure stops setup/startup without plaintext fallback. Port conflicts must not silently change identity. Each Node owns and closes its endpoint once, and Storage denial must not erase independently authorized identity/join admission. Reuse `ofnet`'s endpoint/mesh/pairing/allowlist/generic connection-routing machinery; `of` owns trust decisions and domain/protocol adapter composition. See [networking ownership and source interfaces](design.md#networking-composition-and-trust).

## Current unified CLI provisioning boundary

The standalone `unified-server` CLI currently supports serving an **already provisioned** Unified Host, not creating a fresh Installation. Its config supplies separate context roots, issuer/audiences and exact service Client IDs; relationship secrets come from `UNIFIED_MANAGEMENT_IDP_CLIENT_SECRET`, `UNIFIED_STORAGE_IDP_CLIENT_SECRET`, `UNIFIED_STORAGE_MANAGEMENT_CLIENT_SECRET`, and optional `UNIFIED_IDP_MANAGEMENT_CLIENT_SECRET`. Loading these references does not create their Clients or authorize private-key production. Startup opens the existing endpoint identity and must never fall back to fresh provisioning when a key or owner record is missing.

There is no verified standalone local provisioning command to publish here. Do not substitute the IdP service-client administration command, HTTP registration, manually seeded databases, or a raw-secret manifest for Installation Setup. Desktop setup is a separate host boundary, not a standalone CLI procedure qualified by this document.

The prerequisite investigation found an interrupted initial-Node signer gap in the public IdP owner API: `prepare_node_signer` and the unenrolled branch of `ensure_initial_node` can create missing private signer material, while existing-only `verify_node_signer` requires already enrolled trust. A local host can refuse every ambiguous unenrolled retry, but cannot verify/reuse a retained pre-enrollment signer through that existing-only API. The owner must provide an exact, existing-only continuation boundary before a retry-capable local provisioning command can be qualified without replacement-key fallback or private-repository access. See [07 local provisioning evidence](../.scratch/offline-first-nodes/evidence/07-local-provisioning/README.md). This prerequisite remains blocked; it does not resolve ticket 07 or establish deployment, desktop GUI, Windows, backup/recovery, or full lifecycle readiness.

## Trust, partitions and revocation

At startup, `of` loads persisted locally trusted approved/non-revoked Installation Device endpoint membership into the shared `iroh-chain` allowlist and updates it as changes are learned. `EndpointIdStore` itself is in-memory, not a persistent trust store. Restore the endpoint key and owner trust state before ordinary protocol use without a live central lookup or expiry lease. Pairing exchanges are purpose-specific, not general access; connection/handshake allowlisting is not resource permission.

Use persistent trusted local IdP/Management state for authorization. Missing, invalid or locally revoked evidence denies the affected operation. Remote disconnection alone does not invalidate completed local trust. Any Node may mutate identity/policy/resources after its actor/action/target check.

A revocation/restriction becomes effective when a Node learns it. Verify denial of subsequent local operations, including on existing connections, and eventual propagation, not immediate global rejection on disconnected peers. Allowlist removal alone does not reauthorize those operations; `of` must retain execution-boundary checks. An already-authorized operation may finish. Previously copied bytes cannot be recalled. A Node learning transfer/deselection must gate affected local use until managed-copy cleanup or reset completes; an unaware offline Node can temporarily continue under its earlier view.

OAuth code consumption/refresh rotation is durable and atomic locally. Partitioned Nodes have no global single-use guarantee. Operators must not assume that reconnect reconciliation prevented earlier concurrent consumption or introduce a designated consumer to preserve the old role model.

## Secrets and local identity

Keep each Node's independent private signer local. Synchronize only explicitly approved public/other domain records; do not synchronize raw passwords, raw client secrets or private keys. Store secrets in the consuming service's supported OS keyring/deployment secure store. Protect local CA/server/private-signing key material with platform-equivalent owner-only permissions. Manifests contain IDs/references, not secrets. Never commit populated secrets or log tokens/credential bodies.

Existing ordinary service-client boundaries, where used locally, remain least-privilege:

| Caller → receiver    | Required scopes                                               | Audience boundary                                     |
| -------------------- | ------------------------------------------------------------- | ----------------------------------------------------- |
| Management → IdP     | `idp.token.validate`, `idp.device.lookup`                     | Configured IdP service audience                       |
| Storage → IdP        | `idp.token.validate`, `idp.device.lookup`, `idp.device.list`  | Configured IdP service audience                       |
| Storage → Management | `management.replication.read`, `management.replication.admit` | Configured Management Storage audience                |
| IdP → Management     | `management.permission.evaluate`                              | Management Application audience; registered evaluator |

Use distinct confidential clients/secrets per relationship and environment; never use User passwords for background service calls. Limit inspected-token audiences to caller needs. These local context calls must not introduce a live central authorization dependency. Exact current configuration and command support require verification in 07; the historical example's missing fourth relationship is not solved by this documentation migration.

Rotate through authorized local IdP operations, persist new consuming credentials securely, verify exact scopes/audiences and real owner calls, then revoke the old registration and remove old secret references. Test interrupted rollout and retry. A compromised client must be revoked locally and the change propagated; locally learned old credentials/tokens must fail appropriate activity checks. Other partitioned Nodes may not yet know the revocation. Never widen permission to mask a failed rollout.

## Persistence, reset and recovery

Persist context stores, endpoint identity and protected secrets for restart. `ofdb` owns SQL/KV sync/staging/batching/cleanup through public `ofdb-sql`/`ofdb-kv`; `offs` owns filesystem persistence/sync, not transport. `of` owns protocol-specific adapters wiring these owners to shared `ofnet` networking, not a second reusable networking stack. Mesh messages and direct Iroh streams are distinct; operations must not assume transparent multihop SQL/KV/filesystem synchronization. Do not run competing processes against the same local service roots or copy private signers to another Node.

Back up current-format local domain stores, endpoint identity and protected local secrets according to verified owner/platform procedures. Recovery restores that Node's trust and signing capability; it is not authority promotion and needs no live central service. No complete executable backup/recovery procedure is verified here. Invalid/incompatible state is preserved for explicit recovery/reset; do not silently delete or migrate it.

Reset removes only local setup/data/identity and can proceed offline. Attempt authorized revocation/propagation when possible. Secure-store deletion failure preserves remaining retry state. Deselect removes a local copy, not the global resource; deletion synchronizes a Tombstone. Passthrough content reads need an authorized reachable Full peer and cannot write.

## Verification still required

- Live create/join/interruption/retry/offline restart/reset, actual secure-store support and Windows key ACLs.
- Safe current API/client generation, complete Node configuration, binary/image feature support and workspace-parent build context, persistence, TLS and unattended secret access.
- Real locally authorized client rotation/revocation and learned-state propagation.
- Tested current-format backup/recovery, offline allowlist restoration/update, pairing isolation, existing-connection denial after learned revocation, and exactly-once runtime shutdown.
- Public persistence/execution/cleanup owner APIs and generic owner acceptance at `ofdb/.scratch/storage-sync/map.md` and `offs/.scratch/filesystem-sync/map.md` (handoff targets, not verified here).

Check disk space before future image builds; do not prune Docker or delete caches/data without review. [Ticket 08](../.scratch/offline-first-nodes/issues/08-offline-node-integration-and-final-validation.md) records future real integration and final `of` validation commands. No code tests, builds or deployment commands were run in this documentation migration.
