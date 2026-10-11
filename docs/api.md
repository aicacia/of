# Node API contracts

Source-audited on 2026-10-11 at ticket-06 base `2e67ed5`, with subsequent client/caller owner evidence linked below. These are scoped contracts and qualification, not a claim that owner deliveries are merged or full offline-first acceptance is complete. [System design](design.md) defines requirements; [audit evidence](../.scratch/offline-first-nodes/evidence/06-audit.md) records scope, findings and limitations.

## Owner contracts

IdP owns identity administration, OAuth/OIDC, Device membership and public signer trust. Management owns permissions, restrictions, selections and replication admission. Storage owns namespace catalogs/resources and local Residency. Identity administration goes directly to IdP, never through a Management proxy.

The paths below are owner-relative; unified hosting mounts `/idp`, `/management` and `/storage` once. They are not a substitute for complete live OpenAPI documents.

| Owner | Current contract | Authorization boundary |
| --- | --- | --- |
| IdP | User, Application, Client and Device administration | Verified User actor; exact action and Application/Installation target |
| IdP | `GET /devices/identities/{device_id}` | Ordinary authenticated service caller with `idp.device.lookup`; current signer-backed Device/owner binding |
| IdP | `PUT /devices/{device_id}/owner` | Exact Installation `idp.devices.transfer`; active new User; acknowledgement is not cleanup completion |
| IdP | `POST /replica-signers`, `PUT`/`DELETE /replica-signers/{member_id}` | Exact Installation `idp.replica_signers.enroll`, `.rotate`, `.revoke`; public approval never supplies private capability |
| Management | `POST /permissions/evaluate` | Same verified User actor, or separately registered IdP evaluator Client with only `management.permission.evaluate`; `idp-management` audience and exact typed action/target |
| Management | Device selection, resource-specific deselection, restriction read/update | Distinct permissions plus current local IdP Device identity; ownership and administrator restriction grants are separate |
| Storage | Database/filesystem catalog CRUD and filesystem Residency | User subject/Application namespace, kind audience and typed read/write action; current local owner/policy/cleanup gates |

`/replica-signers` and its permission identifiers are current exact-permission contracts despite their historical spelling. They do not designate privileged replica Nodes and must not be removed merely by searching for `replica`. Storage/Management request bodies, statuses, cleanup and Passthrough limits are documented in [Storage API](../crates/storage-service/docs/api.md). OAuth password authentication remains a supported sign-in grant; it is not a Node-join mechanism.

## Prefixes and application identity

Unified runtime assigns the three service prefixes. Owner OpenAPI routers normalize prefixed paths for owner-relative generation. Configure clients with the verified service base, append an owner-relative path once, and inspect the complete specification rather than assuming its server/path convention. Do not turn `/idp/idp`, `/management/management` or `/storage/storage` into compatibility routes.

Management's built-in Application URI/audience `idp-management` is not the `/management` transport prefix. Keep Canonical Issuer, token audiences, public Application URIs, listener addresses and authenticated endpoint identity distinct. Ordinary local service clients retain their separate scopes/audiences and secure secret references in [operations](operations.md#secrets-and-local-identity).

## Setup, join and readiness

`/setup/bootstrap` and its unused HTTP setup/join request contracts were removed through the source owner workflow. There is no replacement unauthenticated HTTP setup mutation, password-grant join, Storage-only join or privileged replica mode. Restricted native IPC and explicit local CLI provisioning are separate trusted host seams, not public administration shortcuts.

The native setup-only router exposes `GET /lidp/setup/status` with the Installation stage. This is a setup probe, not a durable public-readiness API. `SetupStage`/`SetupStatus` remain legitimate active contracts; do not delete them with obsolete bootstrap models. Native commands coordinate explicit create/join, offer approval, retry, Device completion and local reset. Join pins a trusted reachable approving endpoint and binds Installation, Device/member and independent public signer. A persisted approval receipt alone does not authorize ordinary DATA or complete public bootstrap.

`UnifiedRuntime::node_public_ready` / `node_join_public_ready` check current owner trust and signing capability. Desktop additionally retains Installation/Device completion state and evaluates current runtime readiness. A running HTTPS listener, setup status, endpoint allowlisting, completion marker, successful sign-in or Residency acknowledgement alone is not complete readiness. Partial setup remains incomplete; completed Nodes are required to remain usable after offline restart without a freshness lease.

Production provisioning and purpose-bound bootstrap exist, with scoped backend evidence. **Ticket 04 authorized GUI approval, joining-Node completion and two-profile offline restart remain unverified.** See the [native checkpoint](../.scratch/offline-first-nodes/evidence/04-native-acceptance/checkpoint.md); offer display must not be promoted to approval or full-spec acceptance.

## Generated clients

Generate from complete specifications obtained from verified current owner endpoints using the existing temporary-output workflow in `scripts/generate-openapi-client.mjs`. At this audit base its inventory contains 88 operations across nine groups (IdP 50, Management 24, Storage 14), including current permission, Device, restriction, selection, transfer and Residency operations. Purpose-bound native join/readiness must not be invented as HTTP operations to fill an inventory.

Missing URLs, unreachable endpoints, incomplete operations/supporting files, generator failure or staged formatting failure must leave checked-in generated sources unchanged. Never hand-edit generated models/routes or use stale generated setup APIs as evidence that a removed route is supported. The original audit-base stale bootstrap finding is historical: client-owner evidence at `dcdf8e9` records actual generation from all three isolated live public routers (50/24/14 operations, 88 total across nine groups) and removal of `SuperRoutesSetupApi`/`SetupBootstrapRequest`. [The current handoff](../.scratch/offline-first-nodes/evidence/06-audit.md#current-clientcaller-handoff--2026-10-11) links owner evidence without asserting integration. [Generator safety](../.scratch/offline-first-nodes/evidence/06-generator-safety.md) and [source removal](../.scratch/offline-first-nodes/evidence/06-obsolete-contracts.md) retain prior exact results. This documentation task reran no generation or client/UI tests.

## Storage client consumption

The caller delivery uses explicit `idpBaseUrl` and `storageBaseUrl`, not legacy `baseUrl`/`audience` options or an origin-derived audience fallback. Password-manager requires both `PUBLIC_LIDP_BASE_URL` and **`PUBLIC_STORAGE_BASE_URL`** as complete service bases, including `/idp` and `/storage`; `PUBLIC_STORAGE_AUDIENCE` is no longer consumed. Token exchange selects `resource=storage:filesystems`; catalog calls append `/filesystems` to the Storage base and the socket uses that base with flat Storage requests, preserving each prefix once.

Public Storage package exports resolve through `esm`/`types`. Explicitly run the package's normal build before publication; there is no automatic `prepack` hook. Distribute the complete output, including compiled generated dependencies, not only the five tracked output files. Workspace source consumption and distribution builds are separate; see [operations](operations.md#client-configuration-and-distribution).

## Source anchors

- IdP routes and OpenAPI: `crates/idp-server/src/router/routes/`, `crates/idp-server/src/router/openapi_router.rs`.
- Exact identity permissions: `crates/idp-model/src/contract/permission_evaluation.rs`.
- Actor binding: `crates/management-server/src/router/routes/permission_evaluation.rs`.
- Selection/identity owner calls: `crates/management-server/src/router/routes/device_selection.rs`, `crates/management-service/src/hosted_control_plane.rs`.
- Shared host prefixes/readiness: `crates/unified-server/src/runtime.rs`.
- Native setup probe/lifecycle: `apps/app/src-tauri/src/setup.rs`, `apps/app/src-tauri/src/app.rs`.
