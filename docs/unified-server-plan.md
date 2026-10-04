# Independent servers and unified hosting

## Goal and status

Ship independently deployable IdP, Management, and Storage services, plus `unified-server` for single-host deployment. Both deployment modes use the same authenticated owner-service APIs. Unified hosting has one HTTPS listener and exactly one persisted Iroh key, endpoint, and protocol router.

The architecture is settled in [ADR 0002](adr/0002-service-authority-and-replica-boundaries.md); this plan records implementation and acceptance status. Work is in progress. Breaking changes and a temporarily broken repository are allowed. Do not claim a step complete until its acceptance criteria are met.

## Required service boundaries

| Component                          | Owns                                                                                           | Calls                                                                      |
| ---------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| IdP                                | Users, applications, OAuth clients and grants, signer registry, device enrollment and approval | Management permission evaluation for identity administration               |
| Management                         | Roles, permissions, assignments, restrictions, selections, replication policy                  | IdP validation/device APIs; Storage reads for user resource selection      |
| Storage                            | Resource metadata/content, database/KV/filesystem runtimes, sockets, replication               | IdP validation/device APIs; Management selection and admission APIs        |
| Host (`unified-server` or desktop) | Composition, listener, provisioning coordination, shared endpoint, lifecycle                   | Owner-local first-install operations and normal authenticated service APIs |

- No server crate depends on another server crate. A composition host may depend on multiple servers.
- Services retain independent engines and data roots, including in unified mode. Hosts must not read/write service repositories to implement authorization or provisioning.
- Management owns installation RBAC. It does not proxy identity administration. Users call IdP directly; IdP checks Management’s normal permission API. Permission failure or timeout denies the mutation.
- Management is one authoritative policy domain per installation. Management replication is out of scope.
- Application-scoped permissions control application operations. Explicit installation-scoped permissions control installation-wide identity administration and infrastructure service-client lifecycle. Never grant a wildcard that includes future capabilities.
- IdP verifies the user/service bearer token locally, then submits the verified subject, exact action, and target to Management using its distinct ordinary service bearer token. Do not forward actor headers or user tokens. Permission evaluation must not call back into IdP administration.
- User and service bearer validation use the same authoritative path. Validate issuer, audience, token use, time, active signer, live principal, principal type, and exact permission. Possession of a valid user token alone is not administration authority.
- No `/internal/*` routes, custom service-auth headers, shared-secret resource guards, alternate token issuers, authorization caches, unified-mode bypasses, or synchronized local RBAC projections.
- No database migrations, backward-compatibility path, old-schema loading, export/import cutover, or application-level database lock. Require clean installation; detect prior state and demand an explicit reset. Never silently delete or overwrite it.

## Endpoint and HTTP ownership

**Unified mode owns exactly one Iroh key, endpoint, and protocol router per host.** Register IdP bootstrap and Storage DATA handlers on that one router. Inject the same server into IdP and Storage. Neither service may bind, persist, refresh admission for, or close another endpoint. Sharing a key across two endpoint instances is not sufficient.

Standalone IdP and Storage each own their endpoint, key, router, and shutdown. Management does not need an Iroh endpoint. Shared transport admission is not resource authorization; a Storage failure must not erase independently authorized IdP bootstrap admission.

Unified HTTP mounts `/idp`, `/management`, and `/storage` exactly once. Standalone prefixes remain configurable. Keep public issuer/audiences separate from service transport URLs, preserve prefixes when joining paths, authenticate loopback requests, and require TLS outside verified loopback.

Desktop uses one HTTPS listener, not a proxy plus a second HTTP listener. Separate runtime construction/lifecycle from serving. The host supplies listener and TLS-client configuration, serves the composed router, starts background tasks after readiness, and shuts down each task and the shared endpoint once. Persist the HTTPS port; an occupied port is an actionable error, not a new issuer. Use stable installation-scoped keyring names independent of listener URLs. Trust the local CA explicitly with certificate checks enabled. Protect TLS key files and fail if secure storage fails; never fall back to plaintext.

## Provisioning, installation, and deployment roles

First installation uses owner-local operator commands or capability-restricted Tauri commands. Each service performs operations against its own state; the host coordinates canonical IDs and results. No unauthenticated HTTP mutation route replaces `/setup/new` or `/setup/join`. Running-service mutations use normal RBAC-authorized APIs.

Provision distinct least-privilege service clients for each relationship:

| Caller → receiver    | Capability                                                |
| -------------------- | --------------------------------------------------------- |
| Management → IdP     | Token introspection and approved endpoint identity lookup |
| Storage → IdP        | Token introspection and approved endpoint-ID listing      |
| Storage → Management | Selection listing and replication admission               |
| IdP → Management     | Permission evaluation only                                |

Return each secret only to authorized provisioning, retain it in the consuming service’s secure storage, and store only a one-way verifier at IdP. No shared/default secret. Persist secrets before declaring setup complete. Partial setup is not ready; retry with stable IDs, verify prior steps, and avoid duplicate users/clients/keys. Reset is explicit and local; attempt remote revocation through authorized APIs.

Deployment roles:

- **Fresh unified installation:** designated IdP authority, Management authority, and Storage; one shared Iroh endpoint.
- **Storage-only join:** remote IdP/Management APIs; no IdP database copy or local OAuth authority.
- **IdP-replica join:** only defined IdP state, canonical installation issuer, existing Management authority, and a separately approved signer with local private key.

IdP replica enrollment requires the right audience and installation-scoped replica-enrollment permission. Ordinary Storage device approval is not replica approval. Readiness requires trusted signer enrollment, the joining endpoint’s approval, complete fresh synchronization, and local signing capability.

## IdP authority, replicas, and OAuth

- One designated IdP authority owns identity changes, signer enrollment/revocation, authorization-code creation/redemption, and refresh-token rotation/revocation. Clients call the authority directly. No concurrent replica administration, forwarding, fallback, or automatic promotion.
- Each replica has its own private signer. Never copy private signing keys. Signer identity is separate from token subject. Validate with approved public signing material and publish consistent approved-signer JWKS.
- Authorization-code and refresh-token consumption must be atomic at the designated authority. Verify signature and all claims before consumption; persist rotation/revocation. Replicas never redeem synchronized grants. Local atomicity tests do not prove cross-replica atomicity.
- Replicas may validate tokens and issue client-credentials tokens only while authoritative security state is fresh. Broader replica user-token issuance is out of scope.
- Security-state freshness is at most **30 seconds**, measured from successful authenticated synchronization using a local monotonic clock. Restart begins unready. Expiry stops validation and issuance until a trusted sync completes. Repeated/stale responses cannot renew freshness.
- Replicate only defined IdP records and client-secret verifiers. Exclude Management/Storage records, raw secrets, and replica private keys. Whole mixed-engine copying is prohibited.
- Fail closed on authority loss. Recovery uses a valid current-format backup and documented operator action; no stale-replica fallback.
- Do not expose arbitrary-message `/device/sign`. Use authorized purpose-specific operations that construct their payload, or restricted local Tauri commands.

## Bounded Storage synchronization

Management returns policy decisions, not proof of an Iroh connection. Storage derives its local endpoint from the injected server and the peer from `Connection::remote_id()`. Both peers independently check exact owner, application, kind, resource selection, and admission before every bounded synchronization operation. Never trust handshake endpoint or owner claims.

| Boundary                        | Initial limit |
| ------------------------------- | ------------: |
| SQL/KV encoded frame            |         1 MiB |
| Filesystem content chunk/frame  |         1 MiB |
| Marker/handshake deadline       |     5 seconds |
| Complete policy-check deadline  |    10 seconds |
| Authorized batch/chunk deadline |    30 seconds |

Check policy before each bounded operation on both peers. An already-authorized operation may finish within its bound; denial or unavailability stops the stream and all new work. Bound pending data, queues, and apply work, not only individual frames. Cancellation must stop child tasks and queued work. An idle connection does not retain authorization for its next operation.

Oversized records/transactions fail clearly and retain local data. Do not truncate, skip, or add a fragmentation protocol. Completed valid batches may remain committed after a later failure. Preserve atomic transaction invariants; do not split transactions unsafely. Reuse existing sync protocols. Narrow changes in `ofdb` and `offs` are approved where needed.

## Verified implementation and open work

Status below reflects repository evidence available on 2026-10-04. Earlier focused results are not final validation. Do not infer completion from a passing unit test where live topology or production wiring remains absent.

### 1. Close unsafe OAuth and signing paths

- [x] Remove arbitrary-message `/device/sign` and its OpenAPI entry; purpose-specific local device signing replaces it.
- [x] Persist refresh-token issuance and local atomic rotation/revocation using existing schema. Verify signature, issuer, audience/client, token use/type, principal/subject, time, client authentication, and scope before consuming. Tests cover one local concurrent winner, persistence/reopen, reuse, rollback, and revocation.
- [x] Store one-way client-secret verifiers in the existing initial schema; disclose secrets only on creation/rotation, and verify supplied secrets during client authentication.
- [x] Require bearer authentication on client registration routes; unauthenticated route assertions exist in live IdP listener tests.
- [ ] Complete route-level authenticated RBAC denial/allow coverage for client create/read/update/delete and related administration. Authorization alone is not permission.
- [ ] Do not claim cross-replica single-use grant safety; authority routing and live replica topology are still open under step 2.

### 2. Implement independent signers and replica authority

- [x] Add authority/replica role configuration and reject user-grant, consent, code, refresh, and revocation mutations on replicas in shared service logic.
- [x] Persist public verification material separately from local private stores; verification/JWKS can use public material and still require an active live principal/root. Signing requires matching local private material.
- [x] Add signer metadata and subject/signer binding contracts; deny replica issuance until enrollment, local signing, and freshness integration exist.
- [x] Add a monotonic 30-second readiness predicate with restart-unready semantics. No production synchronization writer exists; the predicate cannot be seeded by configuration or replayed responses.
- [ ] Persist approved signer records and installation membership in existing initial model/schema; add repository-level validation and designated-authority-only enrollment, uniqueness, rotation, and revocation. Do not add a migration.
- [ ] Implement authenticated, scoped authoritative IdP synchronization with replay-resistant provenance, explicit record allowlist, and no grant-consumption records.
- [ ] Load a distinct local replica private signer; issue and validate tokens using approved signer identity while preserving independent subject/principal checks and canonical issuer.
- [ ] Connect trusted synchronization to freshness/readiness. Keep replica unready after restart, missing approval/key, invalid or stale sync, and authority partition.
- [ ] Test revoked signer/principal/client/device propagation, wrong-role enrollment, issuer/JWKS consistency, replay/staleness, partitions, and live independent signers. No auto-promotion.

**Current evidence:** `ReplicaReadiness` has only test seeding and no production writer. Public-key material and metadata are foundations, not approval or independent signer issuance. Do not enable replica issuance.

### 3. Implement normal RBAC permission evaluation

- [x] Add typed permission-evaluation request/response contracts and an authenticated Management permission endpoint/client.
- [x] Add IdP middleware that verifies the caller, checks the exact requested action/target through Management, and fails closed on denial or upstream error.
- [x] Apply permission checks to identity and role/permission administration routes as currently wired; add focused policy-boundary tests.
- [x] Audit mutation routes. Application/client/user/consent/key administration uses typed Management permission checks; device enrollment, rename, and revocation remain owner-scoped. The global pairing-acceptance read/update routes require distinct installation-scoped `idp.device_pairing.read` and `idp.device_pairing.update` permissions.
- [ ] Test allowed and denied user/service principals, cross-application access, installation escalation, exact action/target binding, timeout/unavailable Management, and no recursive authorization call chain. Added pairing acceptance HTTP assertions for unauthenticated denial, application-principal denial, and installation-admin success on both read and update, but the focused unified-server test could not compile because disk space was exhausted. These assertions are unverified. Production provisioning must grant these two permissions explicitly; test-fixture grants do not configure real installations.

### 4. Split first-install provisioning

- [x] Remove unauthenticated HTTP setup mutation behavior instead of restoring it. Keep only safe status/read paths where intended.
- [ ] Replace remaining mixed-repository bootstrap with service-owner-local IdP and Management operations that return canonical IDs/results.
- [ ] Implement local operator coordination and capability-restricted Tauri setup commands. Setup must not use a password grant or an alternate auth path as a shortcut.
- [ ] Provision the initial administrator with explicit installation-scoped grants, including `idp.device_pairing.read` and `idp.device_pairing.update`, through Management’s owner-local provisioning operation. Do not use wildcard grants. Provision the four distinct service relationships and persist each secret securely before reporting readiness.
- [ ] Make each stage restartable with stable IDs and verification. Test injected failure/retry after every stage, duplicate prevention, explicit reset, and rejection of legacy state without deleting it.

**Current gap:** Tauri setup still calls removed `/setup/new` and `/setup/join` mutation routes; residency/completion calls also target removed HTTP behavior. Replace those calls with restricted commands and owner-local operations. Do not restore those routes.

### 5. Enforce bounded synchronization

- [x] Add Storage-side 5-second connection/handshake, 10-second policy-check, and 30-second operation timeouts for database and filesystem paths. Database KV frames are configured to 1 MiB on both sides; `ofdb` SQL transport also rejects inbound and outbound frames above 1 MiB before decoding/applying.
- [x] Fix `offs` metadata reads to decode `ofdb_kv::Value` JSON values correctly; preserve the worktree’s JSON metadata representation and retain Postcard for existing wire/resource records.
- [x] Set `offs` filesystem frames, read requests, and response chunks to at most 1 MiB. Large file fetches use repeated bounded offset reads through the existing protocol.
- [x] Run `cargo fmt -p file-system -- --check` and `cargo test -p file-system --lib` in `offs`; formatting passed and all 6 tests passed, including oversized frame/read rejection.
- [x] Bound the filesystem stream-kind marker read by the 5-second handshake deadline; database marker reads were already bounded.
- [x] Run `cargo fmt -p storage-server -- --check` and `cargo test --locked -p storage-server --lib` in `of`; formatting passed and all 35 tests passed after the marker timeout change.
- [ ] Verify policy is checked on both peer roles before every bounded database, KV, filesystem, metadata, and content operation. Current wrappers/timeouts alone do not prove every queue/apply boundary is authorized.
- [ ] Bound pending bytes, queues, and apply work; ensure cancellation terminates child tasks and does not block unrelated resources or shutdown. SQL synchronization still exports the full state and constructs full outbound/recovery vectors before per-frame size checks; a 1 MiB frame limit alone does not bound that memory.
- [ ] Test oversized data retains source/local data, transaction atomicity, partial progress, tombstones, reconnect, policy denial/outage between operations, and timeout cleanup.

**Remaining:** The focused crates compile and test, but this is not end-to-end synchronization acceptance. Continue with per-operation authorization, queue/apply bounds, cancellation, and outage/oversize tests before marking this step complete.

### 6. Separate composition from serving

- [x] Existing server runtime builders and unified prefixed composition exist; Unified injects one server into IdP and Storage.
- [x] Source audit confirms UnifiedRuntime creates one persisted `UnifiedEndpoint`, injects its server into IdP and Storage, builds one combined protocol router, retains separate IdP/Management/Storage database files, starts Storage/background refresh only after HTTP readiness, and closes the endpoint once in shutdown. Existing endpoint persistence/admission tests are recorded above; live unified acceptance remains open.
- [ ] Separate construction from serving and accept explicit host listener/address/TLS-client configuration where not yet supported.
- [ ] Test one listener, prefixes exactly once, preserved endpoint identity across restart, occupied-port failure, shared endpoint admission behavior, and shutdown exactly once.

### 7. Complete desktop and join roles

- [ ] Replace shared `lidp.redb`/legacy composition with independent service runtimes and data roots.
- [ ] Replace stale setup HTTP calls with restricted owner-local commands and a resumable provisioning coordinator.
- [ ] Implement fresh unified, Storage-only, and IdP-replica setup/readiness transitions. Replica enrollment must use trusted approved signer flow.
- [ ] Persist HTTPS port; use stable keyring names and explicit CA trust; protect TLS private-key files. Reject occupied ports and secure-storage/trust failures without unsafe fallback.
- [ ] Update frontend URLs, probes, setup status, residency/completion, and identity screens with the runtime/API cutover. Identity administration calls authorized IdP APIs, never Management facades.
- [ ] Test restart, partial setup, reset, port conflict, secure-storage failure, and readiness transitions in desktop.

### 8. Complete clients and deployment

- [ ] Regenerate API specifications/clients from current endpoints with existing generators. Do not hand-edit generated files or run destructive generation against missing endpoints.
- [ ] Update configuration and operations for four service relationships, authority/replica roles, stable issuer, verifiers, permissions, secret rotation, and current-format backup recovery.
- [ ] Check disk capacity before Docker planner/build checks. Do not delete caches/data or prune Docker without review. Build all service binaries/images with the required workspace-parent context; verify persistence, TLS, and unattended secure storage.
- [ ] Search sources, configs, specs, and generated clients for obsolete routes, credentials, prefixes, direct server dependency edges, and accidental shared state.

### 9. Run live acceptance

- [ ] Add `justfile` harness commands using isolated temporary engines, ephemeral listeners, real HTTP/Iroh, and no mocked authorization or shared repositories.
- [ ] Run relevant scenarios in standalone and unified topologies: provisioning, user/client grants, RBAC, selection/deselection, CRUD/socket namespace isolation, database/KV/filesystem sync, tombstones/restart, restrictions, revocation/outage, and shutdown.
- [ ] Exercise Storage-only and IdP-replica joins, privileged enrollment, independent signers, canonical issuer/JWKS, 30-second freshness, single-use grant authority, and fail-closed authority loss.
- [ ] Prove forged descriptors/headers and service tokens cannot impersonate users, approve devices, or bypass owner/permission checks.
- [ ] Assert exactly one unified endpoint/key/router, both protocol handlers, preserved endpoint ID after restart, and one shutdown. Assert standalone endpoint ownership remains independent.
- [ ] Resolve focused blockers and record exact commands/results. No acceptance claim without live evidence.

### 10. Final validation only

- [ ] After implementation and live acceptance are complete, run the final commands below. Do not run feature-powerset or CRAP checks per step or phase.

## Execution and validation rules

Preserve all dirty work and `Cargo.lock`. Do not overwrite user changes, remove caches/data, or prune Docker without review. Keep Rust `lib.rs` and `mod.rs` thin. Prefer existing dependencies and protocols. No migrations or application-level DB locks. Breaking changes and broken intermediate states are allowed; continue dependent implementation rather than requiring each phase to pass independently.

During implementation, run focused tests/checks for the changed behavior and `just boundary-check` when server boundaries change. Record exact results and blockers. Do not claim tests passed unless they were run. Save formatting, workspace Clippy, feature-powerset, and CRAP for the final gate.

Run from `of/` only after implementation and acceptance work is complete:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo hack test --feature-powerset --workspace --all-targets
just crap
```

Final-check failures must be reported accurately. Fix failures introduced by this work; report unrelated/pre-existing failures separately.

## Deliberately out of scope

Backward compatibility, migrations, export/import cutover, automatic authority promotion, Management replication, concurrent replica identity administration, replica authorization-code/refresh redemption or broader user-token issuance, shared private signing keys, new fragmentation protocols, in-process service adapters, authorization-decision caches, synchronized cross-service control-plane projections, and offline authoritative authorization.
