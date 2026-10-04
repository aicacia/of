# Independent servers and unified hosting

## Goal and status

Ship independently deployable IdP, Management, and Storage services, with `unified-server` for single-node hosting. Unified and separate deployments use the same authenticated owner-service HTTP APIs.

Implementation is incomplete. The blocker interview settled the architecture below; final confirmation is pending before implementation resumes. See [the architecture decision](adr/0002-service-authority-and-replica-boundaries.md) and [domain terms](../GLOSSARY.md).

## Required boundaries

| Component            | Owns                                                                                                                   | Calls                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| IdP                  | Users, canonical applications, OAuth clients/grants/consents, approved signer registry, device enrollment and approval | Management permission API for identity administration only                 |
| Management           | Roles, permissions, assignments, restrictions, selections, replication policy                                          | IdP validation/device APIs; Storage reads for user selection               |
| Storage              | Resource metadata/content, database/KV/filesystem runtimes, sockets, replication                                       | IdP validation/device APIs; Management selection/admission APIs            |
| Unified/desktop host | Composition, listener, provisioning coordination, endpoint, admission refresh, lifecycle                               | Owner-local first-install operations and normal authenticated service APIs |

- No server crate depends on another server crate. Composition hosts may depend on multiple servers.
- Separate service engines/data roots, even in unified mode. Hosts must not access service repositories to implement provisioning or authorization.
- Management never proxies identity administration. Users call IdP directly; IdP checks Management RBAC.
- Management is one authoritative policy domain per installation. Joining nodes do not create independent local RBAC domains. Management replication is outside scope.
- Application-scoped permissions govern client operations within an application. Installation-scoped permissions govern application creation, installation-wide identity administration, and infrastructure service-client lifecycle.
- IdP verifies the actor locally and submits the verified subject, exact action, and target as permission-request data. Management authenticates that request with an ordinary IdP service bearer token. No actor headers or forwarded user tokens.
- Permission evaluation cannot call back into IdP administration. Ordinary OAuth issuance/introspection does not require Management or Storage. Identity mutations fail closed on Management failure.
- User and service tokens use the same authoritative bearer-validation path. Check principal type, issuer, audience, token use, time, active signer, principal state, and exact permissions. A valid user token alone is not administration authority.
- No `/internal/*` routes, custom service-auth headers, shared-secret resource guards, alternate token issuers, authorization caches, or unified bypasses.

## Endpoint and HTTP ownership

**Unified mode MUST have exactly one persisted Iroh key, one endpoint, and one protocol router per host.** Register IdP bootstrap and Storage DATA handlers on that router. IdP and Storage use the same injected server and never bind, persist, refresh admission for, or close another endpoint. Sharing a key between two bound endpoints is not sufficient.

Standalone IdP and Storage each own their endpoint/key/router/shutdown. Management does not need an Iroh endpoint.

The unified host mounts `/idp`, `/management`, and `/storage` exactly once. Standalone prefixes remain configurable. Keep public issuer/audiences separate from service transport URLs; join paths without dropping prefixes. Loopback requests remain authenticated. Require TLS outside verified loopback.

Desktop has one HTTPS listener, not an HTTPS proxy plus a second HTTP listener. Separate runtime construction/lifecycle from serving. The desktop host supplies transport configuration, serves the router, starts background work after readiness, and shuts down all tasks and the endpoint once.

Desktop persists its HTTPS port. An occupied port produces an actionable error, not a new issuer. Stable installation-scoped keyring namespaces must not depend on listener URLs. HTTP clients explicitly trust the local CA with certificate verification enabled. Protect TLS private-key files with platform-appropriate access controls. Secure-storage failure has no plaintext fallback.

Shared transport admission is not resource authorization. Storage failures must stop replication without erasing independently authorized IdP bootstrap admission.

## Provisioning and installation roles

First installation uses local operator commands or restricted Tauri commands. Each service exposes owner-local operations; the host coordinates results and canonical IDs. Remove desktop `/setup/new` for first installation. Do not replace it with an unauthenticated HTTP route.

Grant the Initial Administrator explicit installation permissions, including RBAC administration and infrastructure service-client lifecycle. Do not grant a wildcard that includes unknown future capabilities.

Provision distinct, narrowly scoped clients for each service relationship:

| Caller → receiver    | Capability                                                |
| -------------------- | --------------------------------------------------------- |
| Management → IdP     | Token introspection and approved endpoint identity lookup |
| Storage → IdP        | Token introspection and approved endpoint-ID listing      |
| Storage → Management | Selection listing and replication admission               |
| IdP → Management     | Permission evaluation only                                |

Secrets are returned only through authorized provisioning, then retained in consuming services' secure storage. IdP stores one-way client-secret verifiers, not raw secrets. No shared/default secrets. Later create/update/revoke operations require the normal RBAC-authorized owner API.

Partial installation is not ready. Retry with stable installation/principal IDs and verify completed steps without duplicate users, clients, or keys. Persist secrets securely before reporting success.

Require a clean installation. No migrations, old-schema loading, compatibility wrappers, or export/import cutover. Detect existing installation state and require explicit reset; never silently delete or overwrite it. Reset affects local state only, with remote revocation attempted through authorized APIs.

Explicit deployment roles:

- **Fresh unified installation:** hosts the designated IdP authority, Management authority, and Storage, with one shared endpoint.
- **Storage-only join:** uses remote IdP/Management APIs; no IdP database copy or local OAuth authority.
- **IdP-replica join:** receives only defined IdP state, uses the installation's canonical issuer and existing Management authority, and has its own approved signer with local private keys.

Full IdP bootstrap requires the correct audience and an installation-scoped replica-enrollment permission, separate from ordinary Storage-device enrollment. Device approval alone does not grant access to IdP state or signing authority. Readiness requires completed synchronization, approved signer provisioning, and approval of the joining endpoint itself.

## IdP replica and OAuth rules

- Independent replica signers; no copied private signing keys. Separate signer identity from token subject. Verification uses public keys, not private-key availability. Publish consistent approved-signer JWKS.
- One designated IdP authority performs identity administration and signer enrollment/revocation. Clients call it directly. No concurrent replica administration or token forwarding.
- That authority also creates/redeems authorization codes and rotates refresh tokens. Consumption must be atomic. Verify refresh-token signature and all relevant claims; persist rotation/revocation state. Replicas must not redeem synchronized copies or fall back when the authority is unavailable.
- Replicas may validate tokens and issue client-credentials tokens while security state is fresh. Broader replica user-token issuance is outside this plan.
- Replica authoritative security-state age is at most **30 seconds**, measured from successful authoritative synchronization with local monotonic time. Restart requires fresh synchronization. Expiry stops issuance and validation until refresh succeeds. Test revoked signer, principal, client, and device propagation; repeated stale responses must not renew freshness.
- IdP replication includes only defined IdP records and client-secret verification data. Exclude Management/Storage records, raw client secrets, and replica private signing keys. Do not use whole mixed-engine copying as authorization.
- No automatic authority promotion. Fail closed and document operator recovery from a valid current-format backup. No stale-replica fallback.
- Remove unauthenticated arbitrary-message `/device/sign`. Required signatures use authorized purpose-specific operations that construct their payloads, or restricted local Tauri commands.

## Bounded Storage synchronization

Management returns policy decisions, not proof of an Iroh connection. Storage derives its local endpoint from the injected server and the peer from `Connection::remote_id()`. Both peers independently check exact owner/application/kind/resource selection and admission before data transfer. Never trust handshake endpoint or owner claims.

| Boundary                        | Initial limit |
| ------------------------------- | ------------: |
| SQL/KV encoded frame            |         1 MiB |
| Filesystem content chunk        |         1 MiB |
| Marker/handshake deadline       |     5 seconds |
| Complete policy-check deadline  |    10 seconds |
| Authorized batch/chunk deadline |    30 seconds |

Check policy before each bounded operation, on both peers. An already authorized operation may finish within its bound; denial/unavailability stops the stream and new work. Bound pending data, queues, and apply work, not just frame size. Cancellation must stop child tasks and queued work. Idle connections do not retain authorization for their next operation.

Oversized records/transactions fail clearly and retain local data. No truncation, skipping, or new fragmentation protocol. Completed valid batches may remain committed after later failure. Preserve atomic transaction invariants and resume through convergence rules; do not split transactions unsafely.

Narrowly scoped changes to `ofdb` and `offs` are approved for these boundaries. Reuse existing sync engines/protocols. Current SQL accumulates session data and filesystem queues do not recheck every chunk; wrapper timeouts alone are insufficient.

## Existing implementation and evidence

These are prior implementation results, not validation of the revised design:

- [x] Normal client-credentials issuance and bearer-protected introspection exist; `client_secret_post` registration matching is checked.
- [x] Bounded IdP/Management HTTP clients, approved endpoint lookup/list APIs, and normal selection/admission APIs exist.
- [x] Removed legacy internal credentials/routes and Management identity facades; added direct-server dependency checking.
- [x] Management uses its own schema and authoritative IdP validation, not local OAuth repositories.
- [x] Storage owns CRUD/socket routes, storage runtimes, and moved DATA/database/filesystem handlers.
- [x] Service runtime builders and unified prefixed composition exist. One endpoint is injected into IdP and Storage; the root executable delegates to unified hosting.
- [x] Owner-local `provision-service-client` CLI exists, with exclusive Unix 0600 output and partial-failure cleanup tests. It is not yet the complete first-install coordinator.
- [x] Unified config/example, run recipes, and preliminary Docker packaging exist. Management generation URL now targets `/management/openapi.json`.

Previously recorded passes: `cargo test -p unified-server` (5 tests), `cargo test -p storage-server --lib` (35 tests), focused CLI/root checks, `just boundary-check`, and `git diff --check`. Unified tests cover paths, discovery/OpenAPI, one live authenticated Management read, endpoint persistence, and new-connection rejection after peer removal. Many protocol tests use HTTP stubs; they do not prove live replication acceptance.

Known failures/gaps: IdP bootstrap library test stack overflow; Docker planner timeouts at 120/300 seconds, followed by disk exhaustion; desktop shared-engine/legacy-prefix composition; stale generated identity clients; incomplete live CRUD/socket, replication, revocation/outage, provisioning, and shutdown acceptance. Disk capacity must be checked before builds; do not delete caches or prune Docker without review. No final feature-powerset or CRAP run has occurred.

## Actionable remaining work

Work in this order. Existing pieces may be reused, but check them against the revised contracts. Checkboxes below remain open until implemented and tested.

### 1. Close unsafe OAuth and signing paths

- [x] Remove arbitrary-message `/device/sign`. Desktop self-revocation now uses a purpose-specific payload/signing method; `DeviceIdentity::sign(message)` is gone. The public route and OpenAPI registration are removed.
- [x] Client registration read/create/update/delete handlers now require user bearer authentication where missing and fail closed with `access_denied` until RBAC exists. A focused helper test passes. Route-level tests for every operation remain necessary.
- [x] Authorization-code consumption now uses one conditional update (`consumed_at IS NULL`) and requires a returned row. A simultaneous two-consumer test passes with exactly one winner on one local engine. This does not implement designated-authority routing or guarantee cross-replica atomicity.
- [ ] Complete route-level security coverage for denied client operations and owner-authorized behavior after RBAC is implemented. The live IdP-listener test sends unauthenticated GET/create/update/delete requests and checks `/device/sign` is absent. It now also covers authorization-code refresh issuance, forged refresh rejection, wrong client/secret rejection, rotation, reuse rejection, authenticated normal `/oauth2/revoke`, repeat revocation, and revoked-token rejection. Authenticated client-administration authorization-denial assertions still depend on the RBAC implementation.
- [x] Enforce the configured designated-authority role for local persisted refresh rotation/revocation and reject code/refresh grants on replicas. Shared-service role checks are implemented and tested; installation-wide authority uniqueness, replica enrollment, independent signers, and freshness remain open under step 2.
  - [x] Persist refresh issuance and local atomic rotation/revocation. The new repository uses the existing initial `oauth2_refresh_tokens` schema, stores SHA-256 token hashes and grant constraints, and assigns database row IDs locally. Refresh JWTs have random `jti` values so same-second issuance and rotation produce distinct tokens. Signature/key, issuer, audience/client, type/use, principal/subject, and time checks precede consumption. Client authentication and scope narrowing also precede consumption. One database transaction conditionally consumes an unexpired, unrevoked, unused token bound to the client/user, requires exactly one returned row, and inserts the replacement; insert failure rolls back consumption. No migration, compatibility path, dependency, or application-level database lock was added.
  - [x] Test local lifecycle and the normal HTTP endpoint. Focused tests cover one concurrent redemption winner, persisted replacement redemption, same-second uniqueness, expired/revoked/wrong binding rejection, forged and invalid signed claims without consumption, unpersisted-token rejection, scope narrowing, reuse rejection, insert-failure rollback, and rotation/revocation across native database reopen. All OAuth constructor sites and the native service alias now include the refresh repository. Standalone and desktop/unified wiring retain their existing endpoints; no cross-server repository access was added.
- [x] Replace raw client secrets with verifiers in repositories and provisioning/token paths. Reuse the initial schema's `client_secret_hash` column and existing Argon2id utility; no migration was added. The client model stores only a verifier, serialization and registration reads omit it, creation/rotation return only the newly supplied secret, and normal token authentication verifies the supplied secret. Client signing-key setup no longer depends on the OAuth secret.

Focused validation: `cargo test -p idp-service --features replica --lib concurrent_consumers_have_one_winner` passed (1 test); `cargo test -p idp-server --lib identity_administration_fails_closed_without_rbac` passed (1 test); `cargo test -p idp-service --lib oauth2::jwt::tests::verifies_signature_and_binds_jwt_header_to_key` passed (1 test); `cargo test -p idp-server --lib live_idp_listener_issues_and_introspects_service_tokens` passed (1 test), including the new client-registration authentication and removed-sign-route assertions. The IdP test command timed out once during dependency compilation, then passed after compilation completed. The stale Management-listener portion was removed from the IdP test setup; `apps/app/src-tauri/src/app.rs` still has known pre-existing diagnostics from the unfinished Storage/runtime cutover. Client-verifier validation: `cargo test -p idp-service --features replica --lib replica::client_repo::tests` passed (2 tests), covering persistent verifier storage, non-disclosure, rotation, and updates without rotation. `cargo test -p idp-server --lib cli::provision_service_client::tests` passed (5 tests), including live rejection of a wrong secret and issuance with the correct secret. `cargo check -p bootstrap-service` passed. Latest observed disk capacity before these checks was 14 GB free. No files/caches were removed.

Refresh-lifecycle validation (2026-10-04; commands run from `of/`, with 60–180 second bounds):

- `cargo test --locked -p idp-service --features replica --lib refresh` passed: 7 tests.
- `cargo test --locked -p idp-server --lib live_idp_listener_issues_and_introspects_service_tokens` passed: 1 live listener test, including the refresh/revoke HTTP assertions above.
- `cargo check --locked -p idp-server -p idp-service --features idp-service/replica` passed.
- `cargo check --locked -p idp-service --no-default-features` passed, with existing unused-import warnings in `oauth2/authorization.rs` and `oauth2/scope.rs`. Its first run failed because service-side `Id::now_v7()` needs UUID's `std` feature; moving row-ID creation into the database repository resolved this without manifest or lockfile changes.
- `just boundary-check` passed: no direct server-to-server dependency edges.
- `cargo test --locked -p idp-service --features replica --lib replica::client_repo::tests` had 1 pass and 1 failure. `client_secrets_are_disclosed_only_on_creation_and_rotation` failed at its existing no-op client update with `invalid input: Error: Incremental payload has no change`. A bounded isolated rerun of `cargo test --locked -p idp-service --features replica --lib client_secrets_are_disclosed_only_on_creation_and_rotation` failed with the same error. Only this test's refresh-repository constructor/import wiring changed in this subtask; the client-update path was not changed.
- Initial new-test compilation errors (test private-key generic and unavailable server-test `chrono` import) were corrected using existing types and `SystemTime`; the listed passing tests were rerun afterward.

Limits: atomicity is proven on one local engine, not across replicas. Revocation is per token; no token-family cascade or already-issued access-token revocation is added. The HTTP path reuses existing Basic client authentication; broader token-endpoint authentication-method work is not part of this subtask. Desktop has only constructor wiring updated and was not built because its pre-existing Storage/runtime cutover is unfinished. Current dirty user changes and `Cargo.lock` were preserved. No final formatting, Clippy, feature-powerset, or CRAP command was run.

### 2. Implement independent signers and replica authority

- [x] Define the local authority/replica role contract and enforce OAuth role restrictions in the shared service. See the focused results below. This is not replica readiness or an installation-wide election/uniqueness mechanism.
- [ ] Complete signer/public-key records, principal binding, canonical issuer, designated-authority enrollment/uniqueness, and replica freshness contracts in existing model crates.
  - [x] Persist public verification material on existing entity-bound keys, separately from local private stores. This is not an approved replica-signer registry.
  - [x] Add separate public signer metadata and subject-root binding contracts; deny replica issuance until trusted enrollment/local signing/freshness integration exists. These contracts are not persisted approval or runtime independent signing.
- [ ] Rewrite issuance/verification/JWKS to use approved local signers and public verification material; preserve user/service principal checks and revocation.
  - [x] Read persisted public material for verification and JWKS without private-key access; retain active-root and live-principal eligibility. Signing still requires matching local private material.
  - [ ] Replace entity-root signing with a separate approved replica-signer identity and bind issuance/validation to that identity without weakening subject checks.
- [ ] Define an explicit IdP replication record scope and ongoing authoritative synchronization. Exclude single-use grant redemption from replica authority.
- [ ] Implement authorized replica enrollment, signer registration/rotation/revocation, freshness expiry, restart behavior, and readiness.
- [ ] Test wrong-role enrollment, missing local signer, inconsistent JWKS, stale/replayed synchronization, partitions, and revoked replica tokens.

Authority/replica role progress (2026-10-04; **security risk: high**):

- `idp_model::contract::IdpRole` defines `authority` and `replica`. `OAuth2Config.role` flows through the existing standalone runtime, unified host's nested IdP config, and desktop constructor. The current fresh-install/default configuration designates `authority`; a replica must explicitly set `[oauth2] role = "replica"` (unified: `[idp.oauth2]`). Unknown role values fail deserialization. This local trusted configuration is not signer approval, device approval, or replica enrollment. Join-role setup remains unfinished and must select replica explicitly before serving.
- `OAuth2Service` captures the role at construction. Changing public OAuth settings cannot promote a running replica. Shared-service checks return `access_denied` before repository work for authorization-code creation, approval/consent writes, authorization-code/password/refresh/exchange grants, refresh revocation, device-code creation, and the common user-token issuance helper. Existing application/client/user/consent mutation methods also require authority. Read-only consent checks and token validation remain available. No forwarding, availability fallback, automatic promotion, database lock, migration, dependency, or endpoint change was added.
- Tests call the service directly, not only routes. Replica approval leaves consent absent; rejected code redemption and refresh rotation/revocation leave credentials redeemable by authority. Refresh rows are unchanged after all rejected user grants. Another test proves the role permits client-credentials issuance without a refresh token and public-key signature verification. Both tests deliberately share one engine/key store to isolate role enforcement; they do not prove independent replica signers, authoritative synchronization, or 30-second freshness.
- Existing endpoint ownership is unchanged: standalone owns its endpoint; unified injects one server into IdP and Storage. No new endpoint is bound. Desktop constructor receives the role through its existing config, but desktop was not built because its known runtime cutover remains unfinished.

Focused commands from `of/` (60–180 second bounds):

- `cargo test --locked -p idp-service --features replica --lib replica_role`: initial run had 1 pass and 1 failure because the new test supplied an empty required PKCE verifier. The fixture now supplies a valid verifier; both tests passed in the following refresh run.
- `cargo test --locked -p idp-service --features replica --lib refresh`: passed, 9 tests, including both role tests and existing refresh lifecycle/atomicity tests.
- `cargo test --locked -p idp-service --features replica --lib idp_role_config`: passed, 1 configuration test.
- `cargo check --locked -p idp-server -p unified-server -p idp-service --features idp-service/replica`: passed.
- `cargo test --locked -p idp-server --lib live_idp_listener_issues_and_introspects_service_tokens`: passed, 1 authority listener test.
- `cargo check --locked -p idp-service --no-default-features`: passed with existing unused imports in `oauth2/authorization.rs` and `oauth2/scope.rs`.
- `git diff --check`: passed. `git diff -- Cargo.lock`: empty. Initial disk capacity was 8.5 GB free; no caches/files were removed. Dirty user work was retained. No final fmt, Clippy, feature-powerset, or CRAP command was run.

At the role-contract checkpoint, independent local signers/public verification, privileged enrollment, scoped replication, restart readiness, and freshness expiry remained open. The following slice supplies public-only verification, not independent signer identity or issuance. Role designation still does not prove that exactly one member is authority. Replica HTTP denial coverage and live replica topology acceptance remain open. Owner-local provisioning and other services are not converted into RBAC-authorized operations by these OAuth service guards.

Public-verification foundation (2026-10-04; **security risk: high**, focused partial slice):

- Traced KeyService, the native key/client/user repositories, bootstrap and CLI provisioning, local signing, OAuth refresh/exchange/revocation, and shared bearer principal validation. The current signer is still the subject's User/Client active root. No replica approval or separate signer identity is inferred from public-key existence.
- `Key.public_jwk` stores typed public-only material in the existing initial `keys` schema's new nullable `public_jwk` text column. Metadata without material remains unusable for verification. `KeyRepo::set_public_jwk` checks the key ID and initializes the column once with a conditional database update; conflicts remain fail-closed through existing repository guards. No migration or compatibility reader was added. Clean installation is required.
- KeyService creation/rotation now persists public material after local derivation. Client creation, CLI service-client provisioning, and new bootstrap keys already use that path. Bootstrap retry can finish an incomplete key's public write from its local derived key and rejects a different stored public point. Private/root/derived secrets remain local; no secret synchronization or private-key transfer was added.
- `find_public_jwk` resolves the existing active root and live User/Client principal, then checks persisted `kid`, signature use, existing algorithm/curve conventions, and EC public-point validity. JWKS uses that same public-only eligibility path and excludes missing material, non-root/superseded/inactive keys, and unavailable principals. Repository lookup errors fail verification; JWKS may omit an ineligible key. Shared bearer issuer/use/time/type/subject checks are unchanged.
- Signing still requires a local private key and now rejects a mismatch with persisted public material. Private-to-public JWK conversion now preserves key use instead of incorrectly marking signature keys as encryption keys. Client repository reads now honor `revoked_at`; the new test exposed that the existing schema field had been ignored. This common read filter protects verification, JWKS, and token/client lookups.
- Five focused tests prove user/client signatures and consistent JWKS across separate databases with distinct empty local secret stores; verification/JWKS after local secret removal; missing signing capability; write-once/public-ID contracts; native public-record persistence after reopen without a private store; rejection of revoked/expired/unbound/non-root/superseded keys, invalid use/algorithm/curve/point/ID, revoked clients, mismatched signature points and local signing secrets; and unchanged refresh-subject binding. Test record transfer is explicit fixture copying of identity tables, not implemented replication or enrollment. No private keys are copied between members.

Focused commands from `of/`, bounded to 60–180 seconds:

- `cargo test --locked -p idp-service --features replica --lib public_keys`: passed, 4 tests before the native-reopen test was added. The later refresh run includes all 5 public-key tests.
- `cargo test --locked -p idp-service --features replica --lib refresh`: passed, 14 tests, including all public-key tests and existing role/refresh lifecycle tests.
- `cargo test --locked -p idp-service --features replica --lib replica::key_repo::tests`: passed, 1 test.
- `cargo test --locked -p idp-service --features replica --lib replica::client_repo::tests`: passed, 2 tests. The earlier documented no-op-update failure did not reproduce in this run.
- `cargo test --locked -p idp-server --lib live_idp_listener_issues_and_introspects_service_tokens`: passed, 1 live listener test.
- `cargo test --locked -p idp-server --lib cli::provision_service_client::tests`: passed, 5 tests, including scoped provisioning, private-store failure cleanup, and the live listener test.
- `cargo check --locked -p idp-server -p unified-server -p bootstrap-service -p idp-service --features idp-service/replica`: passed.
- `cargo check --locked -p idp-service --no-default-features`: passed with existing unused-import warnings in `oauth2/authorization.rs` and `oauth2/scope.rs`.
- `just boundary-check` and `git diff --check`: passed. `git diff -- Cargo.lock`: empty. Disk checks showed 8.1 GB free initially and 7.8 GB at the latest check. Existing dirty user changes were retained; no dependencies, manifests, application-level database locks, endpoints, or lib/mod implementation changes were added. No final fmt, Clippy, feature-powerset, or CRAP command was run.
- Initial test runs caught and corrected the new schema/row column order, existing private-to-public key-use conversion, a missing test trait import, and ignored client revocation. One intermediate compile ran before the new test file existed; subsequent tests passed.

Remaining security gaps: there is no independent approved replica-signer record, privileged enrollment/registration API, separate signer-to-principal issuance model, authoritative replication scope, 30-second freshness enforcement, or replica restart/readiness proof. Public material alone does not approve an IdP member. An empty local store verifies but cannot issue tokens; the old shared-store role test still does not prove independent replica issuance. These gaps require the next model/issuance slice and are not bypassed here. Desktop remains unbuilt due to its known unfinished runtime cutover. This slice is not step-2 completion or live replica topology acceptance.

Signer-contract/readiness foundation (2026-10-04; **security risk: high**, partial slice):

- Owned only `crates/idp-model/src/contract/idp_signer.rs`, its `contract/mod.rs` declarations/re-exports, `crates/idp-service/src/oauth2/service.rs`, `oauth2/refresh_tests.rs`, and this plan. Existing dirty work and `Cargo.lock` were retained. No schema changes, migrations, compatibility code, dependencies, database locks, secret transfer, or endpoint changes were added. No final fmt, Clippy, hack, or CRAP command was run.
- Traced `KeyService` entity-scoped local secret namespaces and root creation, shared `find_principal`/active-root resolution, router `middleware/authorization.rs`, CLI service-client provisioning, and bootstrap `ensure_active_key`. Current bearer validation still resolves a User/Client from `kid`, verifies with its persisted public root, and checks the claimed subject/type. Bootstrap and CLI still provision entity roots, not IdP-member approval. Those paths must change together before independent signer tokens can be accepted; treating their JWKs as member approval would be unsafe.
- `IdpSignerRecord` is a public-only enrollment **data contract**, with independent member/key IDs, exact installation issuer, public JWK, explicit approval timestamp, revocation, and expiry. Its metadata predicate rejects missing/future approval, wrong member/key/JWK ID, wrong issuer, trailing-slash/whitespace issuer forms, revoked/expired records, and unsupported use/algorithm/curve. It does **not** authenticate approval provenance, validate EC points, or grant readiness. Only a future designated-authority owner operation may persist approval; arbitrary serialized records, JWKs, and configuration are not trusted. No runtime accepts this contract as approval.
- `TokenPrincipalBinding` keeps subject entity/type/root ID separate from member/signer ID. The shared active-root check now uses it against the repository's selected active root, including root/revocation/expiry checks. Live User/Client resolution remains required and unchanged. This is subject-root contract integration, not signer-based issuance/verification integration. Tests explicitly use different signer and subject IDs and reject a wrong subject owner/type and revoked root. Existing public-key tests still reject revoked clients, unavailable principals, inactive/superseded keys, and missing/mismatched local signing material. A dedicated revoked-User account test remains open; the current core User model has no account revocation field (credential revocation is not account revocation).
- The local public-material comparison rejects absent/mismatched/unsupported private JWKs without accepting symmetric material or panicking. This is only public-coordinate comparison, not proof of possession: future runtime issuance must derive and validate the public point from its local secret and verify authority-sourced approval. Test coordinates are deliberately non-cryptographic; these tests prove metadata contracts only.
- Replica client-credentials issuance now returns `access_denied` in the common issuance helper. This supersedes the earlier shared-secret-store role test and the historical statement that role alone permits machine issuance. The replacement test proves that even shared subject private keys do not establish replica readiness, while authority machine issuance and replica public verification still work. Code/refresh lifecycle and other user grants remain authority-only. There is no enable switch or fallback that exposes replica issuance before approval/freshness integration.

Exact focused commands from `of/`:

- `df -h .; git --no-optional-locks status --short` (10-second bound): initial free space 7.9 GB; dirty work recorded before edits.
- `cargo test --locked -p idp-model --lib signer_contract` (120-second bound): timed out during dependency compilation. Bounded 180-second rerun found new unconditional `alloc` imports incompatible with the default `std` build; corrected with existing conditional import conventions. Subsequent runs passed, 2 tests.
- `cargo test --locked -p idp-service --features replica --lib refresh` (within 180-second command bounds): passed twice, 14 tests each, including readiness denial, public-only verification/local-key failure, subject binding, role denial, and refresh lifecycle tests.
- Final focused command: `cargo test --locked -p idp-model --lib signer_contract && cargo test --locked -p idp-service --features replica --lib refresh && cargo check --locked -p idp-service --no-default-features && git --no-pager diff --check && git --no-pager diff -- Cargo.lock; df -h .` (180-second bound): passed. Model tests: 2; service tests: 14. Check retains existing unused-import warnings in `oauth2/authorization.rs` and `oauth2/scope.rs`. Diff check passed; lockfile diff empty; disk free 6.1 GB. No files/caches were removed. Server/desktop/live HTTP checks were not run in this slice.

Residual gaps: approved signer persistence in the initial schema and its repository, privileged owner-local provisioning/enrollment, approval provenance/installation membership and authority uniqueness, independent local signer loading, canonical issuer runtime validation, signature/public-point validation for member records, subject resolution from verified claims rather than signer `kid`, issuance/verification/JWKS cutover, revoked member/principal integration tests, scoped authoritative replication, 30-second freshness and restart readiness. Replica validation still has no freshness enforcement; it is not proof of safe replica operation. Authority still uses existing entity-root signing. Do not enable replica issuance until the entire approval/local-secret/freshness path fails closed. Step 2 and independent-signer live topology acceptance remain incomplete.

### 3. Implement normal RBAC permission evaluation

- [ ] Define typed subject/action/target requests, application/installation permission scope, and audit identity.
- [ ] Add Management's ordinary bearer-protected permission capability and bounded IdP client for it. Provision the fourth distinct service relationship.
- [ ] Enforce permissions at IdP application/client/user/consent/key administration and infrastructure-client lifecycle; create missing owner APIs where required.
- [ ] Test permitted callers, cross-application denial, installation escalation, user/service separation, upstream failure, and absence of recursive request chains.

### 4. Split first-install provisioning

- [ ] Replace mixed-repository bootstrap with owner-local IdP and Management operations that return canonical IDs/results.
- [ ] Add local operator coordination and capability-restricted Tauri setup commands. Keep first-install authority separate from running-service bearer APIs.
- [ ] Seed explicit initial grants and four distinct service relationships; store secrets securely before completion.
- [ ] Test failure after each step, safe retry/restart, duplicate prevention, explicit reset, and legacy-state rejection.

### 5. Enforce bounded synchronization

- [ ] Update `ofdb` batching/apply controls and `offs` metadata/content queues to enforce size and memory bounds while preserving atomicity and revisions.
- [ ] Apply deadlines and policy checks to both incoming/outgoing paths, including queued filesystem responses and database/KV apply boundaries.
- [ ] Track/cancel all sessions and child tasks. Prevent one long session from blocking unrelated peers/resources or shutdown.
- [ ] Test large records/files, atomic transactions, partial progress, tombstones, reconnect, denial/outage between batches, oversized failure, and deadline cleanup.

### 6. Separate composition from serving

- [ ] Refactor unified construction to accept host listener/address/TLS-client configuration and expose explicit readiness/start/shutdown lifecycle.
- [ ] Preserve one endpoint/key/router and distinct state. Start refresh/sync only after serving is ready; do not require circular HTTP provisioning.
- [ ] Test one listener, no duplicated prefixes, bind failures, shared bootstrap/replication admission, and shutdown exactly once.

### 7. Complete desktop and join roles

- [ ] Replace shared `lidp.redb` composition with separated runtimes; use persisted HTTPS port, stable keyring namespaces, and explicit CA trust.
- [ ] Implement fresh-install, Storage-only, and IdP-replica setup/readiness transitions without unauthenticated setup HTTP.
- [ ] Fix reset paths and secure TLS-key access. Reject occupied ports and secure-storage/trust failures without unsafe fallback.
- [ ] Update frontend URLs/probes and identity screens together with runtime cutover. Identity administration uses authorized IdP APIs, never restored Management facades.

### 8. Complete clients and deployment

- [ ] Regenerate specs/clients from available current endpoints using existing generators. Do not manually edit generated code or run destructive generation against missing endpoints.
- [ ] Update configs/operations for four service relationships, authority/replica roles, stable issuer, verifier storage, permissions, rotation, and current-format backup recovery.
- [ ] Check capacity, then validate Docker planner and all four binaries/images with the required workspace-parent context. Verify TLS, persistence, and unattended secure storage.
- [ ] Audit source/config/specs/generated clients for obsolete routes, credentials, prefixes, and server dependency edges.

### 9. Run live acceptance

- [ ] Add harness commands to `justfile`: isolated temporary engines, ephemeral test listeners, real HTTP/Iroh, no mocked authorization or shared repositories.
- [ ] Run the same applicable scenarios in separate and unified topologies: provisioning, user/client grants, RBAC, selection/deselection, CRUD/socket namespace isolation, database/KV/filesystem replication, tombstones/restart, restrictions, revocation/outages, and shutdown.
- [ ] Exercise Storage-only and IdP-replica joins, privileged enrollment, independent signers, canonical issuer/JWKS, 30-second freshness, single-use grant authority, and fail-closed authority loss.
- [ ] Prove spoofed descriptors/headers and service tokens cannot impersonate users, approve devices, or bypass owner/permission checks.
- [ ] Assert exactly one unified endpoint/key/router, both protocol handlers, preserved endpoint ID after restart, and one shutdown. Standalone endpoints remain independently owned.
- [ ] Resolve all deferred focused checks and record exact commands/results. No acceptance claim without live evidence.

### 10. Final validation only

- [ ] After all implementation and acceptance work is complete, run formatting, Clippy, feature-powerset tests, and CRAP. Fix introduced failures and report pre-existing failures separately.

## Execution and validation rules

Breaking changes and temporarily broken intermediate states are allowed. Preserve user work and `Cargo.lock`; delete obsolete implementations, not user data. Keep implementation out of `lib.rs`/`mod.rs`, reuse existing libraries, and assess security/state changes as high risk.

During implementation, use targeted tests/checks and `just boundary-check`. Record failures and continue dependent work; do not require independently passing phases. Do not add an application-level database lock.

Run from `of/`, **only after every implementation and acceptance task is done**:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo hack test --feature-powerset --workspace --all-targets
just crap
```

No feature-powerset or CRAP checks per phase, step, or baseline. Shared-library changes need their focused tests during implementation and their applicable final validation after completion.

## Out of scope

Backward compatibility/migrations/export-import cutover; automatic authority promotion; Management replication; concurrent replica identity administration; replica authorization-code/refresh redemption or broader user-token issuance; shared private signing keys; new fragmentation protocols; in-process service adapters; authorization-decision caches; synchronized cross-service control-plane projections; offline authoritative authorization.
