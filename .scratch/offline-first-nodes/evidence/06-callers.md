# Ticket 06 caller / prefix / probe evidence — 2026-10-11

Worktree: `of/.worktrees/ticket06-callers`; branch: `offline-first-ticket06-callers`; base: `2e67ed5`. Scope: app callers, native setup source tracing, shared headless checks, read-only generated/contract/artifact audit. Ticket 04 remains incomplete. Ticket 06 closure and endpoint/regeneration acceptance belong to the parent; this report does not promote either ticket.

Complexity: low, one listener-discovery predicate plus focused public-boundary tests. Risk: confusing an available setup listener with completed local trust, or confusing OAuth audience with transport prefix. Priority: preserve discovery of an empty Installation while making those boundaries explicit. No dependencies, authorization wrappers, role-word purge, new routes or access widening.

The initial-checkpoint sections below record commit `909c109`. Review subsequently identified the active password-manager finding as a ticket 06 closure blocker and expanded write scope; the follow-up section explicitly supersedes its original report-only disposition.

## Changes and exact public seams (initial checkpoint)

- `apps/app/src/lib/common/state/localhostBaseUrl.svelte.ts`: rename private `isLocalhostServerReady` to `isLocalhostListenerAvailable`; retain active `/idp/health` discovery and `/lidp/setup/status` fallback. Require the fallback's actual `{ stage: "installation" }` contract instead of accepting arbitrary HTTP 2xx. Neither response establishes durable local readiness or authorizes an actor. Existing native URL polling/deduplication stays intact.
- `localhostBaseUrl.test.ts`: test exported `loadLocalhostBaseUrl`, `ensureLocalhostBaseUrl`, `getLocalhostBaseUrlCached`; empty setup remains discoverable, unrelated successful setup bodies (`ready`, `device`, `{}`, `null`) are rejected, concurrent discovery is shared, web mode performs no native probe.
- `setupClient.test.ts`: test exported `getSetupStage` for installation/device/ready/unavailable and native failure propagation, with no HTTP calls. Existing session/reset tests preserved.
- `ownerClients.test.ts`: exercise actual checked-in generated clients through exported app APIs, not mocked client classes: native/web prefix behavior, `idpApi.userinfo`, direct `idpAdministration.listApplications`, Management `getDeviceRestriction`, distinct token-exchange resource, Authorization header and current actor on each request. A Management transport URL is rejected as a Management audience before token transmission.
- `apps/app/vitest.auth.config.ts`: include the two new tests in the existing auth suite; no replacement harness. Shared headless implementation is unchanged.

## Native listener versus persistent readiness: traced source

| Match                                                                                                                      | Classification / disposition                                                                                                                                                                                                                                                                                                           |
| -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/app/src-tauri/src/setup.rs` `router`/`status`                                                                        | Active restricted discovery: `/setup/status` always returns Installation. Preserve, not an obsolete HTTP setup mutation.                                                                                                                                                                                                               |
| `app.rs::init_setup_router`                                                                                                | Mounts this router once at `/lidp`, hence actual desktop URL `/lidp/setup/status`, not `/idp/setup/status`. Also merges local callback APIs.                                                                                                                                                                                           |
| `localhost_server.rs::verify_localhost_server`                                                                             | Already validates setup status JSON and exact Installation stage. The TypeScript fallback now follows this actual contract.                                                                                                                                                                                                            |
| `localhost_server.rs::localhost_server_base_url`                                                                           | Native base is `https://localhost:<port>`, with no service prefix or trailing slash. Do not add speculative prefix-normalization helpers.                                                                                                                                                                                              |
| `app.rs::LocalhostServerState`, `localhost_server_base_url_for`, `init_unified_localhost_server`, `restore_setup_listener` | `ready` here is listener availability. An empty Node and a restored setup listener can expose a URL. It is not a setup-completion claim.                                                                                                                                                                                               |
| `runtime.rs::run`                                                                                                          | Reserves the listener, starts persisted runtime only when `setup_ready` is true; otherwise starts the setup router. Failed persisted startup restores setup discovery without deleting completion.                                                                                                                                     |
| `app.rs::setup_ready`, `setup_completion`                                                                                  | Durable marker/manifest/Installation identity, symlink/integrity checks and pending reset decide persisted setup evidence. HTTP health cannot replace this.                                                                                                                                                                            |
| `app.rs::current_public_ready`, `start_composed_unified_runtime`, `get_setup_stage`, `local_setup_stage`                   | Checks current local trust/public contexts/independent signer and usable local URL separately from persisted completion. Native stage is Installation when not completed; unavailable when completed but contexts unusable; device until Device completion; ready only after both. Native source reviewed only, not compiled/run here. |
| `setupClient.svelte.ts::getSetupStage`, `(auth)/+layout.ts`, setup page loaders                                            | Stage is obtained through `get_setup_stage` IPC. Auth layout routes Installation/unavailable/device to recovery/setup before client discovery. It then requires current token/issuer and successful current `userinfo`; health/setup status does not bypass this. Preserve.                                                            |

## Prefix and owner trace

Generated runtimes concatenate `configuration.basePath + context.path`; operation paths are service-relative. Desktop caller configuration must supply the prefix, not generated operation code. These are distinct boundaries:

| Caller / match                                                               | Exact observed transport / audience                                                                                                                                                                                                                                                                                                                 | Disposition                                                                                                                                     |
| ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `idpClient.svelte.ts::ensureTauriIdpApiUrl`, generated `DefaultApi`          | Native host + `/idp`, then `/userinfo`, `/applications`, `/oauth2/token`. Actual tests observe `https://localhost:4100/idp/...`, not `/idp/idp/...`. IdP owner exchange resource is the IdP service base.                                                                                                                                           | Correct, retained.                                                                                                                              |
| `managementClient.svelte.ts::ensureTauriManagementApiUrl`, `readAccessToken` | Native host + `/management`, generated `/devices/{device_id}/restriction`; exchange is sent to `/idp/oauth2/token` with resource **`idp-management`**, never `/management`.                                                                                                                                                                         | Correct, retained; explicit transport-as-audience rejection test.                                                                               |
| Web `setIdpApiUrl`, `setManagementApiUrl`, `validateManagementApiUrl`        | Configured service bases retained; native helpers add nothing in web mode. `/management/version` is public discovery and does not invoke token exchange.                                                                                                                                                                                            | Correct, retained. Initial test fixture incorrectly expected authentication on public version; corrected to real secured restriction operation. |
| `idpAdministration.ts`                                                       | Calls current `idpApi.*Raw` operations for Applications, consents and client keys and validates actual owner JSON with existing Valibot schemas.                                                                                                                                                                                                    | Active direct IdP identity administration, not obsolete Management identity ownership or a new bypass. No edit.                                 |
| `ResourceResidency.svelte`                                                   | `StorageOwnerConfiguration.basePath = host + /storage`; generated Residency paths are `/filesystems/{filesystem_id}/residency`. Supplied resource token is transient. UI explicitly says mode is not content/cleanup readiness.                                                                                                                     | Active local whole-filesystem Residency, not Node role or Storage-only join. No edit. No Storage suite/native acceptance claimed here.          |
| `app.rs::unified_runtime_config`, `provision_service_clients`                | Separate `/idp`, `/management`, `/storage` transport bases and context roots. IdP-to-Management uses `MANAGEMENT_APPLICATION_URI` with only permission-evaluate scope. Management-to-IdP uses token-validate/device-lookup; Storage-to-IdP additionally device-list; Storage-to-Management uses Storage audience and replication read/admit scopes. | Least-privilege relationships preserved, not widened to make callers pass. Secure references/load-only retained credential behavior unchanged.  |
| `setup_peer_revocation.rs::revoke`                                           | Trusted peer base must be exact HTTPS `/idp`, without URL credentials/query/fragment. Fetch metadata before sending bearer, verify retained issuer, exchange resource = peer IdP base, DELETE relative `replica-signers/{member}` and `devices/{member}`.                                                                                           | Active explicit peer revocation, not central authorization or obsolete signing setup. No edit.                                                  |

## Full scoped audit findings: explicit matches and classification

Audit included all app source/native source and headless source via broad role/authority/replica/password/credential/persistence searches, followed by actual API/invoke call tracing. Repository-wide read-only searches also covered docs, current config, source contracts and generated output; this is not a claim of exhaustive manual verification of every Rust implementation, live spec or external repository.

| Matches                                                                                                                                                                                                                                                                                                                                               | Classification / action                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| App `(auth)/applications/[applicationId]/+page.svelte`: Management `listRoles`, `createRole`, `deleteRole`, `listPermissions`, `createPermission`, `deletePermission`, `listRolePermissions`, `assignPermissionToRole`, `revokePermissionFromRole`; `(auth)/users/[userId]`: `listUserRolesAcrossApplications`; `(auth)/roles` application navigation | Active application-scoped RBAC, not designated Node roles. Preserve all. No `isAdmin`, `hasRole`, role-membership layout admission, freshness gate, central-role selector or alternate actor header found in owned app/headless callers.                                                                                                                                                |
| Applications/list/detail, clients/detail, users/detail, authorize/register pages                                                                                                                                                                                                                                                                      | Identity CRUD, OAuth registration/consents/keys remain direct IdP APIs; permissions/roles remain Management APIs. No caller found for `registerBootstrap`/`SuperRoutesSetupApi`.                                                                                                                                                                                                        |
| `devices.svelte.ts`: list/update/revoke Device and pending Node join IPC                                                                                                                                                                                                                                                                              | IdP owns Device lifecycle. Join administration obtains current IdP owner bearer and requires a nonempty token before native IPC. `PendingNodeJoin` contains Installation/member/endpoint/approving-peer/public signer, not a Storage-only/authority join role. Preserve.                                                                                                                |
| `setup/installation/+page.svelte`, `app.rs::join_installation`                                                                                                                                                                                                                                                                                        | Purpose-specific trusted-peer joining calls native `join_installation` with issuer/peer/name, not password grant. New-Installation password goes to restricted native initial-administrator owner provisioning; no password is sent to join a peer. Explicit reset/recovery/revocation remain active. Preserve.                                                                         |
| `_SignIn.svelte`, `idpClient.svelte.ts::passwordToken`, generated `GrantType.Password`, `ResetPassword`, `AuthorizationServerMetadata` grant/credential fields                                                                                                                                                                                        | Ordinary sign-in/current OAuth metadata/password reset, not password-grant join or obsolete join credentials. Preserve; no broad word deletion.                                                                                                                                                                                                                                         |
| `oidc.svelte.ts`, `setupClient.test.ts`, OIDC README/client `authority`                                                                                                                                                                                                                                                                               | OAuth issuer/authority and issuer-scoped session/PKCE storage, not authority-Node topology. Preserve.                                                                                                                                                                                                                                                                                   |
| `app.rs` `role_id`, `IdentityAction::ReplicaSigners*`, `service_secrets.rs`, `setup_reset.rs` relationship credential inventory                                                                                                                                                                                                                       | Stable administrator role ID, explicit identity actions and secure relationship recovery, not legacy Node roles or removed signing credentials. Preserve. `idp_service::repo::RawKeyringRepo` match is in the existing native test fixture, not a new production persistence dependency. Native replica feature flags name current repositories, not topology roles.                    |
| `setup_peer_revocation_tests.rs` `ReplicaMembership`, `DbReplicaSignerRepo`, `DbRoleRepo`, password fixture and remote assertions                                                                                                                                                                                                                     | Existing exact-permission/revocation fixtures and repository adapters; not ordinary remote-only authorization or a password join path. Do not delete tests or rewrite native code under another agent's compile budget.                                                                                                                                                                 |
| `DevicePolicy.svelte` restriction and exact resource-selection mutations                                                                                                                                                                                                                                                                              | Management owns restriction/selection; UUID checks, transient resource Storage token, exact application/kind/resource target, no grant implied by Device approval. Preserve. Transfer is not implemented by this UI; do not invent a transfer route or assert transfer acceptance from these tests.                                                                                     |
| `primary`/`secondary` CSS/button/card classes; HTML `role="alert"`, `role="status"`, `[role="textbox"]` in app/headless                                                                                                                                                                                                                               | Presentation/accessibility matches, not topology/security gates. Preserve.                                                                                                                                                                                                                                                                                                              |
| `packages/idp-client/src/apis/SuperRoutesSetupApi.ts`, `models/SetupBootstrapRequest.ts`, API/model index reexports                                                                                                                                                                                                                                   | **Confirmed obsolete generated artifacts**: still advertise `/setup/bootstrap`/`registerBootstrap`, removed by prior source cutover. No active app caller. Report to generated-client owner; no hand-edit generated code.                                                                                                                                                               |
| Generated IdP `SuperRoutesReplicaSignersApi`, `EnrollReplicaSigner`, `RotateReplicaSigner`; Management `SuperRoutesReplicationApi`, `ReplicationAdmissionRequest`, `IdentityAction.ReplicaSigners*`, `IdentityResourceOneOf9`, `PermissionAuditIdentity.actor`, index exports                                                                         | Current signer membership, replication admission and actor/action/target/audit contracts, not obsolete replica-role designation or alternate actor headers. Preserve.                                                                                                                                                                                                                   |
| Generated IdP `DefaultApi.listApplicationsRequestOpts`                                                                                                                                                                                                                                                                                                | Requires offset/limit but substitutes nonexistent path placeholders instead of populating query parameters. Read-only observation of pre-existing generated pagination drift; prefix tests provide the required public inputs but do not qualify pagination. Generated-client/spec owner follow-up, no wrapper patch.                                                                   |
| `packages/storage-client/src/index.ts`, `apps/password-manager/src/lib/common/storageSocket.ts`                                                                                                                                                                                                                                                       | Initial finding: active consumer, not safe to purge. Wrapper used root `/oauth2/token`, absolute `/storage` paths and an origin audience fallback. Review classified this as a closure blocker and expanded scope. **RESOLVED by the handwritten caller/client follow-up below**; initial report-only disposition is historical. Root's dirty generated outputs/shims remain preserved. |
| `crates/unified-server/src/permission_http_tests.rs` `x-actor-subject` at service impersonation/untrusted evaluation                                                                                                                                                                                                                                  | Negative tests expecting 401/403, not accepted actor headers. Preserve. `crates/idp-server/src/node_join_tests.rs` `role: storage-only` is a forged offer rejected by approval. Preserve.                                                                                                                                                                                               |
| README/GLOSSARY/GLOSSARY-MAP; docs design/operations/public-persistence; IdP/Storage security/design docs                                                                                                                                                                                                                                             | Matches explicitly prohibit authority/Storage-only/freshness topology, label avoided terminology, or describe historical/nonaccepted behavior. Do not erase domain definitions or historical evidence. Named document updates belong to docs owner.                                                                                                                                     |
| Current `config/unified/example.yaml`, Dockerfile, justfile and package READMEs                                                                                                                                                                                                                                                                       | No resurrected primary/secondary setup config found. Unified configuration retains separate roots/secret references. Docker contains sibling workspace copies and known `idp-unified` defaults from prior evidence; deployment owner follow-up, not internal caller persistence. No checked-in standalone OpenAPI JSON/YAML spec was found by tracked-path inventory.                   |

Representative exact audit commands, run from this worktree (read-only):

```sh
rg -n -i 'authority|replica|storage.only|freshness|setup/bootstrap|setup/sign|password|remote|x.actor|credential|persistence|role|idp-management|prefix' apps/app/src apps/app/src-tauri/src packages/svelte-headless/src
rg -n 'managementApi\.|idpApi\.|idpAdministration\.|invoke[<(]|fetch\(|ownerAccessToken|roles.*includes|isAdmin|hasRole|authority|primary|secondary|freshness|X-Actor|x-actor|setup/bootstrap|setup/sign' apps/app/src apps/app/src-tauri/src/setup_peer_revocation.rs
rg -n -i 'authority.node|authoritative.node|privileged.replica|storage.only|primary.node|secondary.node|freshness|setup/bootstrap|SetupBootstrap|SetupJoin|SetupNew|SetupResidency|x.actor|actor.header|remote.only|password.grant.*join|join.*password.grant' --glob '!Cargo.lock' --glob '!pnpm-lock.yaml' --glob '!*.svg' --glob '!AGENTS.md' --glob '!scripts/generate-openapi-client.test.mjs' --glob '!**/node_modules/**' --glob '!**/.svelte-kit/**' --glob '!.scratch/**' .
rg -l -i 'central|authority|replica|primary|secondary|freshness|bootstrap|setup|password|actor|credential|signer|redb|ofdb|internal' packages/idp-client/src/apis packages/idp-client/src/models packages/management-client/src/apis packages/management-client/src/models packages/storage-client/src/generated
rg -n 'StorageClient|StorageSocket|@aicacia/storage-client|StorageOwnerConfiguration|idpAdministration|SuperRoutesSetupApi|registerBootstrap' apps packages --glob '!**/node_modules/**' --glob '!**/.svelte-kit/**' --glob '!**/dist/**' --glob '!packages/idp-client/src/**'
git --no-pager ls-files '*openapi*.json' '*swagger*.json' '*openapi*.yaml' '*swagger*.yaml'
```

## Exact validation and limitations

No installation or network retrieval. Existing root dependency directories were temporarily symlinked into this isolated worktree for Node resolution. `node_modules/.bin/svelte-kit sync` in `packages/svelte-headless` generated only ignored local Svelte metadata. The first probe run failed on missing headless `.svelte-kit/tsconfig.json`; after sync the actual regression was red: returned `https://localhost:4100` for `{stage:"ready"}` instead of null. After the predicate change, the regression passed. No native GUI, Rust/native Cargo, full Cargo hack, CRAP or cross-repository edits were run.

Final commands:

```sh
# cwd apps/app
../../packages/svelte-headless/node_modules/.bin/vitest run --config vitest.auth.config.ts
# 5 files, 61 tests passed; 0 failed/skipped; final formatted rerun 1.96s.
# Breakdown: loader 7, owner clients 4, setup client 11, auth layout 25, installation page 14.

# cwd packages/svelte-headless
node_modules/.bin/vitest run src/lib/state/createReturnTo.test.ts
# 1 file, 7 tests passed; 0 failed/skipped; 775ms.

# cwd worktree root, already cached executable (no npx install)
/home/nathan/.npm/_npx/0ff2b174d795ade9/node_modules/.bin/svelte-mcp svelte-autofixer ./apps/app/src/lib/common/state/localhostBaseUrl.svelte.ts --svelte-version 5
# issues [], suggestions [], require_another_tool_call_after_fixing false; repeated after final edits.
node_modules/.bin/biome lint apps/app/src/lib/common/state/localhostBaseUrl.svelte.ts apps/app/src/lib/common/state/localhostBaseUrl.test.ts apps/app/src/lib/common/state/ownerClients.test.ts apps/app/src/lib/common/state/setupClient.test.ts
# exit 0; existing informational noUselessContinue on unchanged catch/continue.
node_modules/.bin/biome format --write apps/app/src/lib/common/state/localhostBaseUrl.test.ts apps/app/src/lib/common/state/ownerClients.test.ts
node_modules/.bin/biome check apps/app/src/lib/common/state/localhostBaseUrl.test.ts apps/app/src/lib/common/state/ownerClients.test.ts
# check: 2 files, no fixes, passed.
git --no-pager diff --check
# passed.
```

A broader changed-file Biome `check` initially reported four formatting errors because app configuration expects four spaces while pre-existing production/setup-test files use two (and config is ignored). Only new tests were formatted; existing-file restyling is deliberately not mixed into this surgical change. This is not an all-app typecheck/build claim. Tests intercept the HTTP/native boundary; no live endpoint, restarted desktop, server authorization or generated-source regeneration has been qualified here.

Prior evidence remains historical and unchanged: root `06-generator-safety.md` and `06-obsolete-contracts.md`. Generated endpoint safety/regeneration, complete system/API documentation, out-of-scope password-manager wrapper qualification and deferred ticket 04 acceptance remain with their owners. No genuinely obsolete active caller contract or topology role gate was found to delete in the owned scope.

## Delivery

Only owned source/tests, the existing test include configuration and this evidence file were staged. Evidence was force-added explicitly, not the entire ignored scratch tree. No secrets or actual tokens are recorded; test token strings/URLs are synthetic. Temporary dependency symlinks created for validation were removed; ignored worktree-local Svelte metadata is retained.

Delivery commands from this worktree:

```sh
git add apps/app/src/lib/common/state/localhostBaseUrl.svelte.ts apps/app/src/lib/common/state/localhostBaseUrl.test.ts apps/app/src/lib/common/state/ownerClients.test.ts apps/app/src/lib/common/state/setupClient.test.ts apps/app/vitest.auth.config.ts
git add -f .scratch/offline-first-nodes/evidence/06-callers.md
git --no-pager diff --cached --check
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false commit -m "Qualify desktop caller prefixes and setup listener discovery"
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false merge --no-edit offline-first-nodes-integration
# Integration tip 2e67ed5; result: Already up to date.
git --no-optional-locks status --short --branch
# Clean tracked/untracked state on offline-first-ticket06-callers.
```

Commit hooks/automatic maintenance disabled to avoid unrequested native/full validation. This delivery result is recorded in the same scoped commit by amendment, followed by another integration-tip merge/status check. Parent remains responsible for integrating the scoped branch and ticket closure.

## Review follow-up: active password-manager blocker resolved

User expanded write scope to handwritten `packages/storage-client/src/index.ts`/`index.test.ts`, password-manager source and its configuration example. No generated package source, server, Rust crate, root built output or root shim was edited. Complexity low (two explicit service bases and exact existing wire contracts); risk wrong token audience/resource or overbroad read/write actions; priority ticket 06 active-consumer closure blocker. This supersedes only the initial password-manager report-only classification, not ticket 04's incomplete status or unrun system acceptance.

### Actual contract trace before implementation

- `crates/idp-service/src/oauth2/service.rs::token_exchange`: verifies the subject's signature/principal, Bearer/Access token use, canonical issuer, expiration/not-before/issued-at, nonempty audience, current bearer client and registered token-exchange grant/authentication. Requested scopes, when present, intersect with the subject's scopes. The resource is `request.resource` or retained subject resource; it is passed as both resource and issued audience to `issue_tokens_for_client`. An audience-only request does not select the filesystem resource. No new `scope` is requested by this client; existing subject scopes are not expanded.
- `crates/model/src/contract/authorization_details.rs` and `crates/idp-model/src/contract/token_exchange_grant_request.rs`: exact typed detail is `{"type":"storage","actions":["read","write"]}` with lowercase action variants; form JSON encoding is accepted.
- `crates/storage-server/src/router/storage_authorization.rs::storage_authorization`: requires an unexpired User Bearer/Access token, resource equal to `aud`, exactly one typed Storage detail and at least one permitted read/write action. `scoped_file_system_socket_authorizer` additionally requires exact `storage:filesystems`, valid filesystem ID and authenticated User/Application namespace.
- `router/resources.rs::list_file_systems`/`create_file_system`: actual catalog is `/storage/filesystems`; namespace resource is `storage:filesystems`; GET requires read, POST requires write. `authorize_response` rechecks current authorization and unchanged namespace before returning results. The socket is `/storage`; `router/storage_socket.rs::allows` requires read for read/entry/list and write for write/append/delete/createDir/rename, with per-request current authorization checks. These checks were read, not rebuilt or run here.
- `router/storage_socket.rs::serve_socket` parses `StorageRequest` directly, not `{type:"request",request:...}`. This exposed a second genuinely obsolete active wire contract. The handwritten client now sends the flat request, confirmed by a red/green serialized read/write test.
- Password-manager page lists/creates the catalog and selects a filesystem before opening a socket. `SecretStorage.list` reads/list entries, `save` writes and `delete` deletes. Therefore catalog GET remains read-only, creation write-only and the editable vault socket retains its existing read+write request; no wider actions were added. Existing OIDC configured authority/current `getAccessToken` flow and all server issuer/actor/action/namespace checks remain unchanged.

### Handwritten changes and configuration impact

- Replace `StorageClientOptions.baseUrl`/`audience` with explicit `idpBaseUrl` and `storageBaseUrl`. No old-version aliases or compatibility routes. Only existing handwritten caller and its tests needed updating; repository caller search found no other `new StorageClient` consumer beyond password-manager and tests.
- Append `/oauth2/token` to the configured IdP service base, preserving `/idp` and any deployment path. Append `/filesystems` to the explicit Storage base; use that base itself for the socket and switch HTTP(S) to WS(S). Strip only terminal slashes before appending, never duplicate the service prefix. HTTP(S) validation remains, with credentials/query/fragment rejected on service bases.
- Exchange the current User token with `resource=storage:filesystems`; the reviewed server derives **expected issued `aud=storage:filesystems`** from that resource. Remove the ineffective audience-only field and origin fallback. Keep `client_id=password-manager-web`, Access subject-token type and the exact typed action detail. Transport base is not an OAuth resource/audience. No client-side fake issuer trust or actor header was added.
- Password-manager now requires `PUBLIC_STORAGE_BASE_URL`; `.env.example` pairs `PUBLIC_LIDP_BASE_URL=https://api.localhost:1355/idp` with `PUBLIC_STORAGE_BASE_URL=https://api.localhost:1355/storage`. Both are complete service bases, not origins. Missing either fails before requesting a User token or performing network IO. Existing deployments must supply the Storage base; `PUBLIC_STORAGE_AUDIENCE` is no longer consumed.
- Existing app auth Vitest configuration includes password-manager's focused test and aliases `@aicacia/storage-client` to the **worktree handwritten source**, not dirty root `esm`/`types`. No builds/cleaning required to test this API change.

### TDD and exact final validation

Public seams: `StorageClient.listFileSystems`, `createFileSystem`, `openSocket`, `StorageSocket.request`/`close` and password-manager exported `listFileSystems`, `createFileSystem`, `openStorageSocket`. Tests use real handwritten client code and intercepted fetch/WebSocket IO, not fake client classes.

Red/green observations:

1. Updated old audience-only/root-token listing test to the explicit service-base/resource contract. Before implementation it rejected with `Invalid URL` due to obsolete options; after implementation it passed, asserting literal `/idp/oauth2/token`, `/storage/filesystems`, exact resource, no audience-only field, Access subject type and read-only detail.
2. Flat read/write socket contract test initially received `invalidRequest` for both obsolete envelopes, while the catalog/create tests passed. Removing the envelope made it pass, including literal socket URL, read+write detail, serialized flat requests, queue order and close.
3. Password-manager public tests initially had four failures: old caller passed no current bases and missing Storage configuration silently fell back. After updating the caller, five tests passed for real exchange URL/body, catalog/create/socket URLs, action separation and missing IdP/Storage failure. That red run also exposed an unhandled promise caused by the obsolete caller; no unhandled errors remain in green runs.

No installs/network, GUI, Rust builds, full Cargo hack or CRAP. Existing dependency symlinks were used only in this worktree. `node_modules/.bin/svelte-kit sync` in `apps/password-manager` generated ignored metadata needed for its test transform; the initial attempt before sync reported missing `.svelte-kit/tsconfig.json`. An initial invocation used the wrong config cwd and failed to resolve `vitest.auth.config.ts`; rerun from `apps/app` used the existing config correctly.

```sh
# cwd packages/storage-client, existing root tool (final after formatting)
/home/nathan/code/rust/aicacia/of/packages/storage-client/node_modules/.bin/vitest run --no-cache src/index.test.ts src/residency.test.ts
# 2 files, 18 passed / 0 failed/skipped; 341ms (12 handwritten client + 6 unchanged generated-Residency consumer checks).
# Tests cover read-only catalog, write-only creation, service prefixes/deployment paths/trailing slash,
# exact filesystem resource, read+write socket and flat request semantics, missing User token,
# denied exchange/missing issued token, invalid service bases and catalog 403 propagation.

# cwd apps/app
/home/nathan/code/rust/aicacia/of/packages/storage-client/node_modules/.bin/vitest run --no-cache --config vitest.auth.config.ts
# 6 files, 66 passed / 0 failed/skipped; 1.83s (prior 61 plus 5 password-manager).

# cwd packages/svelte-headless
/home/nathan/code/rust/aicacia/of/packages/svelte-headless/node_modules/.bin/vitest run --no-cache src/lib/state/createReturnTo.test.ts
# 1 file, 7 passed / 0 failed/skipped; 813ms.
/home/nathan/.npm/_npx/0ff2b174d795ade9/node_modules/.bin/svelte-mcp svelte-autofixer ./src/lib/state/storage.svelte.ts --svelte-version 5
# issues []; suggestion to inspect updateStorage within $effect. Reviewed: it only serializes/writes browser storage,
# does not assign reactive state. Appropriate side effect retained; no headless edit.

# cwd worktree root
/home/nathan/.npm/_npx/0ff2b174d795ade9/node_modules/.bin/svelte-mcp svelte-autofixer ./apps/password-manager/src/lib/common/state/oidc.svelte.ts --svelte-version 5
# issues [], suggestions [], require_another_tool_call_after_fixing false.
/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome format --write packages/storage-client/src/index.ts packages/storage-client/src/index.test.ts apps/password-manager/src/lib/common/storageSocket.ts apps/password-manager/src/lib/common/storageSocket.test.ts
/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome check --write packages/storage-client/src/index.ts
# Reordered existing handwritten reexports only, resolving the pre-existing export-order diagnostic.
/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome check packages/storage-client/src/index.ts packages/storage-client/src/index.test.ts apps/password-manager/src/lib/common/storageSocket.ts apps/password-manager/src/lib/common/storageSocket.test.ts
# 4 files, no fixes, passed.
git --no-pager diff --check
# passed.
```

An early Vitest run without `--no-cache` changed the worktree's tracked Storage `.vite/.../results.json`. Restored **only that self-created worktree cache change** to its initially clean HEAD version; all subsequent runs used `--no-cache`. Existing tracked worktree shims/dependency links were retained, not cleaned. Root dirty `packages/storage-client/esm`, `types` and `.bin` shims were never edited or rebuilt. Read-only root `git diff --binary -- packages/storage-client | sha256sum` was observed as `667afe03e6a9a7e0e3a4b277b1e1f6ea08082e845cba9591bf7d8b3e03cefe9e`; final preservation check was identical, with the same ten root dirty output/shim paths and no added root changes.

Disposition: **active password-manager caller prefix/resource/action/socket-contract blocker resolved at the tested handwritten public APIs**. This is not live HTTP/native acceptance or a generated-source regeneration claim. Pre-existing generated IdP pagination drift remains documented above and deliberately unfixed. Ticket 04 stays incomplete; parent handles final 06 closure and integration.

Follow-up delivery (worktree root):

```sh
git add apps/app/vitest.auth.config.ts apps/password-manager/.env.example apps/password-manager/src/lib/common/storageSocket.ts apps/password-manager/src/lib/common/storageSocket.test.ts packages/storage-client/src/index.ts packages/storage-client/src/index.test.ts
git add -f .scratch/offline-first-nodes/evidence/06-callers.md
git --no-pager diff --cached --check
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false commit -m "Fix password-manager Storage resource exchange and service prefixes"
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false merge --no-edit offline-first-nodes-integration
# Integration tip 2e67ed5; Already up to date.
git --no-optional-locks status --short --branch
# Clean offline-first-ticket06-callers; self-created temporary dependency symlinks removed.
```

Delivery results are recorded by amendment of this additional fix commit (not the prior caller checkpoint), followed by another integration-tip merge/status check. No generated source, built output, shim or cache change is staged.

## Packaging review follow-up: isolated exported-package qualification

The previous 66-test source-alias result did not establish that normal package exports were current. User approved source but required a Storage package build and normal **unaliased** consumer qualification, while explicitly deferring built-output commits to protect overlapping root dirty files. Complexity low (existing package workflow and an alias-free test config); risk publishing stale exports or overwriting user artifacts; priority packaging closure blocker.

### Merge and build boundary

```sh
# cwd worktree root, initially clean at 86178f5
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false merge --no-edit offline-first-ticket06-clients
# Merge commit 64eee5c, other parent dcdf8e9e81daec6660d559f303af48fd262935d5.
# Clean merge, no conflicts; generated clients and owner evidence imported, not hand-edited.
```

Worktree root `node_modules` was created as a real directory, with only `node_modules/.pnpm` linked to the existing installed root store. No full root `node_modules` symlink was used. Storage package, `esm`, `types` and `browser` were verified to be real worktree-local paths before building. Existing package-local `.bin` tools resolve installed modules from that store. The package scripts are:

- `clean`: `shx rm -rf esm browser types tsconfig.tsbuildinfo` (relative to the isolated Storage package only).
- `build:esm`: `tsc --project tsconfig.json` (all non-test package source, including fresh generated source; declaration/maps enabled).
- `build:browser`: `rolldown -c` (existing `src/index.ts` entry → `browser/index.js`).

```sh
# cwd packages/storage-client
pnpm run build
# exit 0: clean, full package tsc and Rolldown succeeded; browser bundle 17.72 kB, Rolldown 81.81ms.
```

**Constraint deviation, not hidden:** pnpm 12.4.1 unexpectedly performed automatic workspace dependency setup before running `build`, including package prepare and app Svelte sync hooks, and reported `+ @openapitools/openapi-generator-cli 2.41.0`. No explicit install command was issued, but this still breached the requested no-install constraint. Returned output did not show download lines; that is not proof of zero network activity. This setup refreshed six worktree Storage shims and worktree dependency/ignored metadata. The shared installed-store link means cache metadata effects are not claimed absent. Root's original tracked dirty Storage output/shim bytes remained unchanged, verified repeatedly by the identical diff hash below.

Restored only those six self-created **worktree** shim changes with an explicit `git restore -- packages/storage-client/node_modules/.bin/biome packages/storage-client/node_modules/.bin/rolldown packages/storage-client/node_modules/.bin/shx packages/storage-client/node_modules/.bin/tsc packages/storage-client/node_modules/.bin/tsserver packages/storage-client/node_modules/.bin/vitest`. No root restore/clean/build occurred. Subsequent build/test commands used direct existing worktree executables, not pnpm script execution or dependency setup:

```sh
# cwd packages/storage-client
node_modules/.bin/tsc --project tsconfig.json && node_modules/.bin/rolldown -c
# exit 0; package-wide TypeScript build plus browser build passed, Rolldown 31.12ms.
```

### Normal exported package and real caller tests

Added `apps/app/vitest.package.config.ts`: only SvelteKit test transformation plus the existing password-manager public-boundary test include. **No resolve aliases**, including no Storage source alias. The real password-manager workspace dependency link resolves to this worktree's `packages/storage-client`; package exports then select `esm/index.js`.

The first config attempt could not resolve `vitest/config` because the app does not declare Vitest. A worktree-local `node_modules/vitest` symlink to `../packages/storage-client/node_modules/vitest` exposed the already installed tool; no further install. Then:

```sh
# cwd apps/app
../../packages/storage-client/node_modules/.bin/vitest run --no-cache --config vitest.package.config.ts
# 1 file, 5 passed, 0 failed/skipped; final run 249ms.
```

These are the actual password-manager `listFileSystems`/`createFileSystem`/`openStorageSocket` exports using the **built package**, not fake Storage classes. Fetch/WebSocket boundaries are intercepted; current User-token provider is mocked, so this is not a whole-app authentication or live-server test. Assertions cover the complete token-exchange body/resource/read or write detail, configured `/idp/oauth2/token`, independent Storage catalog and socket URLs, selected filesystem and missing configuration. Old built options/audience-only logic would not satisfy these assertions.

Additional direct Node package/declaration qualification, cwd worktree root:

```sh
node --input-type=module -e 'import assert from "node:assert/strict"; import { createRequire } from "node:module"; import { resolve } from "node:path"; import { pathToFileURL } from "node:url"; import { readFileSync } from "node:fs"; const require = createRequire(pathToFileURL(resolve("apps/password-manager/package.json"))); const entry = require.resolve("@aicacia/storage-client"); assert.equal(entry, resolve("packages/storage-client/esm/index.js")); const api = await import(pathToFileURL(entry)); assert.equal(typeof api.StorageClient, "function"); assert.equal(typeof api.ResourcesResidencyApi, "function"); const manifest = require("@aicacia/storage-client/package.json"); assert.equal(manifest.exports["."].types, "./types/index.d.ts"); const types = readFileSync(resolve("packages/storage-client/types/index.d.ts"), "utf8"); assert.match(types, /idpBaseUrl: URL \| string/); assert.match(types, /storageBaseUrl: URL \| string/); assert.doesNotMatch(types, /audience: string/); console.log("Unaliased password-manager package entry:", entry); console.log("Built runtime exports and declared current service-base options: PASS");'
# PASS, entry /home/nathan/code/rust/aicacia/of/.worktrees/ticket06-callers/packages/storage-client/esm/index.js.
```

Supplemental old source-alias auth-suite rerun after workspace setup/merge:

```sh
# cwd apps/app
../../packages/storage-client/node_modules/.bin/vitest run --no-cache --config vitest.auth.config.ts
# 55 passed / 11 failed, 6 files, 1.56s.
# All 11 setupClient tests fail resolving the unbuilt worktree @aicacia/native-fetch package entry.
# Remaining 55, including all password-manager and owner-client tests, passed.
```

This does not supersede that dependency failure with the historical 66-pass result. No unrelated native-fetch build, alias patch, whole-password-manager Vite build, Cargo/native execution or GUI was attempted. No generated API source was edited to make package compilation succeed. Historical generated-bootstrap/pagination findings above remain evidence of the initial state; fresh generated-client branch evidence is now merged, with no new pagination patch by this agent.

### Built output inspection and distribution disposition

`git ls-files` shows these five artifacts are already versioned despite package `.gitignore` ignoring `/esm`, `/types`, `/browser`:

| Worktree output                                | Diff (+/-) | SHA-256 after isolated build                                       |
| ---------------------------------------------- | ---------- | ------------------------------------------------------------------ |
| `packages/storage-client/browser/index.js`     | 388/14     | `f3e4f75f7237456fb8fd9cb1dc9bead9c2a5cf62bd5e503e1a05a5408fdd1fb9` |
| `packages/storage-client/esm/index.js`         | 16/10      | `a0e3764c5b9bc0ef1a5f9c2e5a88a4bcf6f48435f567e389bffb4eca91d5f9bc` |
| `packages/storage-client/esm/index.js.map`     | 1/1        | `e8d24d49a85af834610c5e3b31bd7c51aa46516cc5095d794e21e96b3e39dbf5` |
| `packages/storage-client/types/index.d.ts`     | 6/3        | `a6a0c6cc485bff9da11902a3d40fc646c3363dbb9bf105d0ff648f33b68470b7` |
| `packages/storage-client/types/index.d.ts.map` | 1/1        | `d11ebb1f3408e9c4c2a8d3799db4173663315afbe820a7933bfd19c76801df56` |

Inspected JS/declaration diffs confirm new service-base options, exact resource exchange, prefix-preserving URLs and flat socket requests; JS and declarations also reexport compiled generated Residency/runtime code. Build produced **30 ignored files under `esm/generated` and 30 under `types/generated`**, required by those reexports. The browser output bundles the current generated dependencies; no hand-edit of any built file.

**Decision:** isolated build plus alias-free real-caller/Node checks is adequate qualification that the exported package can be built and consumed correctly. It is **not adequate distribution state for a checkout that runs Vite without rebuilding packages**. This repo currently versions five outputs, but committing only their updated bytes would still omit the ignored compiled generated dependency trees. Package distribution must ship the complete build output or enforce package building before normal consumers run. Root script `packages:build` already provides a package-build workflow, but no app-build precondition was established by this review. Coordinator must choose complete-artifact publication/commit versus a verified build-before-consume policy, reconciling the root user's dirty files first. Per explicit instruction, **none of these built outputs is staged or committed**; all five remain intentionally dirty in this isolated worktree, and ignored generated output trees/metadata are retained for inspection. Root is neither rebuilt nor claimed correct.

### Preservation and delivery

Read-only root command before/after merge/build/tests:

```sh
# cwd root of (not worktree)
git --no-optional-locks status --short packages/storage-client
git --no-pager diff --binary -- packages/storage-client | sha256sum
# Same ten dirty output/shim paths and hash:
# 667afe03e6a9a7e0e3a4b277b1e1f6ea08082e845cba9591bf7d8b3e03cefe9e
```

Only the alias-free test configuration and this exact packaging evidence were staged and committed; merge `64eee5c` carries the separately owned client generation. Worktree shims restored, built outputs intentionally left unstaged. Ticket 04 remains incomplete and parent owns closure/integration/distribution reconciliation. The no-install constraint deviation and supplemental dependency failure remain explicit, not counted as successful acceptance.

```sh
# cwd worktree root
git add apps/app/vitest.package.config.ts
git add -f .scratch/offline-first-nodes/evidence/06-callers.md
git --no-pager diff --cached --check
# Passed; staged stat contains only evidence and the 9-line alias-free config.
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false commit -m "Qualify built Storage package through unaliased password-manager imports"
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false merge --no-edit offline-first-nodes-integration
# Tip 2e67ed5; Already up to date.
git --no-optional-locks status --short --branch
# Only the five explicitly deferred Storage built output files remain modified.
```

Delivery results recorded by amendment of the packaging evidence commit, not by staging any built artifact; integration-tip merge/status is checked again after amendment.

## Production-framework alias and final worktree cleanup

Reviewer approved the minimal production SvelteKit mapping. `apps/password-manager/svelte.config.js` now imports `fileURLToPath` from `node:url` and sets `kit.alias["@aicacia/storage-client"]` to `fileURLToPath(new URL("../../packages/storage-client/src/index.ts", import.meta.url))`. This is a framework source-entry mapping shared by runtime/type resolution, not a compatibility/auth wrapper. The handwritten entry and merged generated source remain the current contract. Dependency declarations, Storage package export map, `apps/app/vitest.package.config.ts` and its existing independent unaliased consumer tests are unchanged.

Added `apps/password-manager/svelte.config.test.mjs`, using Node's built-in test/assert APIs and the already installed Vite/SvelteKit tools. It loads the actual production config, verifies the source entry, resolves framework Vite configuration without starting a server and verifies the real runtime alias/file target. Initial script placement at repo `scripts` could not use CommonJS resolution of SvelteKit's import-only `/vite` export; moved the test into the app and used ordinary ESM imports, with no dependency addition. The meaningful red run then failed both assertions (`undefined` alias before implementation); both passed after the production mapping.

Validation used **direct tools only** in this follow-up: no pnpm execution, dependency installation, package rebuild, Cargo/native build or GUI. Commands from `apps/password-manager`:

```sh
node --test svelte.config.test.mjs
# Final formatted run: 2 passed, 0 failed/skipped; 744.89ms.
node_modules/.bin/svelte-kit sync
# exit 0; only worktree-local generated Svelte metadata.
node --input-type=module -e 'import assert from "node:assert/strict"; import { readFileSync } from "node:fs"; import { resolve, dirname } from "node:path"; const file = resolve(".svelte-kit/tsconfig.json"); const tsconfig = JSON.parse(readFileSync(file, "utf8")); const paths = tsconfig.compilerOptions.paths["@aicacia/storage-client"]; assert.equal(paths.length, 1); assert.equal(resolve(dirname(file), paths[0]), resolve("../../packages/storage-client/src/index.ts")); console.log("SvelteKit generated type resolver uses handwritten Storage source: PASS");'
# PASS: framework generated tsconfig selects the same source entry.
node_modules/.bin/biome check svelte.config.js svelte.config.test.mjs
# 2 files, passed, no fixes.

# cwd apps/app, before restoring isolated package outputs
../../packages/storage-client/node_modules/.bin/vitest run --no-cache --config vitest.package.config.ts
# Unchanged independent unaliased package harness: 5 passed, 0 failed/skipped; 347ms.
```

Formatting used direct worktree `node_modules/.bin/biome format --write apps/password-manager/svelte.config.js apps/password-manager/svelte.config.test.mjs` from worktree root, followed by the final Node test above. No tests/config were changed to turn the independent package harness into a source-alias check. Its application root remains `apps/app`, with no Storage alias there.

**Current broader auth prerequisite:** the latest full auth suite remains **55 passed / 11 failed**, with all 11 failures resolving the absent built `@aicacia/native-fetch` worktree entry. The earlier 66-pass result is historical, not the current result. Native-fetch complete JS package build is a prerequisite for rerunning that suite; no unrelated/native build was attempted here. The framework alias removes the stale Storage output dependency from production password-manager resolution, not that separate dependency prerequisite. Other direct package consumers still require the complete build-output distribution documented by the docs owner; the Storage export map remains unchanged. Independent unaliased checks require an isolated Storage build and are evidence of the build before cleanup, not a claim that clean-checkout or root built artifacts are current.

After all checks, restored **only these self-created worktree build changes** with:

```sh
git restore -- packages/storage-client/browser/index.js packages/storage-client/esm/index.js packages/storage-client/esm/index.js.map packages/storage-client/types/index.d.ts packages/storage-client/types/index.d.ts.map
```

Removed only artifacts created by this agent's test/sync/build/dependency setup, using Python `Path.unlink` for files/symlinks and `shutil.rmtree` for real directories (does not traverse linked root dependency store):

- `apps/app/{.svelte-kit,node_modules}`, `apps/password-manager/{.svelte-kit,node_modules}`.
- `crates/tauri-plugin-fetch-api/node_modules`.
- `packages/{idp-client,management-client,native-fetch,oidc-client,svelte-headless}/node_modules`, `packages/svelte-headless/.svelte-kit`.
- `packages/storage-client/{esm/generated,types/generated,tsconfig.tsbuildinfo}`.
- Self-created `packages/storage-client/node_modules/.bin/openapi-generator-cli` and `packages/storage-client/node_modules/@openapitools` only; original tracked Storage shims/dependency links/cache are retained intact.
- Worktree-local root `node_modules`, including unlinking its shared-store pointer; root store itself is not deleted.

These paths did not exist as untracked/ignored artifacts before this agent's work; the Storage node_modules baseline is tracked and was deliberately not removed. No blanket `git clean`, reset, deletion of source or root cleanup. Merged `dcdf8e9` generated source is retained. Exact post-cleanup checks:

```sh
git --no-optional-locks status --short --ignored
# Only production config and its new test pending staging; no remaining ignored artifacts.
git --no-pager diff --check
# passed.
git --no-pager diff --exit-code -- packages/storage-client/src/generated packages/idp-client/src packages/management-client/src
git --no-pager diff --exit-code -- apps/app/vitest.package.config.ts packages/storage-client/package.json packages/storage-client/esm packages/storage-client/types packages/storage-client/browser packages/storage-client/node_modules
# both exit 0: merged source, independent harness/export map and original built/tooling baseline preserved.
```

Read-only root check after cleanup again reports the same ten dirty Storage output/shim paths and exact diff hash `667afe03e6a9a7e0e3a4b277b1e1f6ea08082e845cba9591bf7d8b3e03cefe9e`. No root bytes were restored or overwritten. Only production source-alias config, its focused test and this evidence were staged and committed; no built output or tooling is committed. Parent/docs owner retains complete-output distribution instructions and ticket closure. Ticket 04 remains incomplete.

Final delivery commands (worktree root):

```sh
git add apps/password-manager/svelte.config.js apps/password-manager/svelte.config.test.mjs
git add -f .scratch/offline-first-nodes/evidence/06-callers.md
git --no-pager diff --cached --check
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false commit -m "Use current Storage source through production password-manager SvelteKit alias"
GIT_EDITOR=true git -c core.hooksPath=/dev/null -c maintenance.auto=false merge --no-edit offline-first-nodes-integration
# Integration tip 2e67ed5; Already up to date.
git --no-optional-locks status --short --ignored --branch
# Clean offline-first-ticket06-callers: no tracked, untracked or ignored created artifacts remaining.
```

Delivery result recorded by amendment of the source-alias commit, followed by the same final merge/status check. All validation preceded deliberate cleanup of the isolated build/dependency metadata; no unrun post-cleanup check is asserted.
