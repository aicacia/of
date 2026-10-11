# 01 Local trusted identity, policy, signers, and grants

Status: ready-for-agent
Type: task
Work status: resolved
Blocked by: None

## What to build

Replace authority/replica identity and policy semantics with equal Node operations against persistent trusted local state. Question: can a completed Node administer identity/policy, validate and issue tokens, and restart without a reachable central service?

## Scope and acceptance criteria

**Completion scope:** checks below certify the ticket 01-owned local identity/policy/signer/grant foundation and public security contracts, as split explicitly in the Answer below. Native persisted binding/database reopen is local acceptance. Production setup/join is 04; OS secure-store/completed-host restart is 04/07/08; safe history exchange and authenticated import/apply are 02/03. Those are downstream consumers, not prerequisites of 01. These checks do not certify the complete offline-first spec or resolve any other ticket.

- [x] Audit/remove designated-writer/authority/replica mutation guards, promotion concepts, 30-second freshness readiness, restart-unready leases, and mandatory remote authorization. Keep context repositories separate and owner APIs authenticated.
- [x] Any Node may perform identity, signer, client, role/permission, consent, code, and refresh lifecycle mutations when its locally checked actor/action/target permissions allow them. Missing/invalid local state or failed local evaluation denies without mutation; remote disconnection alone does not.
- [x] Persist local trust and policy so completed Nodes restart usable offline. Establish explicit trusted peer record allowlists and safe domain conflict handling; never treat CRDT convergence as proof of authorization or globally ordered administration.
- [x] Independent local private signers remain local. Preserve public signer uniqueness, Installation/endpoint binding, exact retry/conflict checks, configured Canonical Issuer, and distinct Principal/signer/transport identity. No raw secrets/passwords/private keys synchronize; approved public data may.
- [x] Token checks enforce signature, issuer, audience, use, lifetime, locally active signer/Principal/client, scope and permission. All Nodes support user/client issuance; learned signer/Principal/client/Device revocation blocks subsequent work locally.
- [x] Code consumption and refresh rotation remain durable and atomic locally, with one local concurrent winner and replay denial after reopen. Document and test the absence of a global partitioned single-use guarantee; no designated consumer or global lock is introduced.
- [x] Define allowed synchronized grant/security data and reconnect reconciliation without overstating protection against consumption already performed during a partition.
- [x] Domain-focused tests cover allowed/denied mutation, wrong actor/action/target/audience, impersonation, local corruption/revocation denial, offline restart/issuance, independent signers and accepted divergent decisions. Generic persistence changes are handed to 02/`ofdb`, not implemented through internal crates here.

## Verification and completion

Assess complexity, risk, and priority before code changes. Record exact focused commands and outcomes; final live partition integration belongs to 08. Historical old 01 signer tests are useful baseline evidence, not acceptance of removed role guards.

## Comments

Retains domain portions of old 01–03, 11 and 16; retires authority-only lifecycle, freshness, and global single-use requirements. [Spec](../spec.md), [migration map](../map.md).

### Implementation claim — 2026-10-07

Claimed on `offline-first-local-identity` in `.worktrees/local-identity`; integration ancestry confirmed at `5b22a32`. Complexity: high (identity/policy/OAuth/trust boundaries); risk: high (authorization bypass, secret disclosure, replay); priority: prerequisite for 02–08. Public seams under test are the ticket-specified OAuth issuance/validation/grant lifecycle, authenticated administration/signer operations, local permission evaluation, and safe public security-record contracts. No generic persistence-owner implementation or other-repository edits.


### Implementation evidence and acceptance gaps — 2026-10-07

Implementation commit: `ed8fa2b24b3228eed28da738605bd1173895eed1` on `offline-first-local-identity`, worktree `/home/nathan/code/rust/aicacia/of/.worktrees/local-identity`. Only implementation files in that worktree were committed. Original modified domain documents are preserved; no other repository was edited. Integration tip `5b22a32b17f88705023e0dc05e16c474e0c4d578` is an ancestor of HEAD. Post-commit `git merge --no-edit offline-first-nodes-integration` returned **Already up to date**. The integration branch was not changed, and the implementation worktree is clean.

**Disposition: remains claimed, not resolved.** The implementation is substantive, but the evidence below does not demonstrate every acceptance criterion. Acceptance checkboxes remain unchecked rather than implying full qualification. Contract details and evidence boundaries are committed in `crates/idp-service/docs/local-security.md`.

#### Delivered behavior and acceptance coverage

| Acceptance area | Implementation/evidence | Remaining boundary |
| --- | --- | --- |
| Equal local mutation and readiness | Removed `IdpRole`, authority mutation/provisioning guards, `ReplicaReadiness`, freshness/restart leases, and IdP remote `PermissionClient`. Unified and standalone IdP use Management-owned `LocalPermissions` with a separate persistent policy store. | Retained replica feature/module/route names are not role guards; wider naming/client cleanup belongs to 06. Legacy signer HTTP fixture is not qualified. |
| Locally authorized administration | Real HTTP administration preserves actor/action/target/audience and impersonation denials, yet succeeds after the Management HTTP listener stops. Policy reopen test preserves local evaluation and wrong-actor/action/target denial. | Complete deployed caller/host offline qualification remains unproven. |
| Persistent trust/policy and safe conflicts | Native database reopen tests; unresolved security conflicts fail closed. Authorized conflict resolution cannot clear consumed/revoked lifecycle timestamps to null. | Test private-key store survives database reopen; this is not process/OS secure-store restart evidence. |
| Independent private signers and public security contracts | `NodeSignerBinding`; local private material; exact derived-public-key/approval matching; Device/endpoint/membership/issuer/expiry/conflict checks; public metadata cannot sign. IdP projection rejects private fields, embedded private JWK scalars and raw grants; Management has a separate policy-table allowlist. | Projection is not a safe opaque CRDT-history export API. Trusted-peer checks require independently authenticated connection identity. Actual import/apply and transport provenance belong to 02/03. |
| Token and Principal security | ES256K/secp256k1 metadata; strict JWT segment parsing; signature/issuer/audience/use/lifetime/client/scope checks; signed required `principal_key_id` separate from Node signer preserves root rotation/revocation invalidation. User/client issuance and locally learned revocation denial covered by service/lifecycle tests. | Old tokens without `principal_key_id`, retired role config, and old mislabeled key metadata are intentionally rejected, with no compatibility fallback. |
| Local code/refresh lifecycle | One local concurrent winner, durable replay denial after reopen; signing capability and issuance inputs checked before code consumption. Independent disconnected Nodes can both issue from their local grant view. | No global single-use guarantee, designated consumer or global lock. |
| Reconnect/security data | Public hashed grant lifecycle projection; explicit conflict denial and non-null revocation/consumption reconciliation. Already-issued partition tokens cannot be undone by reconnect. | Authenticated live import/reconnect/partition evidence is downstream 02/03/08, not inferred from convergence. |
| Domain tests | OAuth/signers/local policy/public projection seams and real authenticated HTTP lifecycle tests, including wrong actor/action/target/audience and impersonation. | Complete host restart and the legacy live-listener signer fixture remain unqualified; broader suites have failures below. |

#### TDD regression evidence

Observed failing behavior before fixes: authority freshness denied service reopen; token signer incorrectly equaled User authentication key; JWT accepted a fourth segment; unavailable local signer consumed an authorization code; conflict reconciliation could clear refresh revocation; the real lifecycle test exposed lost Client-root rotation invalidation. Each was addressed with a focused regression. Client-root denial expectations were retained, not weakened; signed `principal_key_id` restored the independent binding. The obsolete expectation that remote evaluator capability loss causes IdP 503 was replaced with local-policy success, while actual client/root revocation and permission denials remain.

#### Commands and results

Commands ran in the implementation worktree. Results recorded from this implementation session:

| Command | Result |
| --- | --- |
| `cargo hack test -p idp-service --feature-powerset --all-targets` | All 10 feature combinations passed; replica combinations run 38 tests, non-replica combinations 10. |
| `cargo test -p unified-server --lib normal_permission_http_administration` | Passed; latest sequential run 151.57s. Local policy permits administration after Management HTTP stops. |
| `cargo test -p unified-server --lib normal_identity_and_infrastructure_lifecycle` | Passed, 129.07s; client secret/root rotation, key revocation, permissions and impersonation preserved. |
| `cargo test -p management-service --features replica local_policy_survives_reopen_and_denies_wrong_actor_action_and_target` | Passed. |
| `cargo test -p management-service --features replica policy_sync_is_context_local_and_explicitly_allowlisted` | Passed. |
| `cargo test -p idp-model --features replica reconnect_conflict_resolution_cannot_resurrect_revoked_refresh_grants` | Passed. |
| `cargo test -p idp-model --features replica security_decisions_fail_closed_until_an_administrator_resolves_the_selected_state` | Passed. |
| `cargo clippy -p idp-service -p management-service --features replica --lib -- -D warnings` | Passed. |
| `cargo check -p idp-server -p unified-server --all-targets` | Passed. |
| `git diff --check` and cached diff check | Passed before commit. Changed Rust files formatted using `rustfmt --edition 2024 --config skip_children=true`. |

#### Remaining qualification gaps and unsuccessful validation

1. Completed-host/process restart and actual OS secure-store persistence were not demonstrated. Native database reopen retains a test private-key store. Setup/join must persist local signer binding and endpoint identity; actual host qualification belongs to 04/07/08.
2. Authenticated transport import/apply is not wired by this ticket. Safe projection contracts do not authorize exporting opaque row history or establish provenance. 02/03 supply adapters and execution checks; 08 supplies live reconnect/partition acceptance.
3. `crates/idp-server/src/cli/provision_service_client.rs` has compile-cutover changes, but its large legacy signer HTTP fixture still assumes remote permission fixtures/old signer behavior. Full fixture success is not claimed.
4. `cargo test -p idp-model --features replica` reported 13 passed / 1 failed: `initializes_idempotently_with_uuid_primary_keys_and_unique_devices` uses hard-coded non-UUIDv7 primary keys. Focused unchanged Management tests `actor_validation_uses_scoped_client_bearer_and_returns_verified_claims` (configured-issuer mismatch) and `selection_survives_reopen_and_rejects_wrong_namespace` (UUIDv7 primary-key requirement) also failed; other selection tests failed in a broader run. These failures were not hidden or fixed as unrelated ticket work.
5. `just crap` timed out after 120 seconds during workspace coverage compilation: no CRAP result/score produced. Full workspace feature-matrix/final qualification is not claimed.
6. Running HTTP tests concurrently with the feature matrix caused a 12-second request timeout under contention; sequential focused HTTP runs passed. This is not evidence of concurrent-load qualification.

The remaining gaps are explicit handoffs/evidence boundaries, not permission to weaken local security checks or mark downstream tickets resolved. No tests were disabled to conceal failures.


### Review follow-up claim/risk — 2026-10-07

Continuing claimed ticket 01 after review of `ed8fa2b`. Complexity: medium/high; security risk: high (signer trust, signed Principal binding, incomplete security projections); priority: fix ticket 01 contract regressions before downstream wiring. User-requested seams: real IdP listener issuance/introspection, persisted signer binding and database reopen with real OAuth issuance, owner token verification, and public security projection validation against actual schemas. Reproduced `cargo test -p idp-server --lib live_idp_listener_issues_and_introspects_service_tokens`: failed 403, local node signer not configured. Production preparation/setup wiring remains an explicit 04 blocker; no authority fallback or whole setup implementation.


### Review fixes committed and qualified at local seams — 2026-10-07

Follow-up commit: `ea8d6e2861586259c964c0959a348a1d66219184`, based on `ed8fa2b24b3228eed28da738605bd1173895eed1`, branch `offline-first-local-identity`. Eight implementation files committed in the local-identity worktree only. Original domain-document edits are preserved; no other repository edited. Integration tip `5b22a32b17f88705023e0dc05e16c474e0c4d578` remains an ancestor; post-commit merge returned **Already up to date**. Integration branch untouched; implementation worktree clean. Ticket remains **claimed**, not resolved.

#### Review findings addressed

- Real listener fixture now explicitly prepares an independent Node signer, approves matching Device/member/public-signer trust, and supplies `OAuth2Config.local_signer`. The old remote permission fixture, evaluator credentials and blanket replica-role denial blocks are removed. It uses separate persistent Management policy, proves denial before grants, explicit local permission approval, enrollment retry/conflict, independent signer rotation/revocation, local grant revocation, user/client issuance, introspection and client/refresh security checks. Local signer trust remains intact when the peer signer is revoked. Both HTTP listener tasks are shut down explicitly. **This supersedes the earlier unqualified legacy-listener gap.**
- Native reopen coverage now persists the complete OAuth binding configuration to disk, drops original services, reconstructs owner repositories and configuration from the native database, and exercises real OAuth refresh issuance/validation across two reopens. Preparation retry preserves the approved public point; missing private material, forged endpoint, and wrong peer identity deny; original grant replay remains denied across reopen. The test retains its test private-key store: it does not claim process/OS secure-store persistence. Local fixture state copying is not public security transport/import.
- `IdTokenClaims` and issued ID tokens now require signed `principal_key_id`, independent of Node signer identity. A red regression observed the missing binding, then exposed duplicate flattened `sub` serialization; canonical subject serialization and typed profile roundtrip are fixed. Owner-local `verify_token_principal` accepts a valid ID Principal, rejects missing/wrong signed root binding and locally learned root rotation/revocation, and an unaware independent verifier deliberately retains its prior view. Access-token validation still rejects ID tokens. This is not a complete relying-party OIDC audience/nonce/session validator or immediate offline revocation guarantee.
- `PublicSecurityTable::permits_record` now requires the complete projected SQL column set with explicit nullable fields; validates UUID identities/UUIDv7 primary IDs, signed integer versus text types and required non-null columns; validates public JWK SQL text and public point; and rejects secret fields, embedded private scalars, raw grants, unknown fields, malformed types and omitted lifecycle columns. Schema-derived tests cover every allowlisted table and actual column/type declarations. Corrected consent `scope`, added consent revocation/details, and added authorization-code User/details columns. Removed obsolete permissive partial-record test rather than retaining misleading assertions. **Projection is not provenance, a partial update format, safe opaque CRDT-history export, or trusted import/apply authorization**; indexes/dependencies/domain semantics and authenticated execution checks remain 02/03.
- Enabled the existing `serde_json` dependency alloc feature for the new ID-claim serialization path; no new dependency or authority compatibility fallback.

#### Focused verification

| Command | Outcome |
| --- | --- |
| `cargo test -p idp-server --lib live_idp_listener_issues_and_introspects_service_tokens` | Red reproduced 403 missing local signer; final green 1 passed, 46.19s (after explicit listener shutdown cleanup). |
| `cargo test -p idp-service --features replica id_tokens_bind_the_principal_root_for_owner_local_verification` | Red missing signed root, then duplicate subject; green after fixes. Final expanded binding/profile/rotation/revocation coverage also passed throughout the feature matrix. |
| `cargo test -p idp-service --features replica projections_` | Red missing-column/type acceptance; green after schema cutover. Final matrix includes complete typed record and actual-schema tests. |
| `cargo test -p idp-service --features replica persisted_node_binding_reopens_for_real_offline_issuance_and_rotation` | Final 1 passed, 20.63s, including restored binding/private capability checks, persistent peer admission, real issuance and replay denial across both reopens. |
| `cargo hack test -p idp-service --feature-powerset --all-targets` | All 10 combinations passed; final replica combinations 40 tests, non-replica combinations 10. An initial no-default-feature test UUID generator/import issue was fixed, then the entire matrix rerun successfully. Final additional peer-admission assertions were separately rerun with the focused reopen command above. |
| `cargo clippy -p idp-service -p idp-model --features replica --lib -- -D warnings` | Passed. |
| `cargo check -p idp-server -p unified-server --all-targets` | Passed. |
| `cargo check -p idp-model --all-features` | Passed with existing tsify ABI deprecation warnings. |
| `git diff --check` / cached diff check | Passed; changed Rust files formatted with `rustfmt --edition 2024 --config skip_children=true`. |

#### Remaining gaps and unsuccessful broader checks

- **04 production wiring blocker:** source audit still finds no production calls to `prepare_node_signer`. Setup/join must explicitly prepare/approve/persist the binding and endpoint/secure material as specified in committed `crates/idp-service/docs/local-security.md`. Unconfigured production issuance intentionally fails closed. No whole-setup work or authority fallback added.
- Completed-host/process/OS keyring restart (04/07/08), authenticated security import/apply/provenance (02/03), and live reconnect/partition qualification (08) remain unproven. No globally immediate revocation or globally single-use grant guarantee is claimed.
- `cargo check -p idp-model --no-default-features` remains blocked by unchanged `crates/key/src/derived_key.rs`: missing alloc `String`/`ToString` imports. Initial serde_json alloc-feature failure was addressed because the new serializer needs allocation; unrelated key implementation was not changed. Passing service feature tests does not establish standalone model no_std qualification.
- Expanded `cargo clippy -p idp-service -p idp-model -p idp-server --all-targets -- -D warnings` fails on existing items-after-test-module diagnostics in `idp-model/src/model/device.rs` and `idp-service/src/oauth2/config.rs`; including idp-server in the lib-only lint also fails on existing useless router `.into()` in `idp-server/src/runtime.rs`. Focused changed production libraries pass as recorded above; no lint suppression added.
- `just crap` was retried and timed out after 120 seconds during workspace coverage compilation; no score produced. Earlier broader model/Management fixture failures remain recorded above and were not resolved by this follow-up.

This fixes the specific review findings without declaring full ticket 01 or downstream acceptance complete.


## Answer

### Disposition — resolved local foundation, not full offline-first acceptance

Re-audited on `offline-first-local-identity` after merging current integration **first**. `git merge --no-edit offline-first-nodes-integration` fast-forwarded `ea8d6e2861586259c964c0959a348a1d66219184` to **`e7526fecc9ff570838e685eb9d37103d81d3df45`**, which already contains both 01 implementation commits and the public-facade IdP/Management cutover. Original ofdb is **`25b92516df6ef884d9cdf723da65c64568acdbd0`**. Tests below use the original sibling sources through existing worktree symlinks: no path overrides or owner edits. No remaining 01-owned behavior gap was identified; no source fix/new implementation commit is needed.

Audit risk: security-sensitive acceptance boundaries (high consequence), low source-change risk because no implementation changed. Prior claimed status overblocked the local foundation on downstream setup/host/provenance work. This resolution supersedes earlier claimed dispositions and unqualified-listener/model-fixture notes; historical test results remain historical, not silently replaced with current results.

### Criterion-by-criterion local evidence and downstream split

| Criterion | Checked ticket 01-owned behavior and evidence | Explicit downstream work, not a reverse dependency |
| --- | --- | --- |
| 1. Equal local operations | Source audit finds no `require_authority`, `IdpRole`, `ReplicaReadiness`, restart/freshness/promotion gate in IdP/Management/unified implementation. Retired role config is rejected. Separate owner stores and authenticated owner endpoints remain. Unified composition injects Management local policy; standalone supports a separate local policy data root. | 04 removes obsolete deployment/setup/join paths; 06 finishes public naming/config/client cleanup. Remaining replica module/feature/route names are not designated-writer restrictions. |
| 2. Local authorization | Real unified HTTP administration covers allowed identity/client/consent and role/permission operations, wrong actor/action/target/audience, service/User impersonation and denied mutations. Real listener signer lifecycle proves missing grants deny and local grants allow exact enrollment/retry/rotation/revocation. Administration succeeds after Management HTTP stops because local policy persists; local evaluation errors/missing evidence still deny before mutation. | 03 qualifies actual SQL/KV/filesystem apply/write and existing-connection execution policy; 05 owns Device resource/selection/transfer behavior. |
| 3. Durable trust/policy and conflicts | Native configuration/binding/store reopen reconstructs actual owner services and issues/validates OAuth tokens offline. Local policy survives reopen with wrong actor/action/target denial. IdP conflict tests fail closed until explicit owner resolution; grant revocation cannot be resolved back to null. Management public-facade restrictive-conflict/reopen regression now passes 5/5 observed runs with original owner fix. | 04 persists production setup completion/endpoint/binding and restores runtime admission; 07/08 qualify real OS secure storage, process/full-host restart and live integration. Native persisted binding is sufficient local 01 evidence, not OS evidence. |
| 4. Independent private signers and safe records | Independent signer/Principal/transport identities, signer uniqueness, exact retry/conflict, approved Device/Installation/endpoint/issuer/expiry binding, private-to-approved-public matching, and public-only verification are covered by passing service/listener tests. Complete typed projection allowlists reject secret/private/raw grant material. Production mixed security-history exchange is disabled rather than exporting secrets via opaque CRDT state. | 02 must deliver safe dependency/conflict/tombstone-preserving history exchange; 03 must authenticate provenance and authorize actual import/apply. Public projections/preflight are not import permission. |
| 5. Token security and issuance | All service tests pass for independent user/client issuance, signature/issuer/audience/use/lifetime/client/scope/Principal/signer checks and learned Device/signer/client/root denial. Signed access/refresh/ID `principal_key_id` preserves local root rotation/revocation independently of Node signer. Live lifecycle preserves secret rotation, key revocation, permissions and impersonation denials. ID-token owner Principal verification is not a complete relying-party OIDC validator or revocation guarantee for an unaware offline client. | 04 wires production signer preparation/approval/configuration. That consumes the already qualified issuance contract, not a missing authority fallback. 07/08 cover host credential delivery/propagation and live integration. |
| 6. Local grant atomicity | Code/refresh concurrent tests have one local winner; native replay/rotation denial survives reopen. Missing local signer does not consume a code. Separate partitioned stores can each consume/rotate their prior local grant view; later local replay denies. No designated consumer, global lock, or global partition single-use guarantee. | 08 proves these accepted semantics with independently running full Nodes and live partition/reconnect. |
| 7. Security/grant reconciliation contracts | Allowlisted hashed grant lifecycle and public identity/policy fields are defined and schema/type checked. Unresolved security conflicts deny; explicit authorized owner-local resolution cannot null consumed/revoked timestamps. Reconnect cannot retroactively undo partition issuance. These local contracts/tests define reconciliation semantics without enabling unsafe mixed-history transport. | 02 supplies safe actual history exchange/import integration; 03 supplies provenance and operation authorization; 08 supplies live reconnect/revocation evidence. |
| 8. Domain-focused coverage/owner boundaries | Current focused tests use actual IdP/Management owner services, native binding/policy reopen, public SQL facades, authenticated HTTP and independent Node stores/signers. Wrong actor/action/target/audience, missing/corrupt/conflicted trust, learned revocation and accepted divergence are tested. Generic persistence stays in ofdb; the integrated 02 cutover removed backend-owned implementations from of. | 08 owns final live full-Node and full-workspace/platform gates. Generic ofdb/offs qualification remains with owners. |

### Current focused commands and results

All test commands below ran in `/home/nathan/code/rust/aicacia/of/.worktrees/local-identity` at `e7526fe`, against original ofdb `25b92516`. **Test environment: `RUST_MIN_STACK=16777216`**, the documented facade-cutover test-thread setting, supplied explicitly via `env`; no Cargo source overrides. No security assertion, integrity check or test was disabled.

| Command (tests prefixed with `env RUST_MIN_STACK=16777216`) | Observed result |
| --- | --- |
| `cargo test -p idp-service --features replica --lib` | 40/40 passed, including persisted binding/real offline issuance/reopen, grant concurrency/replay, independent signers, accepted partition divergence, typed/schema projection and signed ID-root checks. |
| `cargo test -p idp-model --features replica --lib` | 14/14 passed, including security fail-closed/conflict resolution, revocation non-resurrection and current schema initialization. Earlier UUID fixture failure is superseded for this suite. |
| `cargo test -p management-service --features replica --lib local_policy_survives_reopen_and_denies_wrong_actor_action_and_target` | 1 passed. |
| `cargo test -p management-service --features replica --lib policy_sync_is_context_local_and_explicitly_allowlisted` | 1 passed. |
| `cargo test -p management-service --features replica --lib public_facade_preserves_owner_denial_and_restrictive_resolution_after_reopen` | 5 separately executed repetitions passed (one initial plus four further runs). This consumer regression no longer reproduces the earlier intermittent owner delta error in these runs; not a substitute for full owner sync qualification. |
| `cargo test -p idp-server --lib live_idp_listener_issues_and_introspects_service_tokens` | 1 passed, 53.08s; trusted independent signer and local policy, user/client issuance, introspection and lifecycle denials. |
| `cargo test -p idp-server --lib authenticated_security_projection_rechecks_local_trust_and_rejects_secrets` | 1 passed, 5.32s; authenticated connection preflight, native trust reopen, forged member/Installation and secret/history rejection, learned revocation. Still not an import/apply API. |
| `cargo test -p unified-server --lib normal_permission_http_administration` | 1 passed, 184.97s; local policy remains usable after Management HTTP stops. |
| `cargo test -p unified-server --lib normal_identity_and_infrastructure_lifecycle` | 1 passed in its isolated rerun, 123.53s; root/client/key/security lifecycle preserved. |
| `cargo clippy -p idp-service -p idp-model -p management-service --features replica --lib -- -D warnings` | Passed. |
| `cargo check -p idp-server -p unified-server --all-targets` | Passed. |

Qualification limits reported, not erased: the initial IdP-service command with the default test-thread stack aborted in `public_keys_survive_native_reopen_without_secret_store` with stack overflow; the documented 16 MiB test-thread setting passed. The combined three-HTTP-command run reached its overall 600s tool limit after the listener and administration had passed, interrupting lifecycle without a result; isolated lifecycle subsequently passed. No default-stack/platform qualification or newly rerun full powerset/workspace/CRAP success is claimed. Earlier no_std/expanded-Clippy/selection-fixture/CRAP gaps remain full-workspace follow-up evidence for 08, not missing local 01 behavior. Previous powerset passes retain their recorded revisions; the current commands above are the merged-source qualification.

### Downstream handoff (no completion cycle)

- [04 setup/join](04-equal-node-setup-join-and-desktop.md): use the committed `KeyService::prepare_node_signer` → approved Device/member/public-signer owner state → persisted `OAuth2Config.local_signer` and stable endpoint/secure-store references sequence in `crates/idp-service/docs/local-security.md`. Production calls are still absent and unconfigured issuance intentionally fails closed. Implement restricted/retry-safe completion, equal-Node join, actual host restart and admission restoration. **04 depends on the resolved 01 contract; 01 does not wait for 04.**
- [07 runtime/OS operations](07-node-operations-and-runtime-lifecycle.md) and [08 real Node acceptance](08-offline-node-integration-and-final-validation.md): prove real OS keyring/process/host persistence, TLS/endpoint lifecycle/allowlist updates, recovery, live partition/reconnect and final workspace gates. Retained test private storage is explicitly not that proof.
- [02 persistence/sync integration](02-public-persistence-and-sync-integration.md) and [03 execution authorization](03-execution-boundary-authorization.md): consume the complete typed allowlists and local trust/conflict/grant contracts; deliver safe public security history and authenticate connection provenance plus actor/action/target immediately before actual apply/write. Never export opaque mixed IdP/Management history or assume convergence establishes authorization.

Only 01 is resolved. No downstream ticket or full spec acceptance is resolved by this answer. No new implementation commit: branch HEAD is integrated `e7526fe`; implementation commits remain `ed8fa2b` and `ea8d6e2`. Integration branch and original modified domain documents were not edited.

Pre-existing worktree `Cargo.lock` delta was preserved before the merge in named stash **`23d034730a9ff0bd467092da1cc266eb3c758a2b`** (message: Preserve pre-audit local Cargo.lock before ticket 01 integration merge). Its removal of the retired ofdb-sql-sync iroh edge is already represented by the current integration lockfile; the stash remains available and was not blindly applied over the new lockfile. No existing user work was discarded.
