# 08 — bounded two-completed-full-host slices (compiled; runtime qualification blocked)

2026-10-11. **Source compiles; none of the three two-Node qualification slices passed. One narrow single-full-host diagnostic passed; its four-extra-service-Client control reproduced the Management HTTP timeout.** The authorized shared-target runs reached authenticated same-Installation join and both completed full hosts, but unchanged fixture HTTP deadlines blocked refresh replay and Management policy mutation before offline reopen or authenticated reconciliation. No learned-denial, completed offline-mutation/issuance, retained-socket denial/cleanup, GREEN result, Clippy pass, or ticket acceptance is claimed. Latest tested two-Node source: `19db0df9e124c626bde56cde99d7133e3ab3e8b0`; run06–08 retain their failed qualification results. Narrow diagnostic sources/results `d1e5319` and `fc28292` are recorded at the end. TDD and ponytail skills loaded; the user explicitly selected these production seams. No root claim/status/map/spec/closure edit or root merge was made.

## Source provenance and boundaries

- Worktree: `of/.worktrees/ticket08-full-nodes`.
- Branch: `offline-first-ticket08-full-nodes`.
- Created directly from `offline-first-nodes-integration`, exact base `db50c751a9d994eaac4d83de78306d71eb1d4210`.
- `git merge-base --is-ancestor db50c751a9d994eaac4d83de78306d71eb1d4210 HEAD` returned 0 before implementation and before publication. Both branch tips equalled the base at creation. No integration/root merge.
- Read the current [spec/policy](../spec.md), [ticket08](../issues/08-offline-node-integration-and-final-validation.md), [map](../map.md), shared glossary/map, existing production provisioning/bootstrap/runtime seams, and the concrete inherited evidence below. 04/07 resolution at this base is recorded in the map; it is not new08 runtime evidence.
- Complexity: high integration-fixture complexity; risk: high authorization/false-positive/lifetime risk; priority: the outstanding same-Installation full-host seam. No production defect is proven; **no production behavior was changed**. `runtime.rs` gains only a Unix/test child declaration; that dedicated child exposes the existing shared Server for authenticated test connections, not another endpoint/router.
- Only Unified Server test/helper files, necessary declarations, and this evidence file are committed. Existing rotation test passes its original grants/audience explicitly to its reused login helper; its behavior is intended unchanged, not revalidated.
- Existing owner-repository paths use the already present `.worktrees/{ofdb,offs,ofnet}` links to original owner repositories. No manifest overrides, new dependency, networking implementation, owner writes, provider/system/profile/CA operation, root dirty-file edit, broad sweep, or cleanup.

## Original agreed seams and test design — superseded by bounded decomposition below

Exact test: `local_provisioning_tests::full_nodes::two_completed_full_hosts_join_partition_reopen_and_learn_denial`.

One Installation creation, one production authenticated join, one stop/offline-reopen cycle, one authenticated reconnect. No repeated setup journeys or owner matrix. The only concurrency probe is two refresh requests against one local store. Internal test bound **360s**; no existing timeout is increased. Runtime/performance headroom is unknown until the authorized run. On timeout, inspect phase progress and narrow the slice; do not widen the bound to hide a failure.

1. Reuse `local_provisioning_tests::Fixture` and restricted `LocalProvisioner::{create,provision,build_runtime}` for A only. No second unrelated Installation, private-store/database copying, unchecked public-row seeding, or fake completion journal for B.
2. Distinct IdP/Management/Storage/endpoint roots, endpoint identities, key namespaces, local relationship Client IDs and secrets. Two separate fixture credential stores. Because production keyring injection is process-global, a test-only dispatcher routes exact namespace-prefixed credential requests to those separate stores and rejects unknown namespaces. Source and joiner private inventories must be nonempty, disjoint, and unchanged by offline reopen. This is fixture-provider evidence **only**, not real OS-provider availability/security qualification.
3. Source grants use real public provisioning/owner APIs. The login Client is public (no copied confidential secret); three real refresh grants are issued before bootstrap. Two separate public User rows are identity-mutation targets, avoiding concurrent edits to the active join approver/actor row. Exact Installation Device restriction grants are explicitly provisioned, not a permissive authorization callback.
4. B uses `UnifiedEndpoint::open_fresh`, `SecurityProtocol::open_node_bootstrap`, independent `OwnerProvisioner` secret preparation and `prepare_node_join`. Send the actual request over authenticated pairing to A's actual shared endpoint address. Observe the real pairing delivery, deny forged-bearer approval, approve through UnifiedRuntime's production pending-offer API, verify the pinned reply, and persist its receipt. Receipt alone must not publish readiness or admit ordinary DATA. Import both public contexts through `receive_node_bootstrap`; then `complete_node_join_public_bootstrap` and current signer checks. Public registration templates alone are reused for B's independently provisioned local service relationships.
5. B starts actual IdP/Management/Storage through `UnifiedRuntime::build`, with durable joined public readiness and explicit local Device policy. Both `Host` instances use the production composed router/listener and `start_background_tasks` shared protocol wiring. Check current public readiness and each context's actual HTTP health before declaring a full host. Bootstrap-public completion alone is **not** treated as Storage/full-host completion.
6. Learn B's ready policy through authenticated DATA/Management synchronization, explicitly close that connection, then qualify a controlled **domain-protocol partition**: there are no security sync sessions until the explicit reconnect. This is not OS network isolation or air-gapping; endpoints remain same-host and background generic mesh work is not proof of transparent DB/FS sync.
7. Both hosts independently race two requests against the same previously learned refresh grant: exactly one local HTTP200 with a replacement, the loser and local replay must be client-error `invalid_grant` (not503/server failure). Both partitions succeeding is the accepted absence of global single use. A separately consumes another learned grant and revokes a third through real OAuth. Stop both hosts normally and await managed runtime/listener shutdown.
8. Reopen both through `LocalProvisioner::open_runtime` without peer lookups: A retains its completed journal; B takes the existing-only joined path, verifies retained Storage roots and its exact signer, and must not synthesize a fresh Installation journal. Require persisted endpoint/public readiness, unchanged private stores, both approved signer IDs in each locally served JWKS, and durable local shared-grant replay denial.
9. Independently after offline reopen, issue real User tokens by token exchange and real local confidential Client tokens, mutate distinct identity targets through IdP HTTP, mutate distinct Device restriction rows through Management HTTP, and create/write/read distinct resources through Storage HTTP/WebSocket. Each own Device remains allowed under its prior local view although the other partition has restricted it. Each local catalog lacks the other independently created resource ID. No remote authority or mock policy server is involved.
10. Authenticated DATA reconnect uses the persisted endpoints. IdP exchange must reconcile both identity edits and grant consumption/revocation. B's untouched consumed/revoked target grants must then deny. Management exchange must learn restrictions on both local Devices. **Retain the resource sockets across this exchange**; the next write must fail/close with no successful write result. Restore allowance through the real owner API, reopen resource access, and read the exact earlier bytes to prove the denied write did not replace them. Delete through the public Storage API and check404; normally shut down/await both hosts.

### Sensitivity and scope limits

The original design below describes intended assertions, not completed qualification. Runs below stop before the remaining acceptance assertions. Planned sensitivity checks after successful baseline qualification: removing local consumption serialization should violate one-winner/replay assertions; suppressing the authenticated IdP reconnect should allow B's untouched consumed/revoked grant (violating expected denial); suppressing Management reconnect should preserve true local allowance and permit the retained-socket write. No such negative/control run was performed.

This increment uses a previously learned **refresh grant**, not a new authorization-code matrix. It adds a representative retained **local resource WebSocket** learned-restriction/next-write check and public local deletion receipt, not new SQL/KV/FS Iroh apply/batch gates or physical managed-copy-removal receipts. Transfer/deselection cleanup propagation, authorized in-flight completion, first committed KV batch, staging/handle drains, cancellation and Tombstones reuse inherited03/05/owner evidence below. It does not claim new full-host selected-resource DATA/content synchronization, cross-user grants, globally immediate revocation, globally single-use OAuth, remote erasure, WAN/relay/physical-device, GUI approval, real-provider or crash/power-loss qualification.

Owner API calls are actual loopback HTTP/WebSocket and authenticated Iroh. UnifiedRuntime's loopback listener is HTTP, not HTTPS. Existing07 TLS/explicit-CA evidence is inherited, **not relabeled as a new full-host HTTPS run**; no TLS/provider dependencies or system trust changes were added. Test-only credential routing is not mocked identity/permission evaluation. Ordinary successful stop awaits managed runtime and HTTP task; panic fallback cancels/aborts its listener, not proof of OS process exit or every detached owner-task guarantee.

## Inherited evidence — read, not rerun

- [ofdb05](../../../../ofdb/.scratch/storage-sync/issues/05-local-regression-qualification.md#final-broad-qualification--resolution): resolved owner-local integrity/atomicity/recovery/cancellation/writer-progress/feature qualification, exact final source `38696d981e88bcfe20a475f49eb514f498f29b75`; concrete01–04 results inherited through that ticket. Historical581-combination pass and CRAP coverage/warning limitations retain their original meaning; no owner harness or powerset/CRAP rerun by08.
- [offs03](../../../../offs/.scratch/filesystem-sync/issues/03-iroh-extraction-offline-reconnect.md#answer): resolved extraction acceptance at verified original `of e7526fe`, `offs 516b692`, `ofdb 25b9251`; actual moved consumer filesystem transport6 and Storage50 passes, real authenticated same-connection reconnect plus metadata/byte reads and handle/stream/task cleanup. Controlled callbacks there do not become full-Node policy evidence. offs01–02 retain their generic admission/content integrity acceptance.
- [of03 completion](03-completion/README.md): exact public SQL/KV/FS execution hooks, native real-owner/Iroh queued-send/apply checks, explicit prior KV commit, admitted completion and subsequent denial, reconnect/source preservation, namespace and task-lifetime fixes. [of03 ticket](../issues/03-execution-boundary-authorization.md) records resolved current criteria; historical pending notes in original evidence are not new blockers. The public API/bearer versus Device-policy distinction is retained.
- [of05 ticket Answer](../issues/05-device-policy-catalog-and-cleanup.md#answer), [review](policy2000d0a-review/README.md), [completion audit](05-completion/criteria.md) and [Tombstone correction](05-completion/p1-completion.md): accepted real public owner retirement/drain/retry/reopen, generation fencing, policy/transfer/deselection/Full-peer boundaries; implemented `2000d0a` plus `4936146`, integrated before this base. The original implementer audit's pending-review language is historical. Whole-resource cleanup is inherited from these actual APIs/results, not inferred from staging cleanup or this test's404 response.
- [04 local transitions](04-local-transitions.md), [07 audiences](07-desktop-audiences.md), [07 TLS paths](07-tls-paths.md), [07 lifecycle](07-lifecycle.md), [07 recovery](07-recovery.md): resolved bounded production join/readiness/reopen, listener/audience/TLS/runtime/recovery slices at this integration base. Deferred GUI/platform/provider/deployment limitations remain explicit.

Some inherited evidence directories are ignored and exist in the coordinator's original checkout, not this new worktree. Links identify those original reviewed records; this commit does not copy or requalify them.

## Actual static validation

Run in `of/.worktrees/ticket08-full-nodes`:

```sh
rustfmt --edition 2024 --config skip_children=true --check crates/unified-server/src/full_node_tests.rs crates/unified-server/src/full_node_runtime_fixture.rs crates/unified-server/src/local_provisioning_tests.rs crates/unified-server/src/runtime.rs
python3 scripts/check_server_dependencies.py
git --no-pager diff --check
git --no-pager diff --exit-code -- Cargo.lock Cargo.toml crates/unified-server/Cargo.toml
```

Formatting/whitespace checks passed, including the final evidence handoff. Existing boundary checker returned `No direct server-to-server dependency edges found.` Manifests/lock unchanged. Ancestry from the exact integration base returned0 again. Rust type checking subsequently succeeded in the authorized runs below; all three exact tests ran and failed. No Clippy, full Cargo Hack, CRAP or all-workspace gate was run.

## Exact authorized bounded command

The initial fresh-target/profile-override proposal was superseded and is not a rerun recommendation. Actual run06 from `of/.worktrees/ticket08-full-nodes` used:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-full-nodes-06 --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::full_nodes::two_completed_full_hosts_join_partition_reopen_and_learn_denial -- --exact --nocapture --test-threads=1
```

Outer tool bound910000ms; internal360s scenario bound; unchanged10s fixture HTTP deadline. Run07/08 used the same properties/environment/shared target with their exact independent test names and distinct unit names, preserved verbatim in the logs. Memory was checked before each run (approximately3.3–3.4GiB available, host swap effectively full). No target cleanup, cache copying, fresh target or profile overrides. Do not count a build-only completion, zero matched tests, timeout, or inherited pass as success. If a production defect is demonstrated, report/coordinate the exact owner fix rather than changing production under this test-only assignment.

Coordinator retains root claim, integration, review, acceptance/status and final bounded-validation decisions. This is a source/evidence handoff, not ticket08 closure.

## Authorized shared-target execution — initial results

The coordinator granted the exclusive Rust slot and superseded the initial fresh-target/profile-override proposal. All runs use shared original `of/target`, standard profiles, flags unset, jobs1, offline/locked, systemd MemoryMax4G/MemorySwapMax0/RuntimeMaxSec900 and tool910000ms. First memory check: MemAvailable3.4GiB, host swap effectively full; no unrelated process/provider/system changes.

- Run01/source `1fc2856`: compile failed E0618, local HTTP revocation response shadowed the socket response helper; no test executed. Service377.685s, exit101. Fixed only that test binding in `9bb416c`; no production change.
- Run02/source `9bb416c`: compile succeeded (test profile optimized+debuginfo,277s), exact test1 failed at26.36s before source startup. The initial-administrator provisioning API correctly rejected a fixture permission list missing both mandatory pairing actions. Replaced that incorrect additive use with ordinary public ManagementService create-permission/attach-to-existing-role operations for just the two intended restriction actions. Nonsecret source/join phase markers added; no timer increase. Service303.619s, exit101.
- Detailed commands/output retained in `08-full-nodes-run01.log` and `08-full-nodes-run02.log`. Systemd printed implausibly low MemoryPeak values (256/512KiB); do not infer actual process memory usage from those accounting numbers. Swap peak reported0. The enforced requested properties and command are recorded in each log. Subsequent attempts are recorded below; no runtime acceptance has been achieved.

### Run03 timeout diagnosis and bounded decomposition

Run03 at stable `27e9902` compiled (200s), then exact1 failed at363.74s on the unchanged360s internal bound; service564.403s, exit101. Nonsecret markers establish: source ready26.93s, source listener45.65s, join entered59.37s, IdP import completed86.40s after join began, Management import142.77s, BOTH full hosts ready247.51s, preliminary ordinary Management sync/partition reached347.61s. No completed grant/reopen/reconnect acceptance is inferred. `08-full-nodes-run03.log` preserves the failure; no production stall or defect has been demonstrated by those progressing owner sessions.

The original single aggregate/design/command above is now **superseded** by three independent360s tests sharing ONE production join fixture helper:

- `two_completed_full_hosts_join_partition_reopen_and_learn_denial`: no ordinary security DATA exchange; both completed hosts independently consume the previously learned refresh grant with local races, stop/reopen using retained stores, deny durable local replay, serve approved JWKS, and independently mutate identity/policy/resources and issue User/Client tokens offline. Distinct local views of the same owner's display name are acceptable here; this slice does not attempt reconciliation of those competing edits. Each successful resource connection is closed and resource deletion checked before ordinary managed shutdown.
- `two_completed_full_hosts_reconcile_consumption_and_revocation`: independently created pair, same production join, previously learned three grants, sequential local consumption/replay and accepted partition divergence (concurrency remains in the offline slice), A-only consumption/revocation followed by one authenticated IdP DATA exchange and B denial. Persisted offline reopen is separately qualified by the first test, not duplicated here.
- `two_completed_full_hosts_learn_restrictions_on_retained_sockets`: independently created pair, same production join, divergent Device restrictions/Full local resource writes, one authenticated Management DATA exchange while retaining both resource sockets, subsequent-write denial and restored-read earlier-byte preservation/public deletion. No extra IdP exchange/restart or generic SQL/KV/FS matrix.

Remove the unnecessary preliminary ordinary Management exchange and two extra public User fixture rows. The source initializes the approved joined Device's empty policy through the existing public provisioning API AFTER authenticated approval, BEFORE the public Management import; B imports that current policy through production bootstrap. No copied native/private stores or unchecked policy bytes. Each scenario provisions only its required extra restriction actions/grants; normal owner checks are unchanged. Source/peer stops and existing-only reopens in the offline slice may run concurrently against their isolated roots. Each exact test can run alone with a fresh pair; no ordering/shared-pair assumption. All360s bounds remain unchanged. This is test decomposition, not a larger aggregate timeout or a successful test claim.

Run04 at `1ff0b6b`: compilation succeeded266s; exact offline slice failed62.83s after genuine approval, before imports. The fixture called management-server's stopped-store provisioner while the full source already held its native Management engine, correctly receiving `Database already open. Cannot acquire lock.` Corrected to use the existing test-only host Management handle and the SAME public `DbSelectionPolicyRepo` API consumed by that provisioner, after exact actual approval owner/member/endpoint assertions and an absent-policy assertion. The fixture initializes only the approved Device's empty initial policy; it does not reopen a live database, bypass request authorization later, relax native locks, or change production. Service329.395s, exit101; preserved in `08-full-nodes-run04.log`.

Run05 at `30c36d1`: compile succeeded192s; source+joined authenticated imports and full-host readiness completed231.12s. Exact offline slice failed250.81s on the unchanged10s fixture HTTP timeout during local refresh redemption, before the offline reopens. No authentication defect or false permission finding inferred from a transport timeout. Service443.433s, exit101; `08-full-nodes-run05.log`. Added refresh node/status/elapsed and source-A/joined-B race markers without logging grant/bearer/secret values, and stopped/reopen markers. Bounds unchanged; no production change. The independent grant reconciliation slice now does sequential single-use/redemption/replay checks instead of repeating the offline slice's local concurrency probe; accepted cross-partition success remains asserted.

## Current runtime results — run06–08 at stable source `19db0df`

All runs used the exact limits/shared target above and exited101. Each ran exactly one test (0 passed,1 failed,75 filtered), not a matrix. Complete output is retained in [run06](08-full-nodes-run06.log), [run07](08-full-nodes-run07.log), and [run08](08-full-nodes-run08.log).

| Run / independent slice | Compile      | Two full hosts ready | Test duration | Service duration | Actual failure                                                                    |
| ----------------------- | ------------ | -------------------- | ------------- | ---------------- | --------------------------------------------------------------------------------- |
| 06 / offline            | 206s         | 258.009s             | 282.01s       | 488.695s         | Joined-B refresh competitor transport timeout10.853s, before stop/reopen          |
| 07 / grants             | 1.48s (warm) | 251.043s             | 274.08s       | 275.709s         | Joined-B sequential refresh replay transport timeout10.002s, before IdP reconnect |
| 08 / restrictions       | 0.39s (warm) | 263.477s             | 278.41s       | 278.909s         | Real Management restriction PUT `TimedOut`, before Management reconnect           |

### Observed behavior versus unqualified assertions

- Run06 source-A local race returned200 at3.412s,400 at6.963s, then replay400 at3.492s; the helper's `invalid_grant` checks completed. This is source-A local one-winner/replay evidence only. Joined-B returned200 at5.454s, but its competitor timed out: **no B losing/replay denial response was observed**. Both partition-local success responses for the same previously learned grant were observed before the failure; this is accepted divergence, not global single-use enforcement.
- Run07 source-A sequential redemption returned200 at3.007s and replay400 at3.290s. Joined-B redemption returned200 at5.621s, then its sequential replay timed out. The B timeout therefore reproduces without the local concurrent-race probe; it is not established to be merely concurrent serialization overhead. No B replay denial, later A-only consumption/revocation, IdP authenticated reconnect, or learned denial is qualified by this run.
- Run08 reached both full hosts but the real Management restriction mutation request timed out. The log does not explicitly label its source host; no host-specific cause is inferred. No divergent restriction completion, retained resource-write result, Management reconnect, next-write denial, restored-byte preservation, or deletion/cleanup propagation is qualified by this run.
- All three runs reached the fixture's production authenticated join, both public imports, current public completion checks and local IdP/Management/Storage HTTP health checks. That partial progress is **not** a passed journey, OS-provider qualification or new HTTPS evidence.
- Offline reopen, unchanged-private-inventory reopen assertions, post-reopen identity/policy/resource mutations and User/Client issuance remain **unreached**, as do consumption/revocation reconciliation and retained-socket learned denial. Inherited03/05 cleanup evidence retains its original meaning and cannot fill these missing08 observations.

### Bounded diagnosis / owner handoff

Read-only inspection of IdP refresh handling found replay detection in the refresh issuance/rotation path: previous-row lookup, issuance eligibility, native transaction, conditional consumption update, rollback on zero updates and `invalid_grant`. No internal stage timing or blocking location was measured. Do not attribute the timeout to rollback, infer a deadlock, call it authorization denial, or alter production speculatively. The Management PUT traverses real actor introspection/permission/Device lookup/policy handling; only its HTTP timeout was observed.

The next useful step is a coordinated focused diagnosis of joined-B refresh replay latency and the independent Management PUT latency, preserving the10s client and360s scenario bounds. Another identical full journey adds little evidence. No timer inflation, assertion removal, production workaround, private-store copying, generic owner matrix, or system/provider mutation was made. No additional Rust invocation follows these three failures in this handoff; shared build artifacts are retained.

Source reviewer can use stable `19db0df9e124c626bde56cde99d7133e3ab3e8b0` for the tested implementation, together with this evidence commit. Coordinator retains claim, review, integration and acceptance/closure; ticket08 remains blocked, not resolved.

## Read-only request-path diagnosis (historical; followed by authorized narrow probes below)

### Exact request identities and wiring

The stable source now resolves the run08 host ambiguity: `full_node_tests.rs:1148–1160` loops source-A first, obtains a Management-targeted token, then immediately awaits the PUT. The panic is inside that PUT, so **source-A's first PUT targeting joined-B's Device** failed; joined-B's own restriction iteration had not begun. This is a source-trace deduction, not an additional runtime phase measurement.

`UnifiedRuntime::build_on_listener` (`runtime.rs:201–239`) injects `LocalPermissions` from the existing Management engine, clears `idp_config.control_plane_uri`, and builds all HTTP service bases from that host's actual loopback listener plus `/idp/`, `/management/`, `/storage/`. The issuer is a claim/trust namespace, not the outbound IdP HTTP base. `with_permission_evaluator` stores an allowed evaluator Client ID, not an HTTP broker callback. `LocalPermissions::evaluate` (`management-service/src/local_permissions.rs:22`) directly invokes the owner service on that engine. No configured IdP→Management→IdP permission-HTTP recursion is present in these full hosts.

Joined-B's registration loop (`full_node_tests.rs:411–425,570–579`) uses the same ordering as `local_provisioning.rs:590–625`: Management→IdP, Storage→IdP, Storage→Management, IdP→Management. It changes only Client IDs/secrets in the public templates. Source/B audiences are identical fixture constants; `runtime.rs:659–724` validates their relationships. Management→IdP retains `idp.token.validate idp.device.lookup`, IdP service audience, and permission to inspect `idp-management` and the Storage Management audience (`local_provisioning.rs:627–638`). The User Management token is issued for resource/audience `idp-management`; only the filesystem exchange adds Storage authorization details (`full_node_tests.rs:169–193`). The restriction request uses `Installation/Device{Some(remote)}` and the explicit restriction-update grant, not a Storage resource/Application permission target (`device_restriction.rs:23–42`, `permission_evaluation.rs:223–256`). There is no demonstrated URL/audience/target mismatch.

### Joined-B refresh replay trace

1. `idp-server/src/router/routes/oauth2/token.rs:13–35`: ordinary form token route; refresh without Basic auth yields `client_auth=None`. No bearer/permission HTTP extractor.
2. `idp-service/src/oauth2/service.rs:983–1047`: verify source signer and principal binding, find public login Client, validate refresh type/client/scopes, enter issuance. Public-client authentication (`1139–1188`) does not verify a password or wait for a missing local Client verifier. Principal lookup (`1371–1430,1925–1988`) reads public keys/User rows; it does not call User password lookup.
3. `1505–1594`: reload live Client/principal, load B's locally approved signer, sign access/ID/new refresh JWTs **before** consumed-state rejection. `oauth2/node_signer.rs:48–76` checks public trust, then synchronously loads the namespaced B private key. The test credential dispatcher (`full_node_tests.rs:35–46`) delegates to the exact mock store or returns `NoEntry`; no provider prompt/retry/await exists there. B's preceding200 already traversed this path successfully. That does not exclude lock latency, but missing User private/password stores are not a refresh dependency.
4. `replica/oauth2_refresh_token_repo.rs:48–134`: previous hash lookup and conflict check, native transaction, conditional consume update, zero-result rollback then `invalid_grant`. `ensure_clear` checks row conflicts, **not** consumed status. Thus a consumed grant still incurs all preceding authentication/signing work and reaches native transaction/update/rollback. No Management/Storage HTTP call occurs in this path.

Run07 demonstrates B's sequential2005.621s followed by replay timeout10.002s. It does not locate that wait inside credential read, DB admission, signing, update or rollback. A's replay completed3.290s. A permanent missing local credential cannot explain a public-client path whose immediately preceding redemption succeeds without that credential.

### Source-A restriction PUT trace

1. `management-server/src/router/middleware/management_authorization.rs:34–56` awaits `HostedControlPlane::validate_actor_token` **before the handler**. `hosted_control_plane.rs:134–230` may first acquire a Management→IdP client-credentials token, then calls local `/idp/oauth2/introspect`. The cache Mutex is released before HTTP awaits (`141–158`); no cache-lock-held HTTP recursion is apparent.
2. Introspection (`idp-server/src/router/routes/oauth2/introspect.rs:36–61`) validates the service Client bearer, checks its service audience/scope, reloads the Client allowlist, validates the actor bearer, and looks up the actor Client's Application. Both validations perform native key/User/Client/trust reads. Wrong audiences/scopes have explicit401/403-style rejection paths, not a broker wait.
3. `device_restriction.rs:29–42` evaluates exact Installation permission locally. `ManagementService::evaluate_permission` maps to `INSTALLATION_POLICY_ID` and `DbRoleRepo::has_user_application_permission`; `role_repo.rs:376–411` loads all actor roles/role-permission links/permissions and conflict-checks each relevant link and permission, not just the requested restriction grant.
4. `device_restriction.rs:44–55` calls `get_storage_device_identity`, which despite its name calls **IdP**, not Storage (`hosted_control_plane.rs:365–388`). It uses the cached service bearer and GET `/idp/devices/identities/{B}`. `devices.rs:134–190` validates the Client again and requires approved Device plus current signer membership.
5. Owner reconciliation and policy update are local Management DB operations (`selection_policy.rs:96–147,466–497` and `set_admin_allowed_prevalidated`). Existing matching owner and no cleanup marker return true; no wait-for-copy-cleanup callback is installed by this handler. Neither resource creation nor Storage grant/write handling has been entered at the failed PUT.

The outer10s client covers the sum of these steps. Inner HTTP calls also have individual10s deadlines; an outer timeout does not prove any individual nested call exceeded10s or deadlocked. Client-secret verification is synchronous Argon2 (`oauth2/service.rs:1170`); registration uses `PasswordConfig::default()` (`client_repo.rs:93–95`), not the fixture's reduced User-password configuration. This is another measurable cost, not a demonstrated denial/cycle.

### Concrete hypothesis and smallest discriminating probe

**Leading hypothesis: repeated native schema/history reconstruction and serialized DB admission, amplified by current-trust polling and the restriction route's cumulative authorization chain.** Static facts:

- `ofdb/sql-engine/src/executor.rs:32–57` opens/commits a kernel transaction even for SELECT. `engine.rs:333–338` opens/rolls back a transaction for each conflict lookup.
- `ofdb/btree-redb/src/database.rs:27–35` serializes those transactions through an async admission Mutex and calls `begin_write`; they are not independent native read snapshots.
- Conflict lookup rebuilds table/schema information (`executor.rs:1256–1260`); schema columns scan the catalog fields (`schema.rs:621–650`). Automerge documents are reconstructed from history (`sql-engine-automerge/src/codec.rs:197–224`).
- IdP key lookup scans all keys (`key_repo.rs:44–58,161–193`); signer trust repeatedly checks two Nodes' membership/signer/Device conflicts (`replica_signer_repo.rs:35–158`). B retains source public service Clients plus four independently created local Clients, so its public Client/key inventory is larger than A's.
- Both hosts run current-trust refresh after each2s sleep (`runtime.rs:41,849–866`), exercising the same IdP engine as token requests. This is contention-capable work, not proof of starvation or an HTTP broker.

These are concrete mechanisms, **not measured root cause**. Rollback latency, a leaked native transaction, or another scheduling problem remain alternatives until phase timing distinguishes them. No production edit is warranted yet.

Smallest discriminating new probe (source not added/run): a dedicated Unified Server test using ONE existing native `Fixture` + `LocalProvisioner`, public login grant, exact restriction grants, and real composed listener. No second full host/import/reopen/resources/reconnect. First issue/redeem/replay one public refresh grant. Then exchange one `idp-management` User token and perform one restriction PUT on its approved local Device. Time the same existing public boundaries separately: `verify_token_principal`, Client lookup, trusted signer/private load, refresh repo issuance/replay; Management service-token issuance, `validate_actor_token`, local `evaluate_permission`, `get_storage_device_identity`, owner reconcile, policy update. Log begin/end, elapsed, status/error category and A/local-target label only; no JWTs, secrets, request bodies or verifier hashes. Keep the10s HTTP bound and at most120s whole diagnostic bound. If standalone owner phases are fast but the composed request stalls, inspect its HTTP/scheduling boundary; if replay reaches conditional-update/rollback without returning, hand off that native transaction stage; if scans/auth phases dominate, hand off measured native/schema/auth cost. Single-node reproduction would isolate common cost, not qualify joined-B behavior. If only joined state fails, a separate public-bootstrap IdP-only probe is needed; do not invent joined readiness or copy private stores.

Ready-existing narrow baseline command, **not executed and not authorized for execution yet**, from this worktree after a memory check and slot grant:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-refresh-native-diagnostic-01 --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p idp-service --features replica --lib oauth2::service::refresh_tests::persisted_node_binding_reopens_for_real_offline_issuance_and_rotation -- --exact --nocapture --test-threads=1
```

Outer910000ms. This existing test exercises native refresh issuance/replay without composed-host background polling or Management HTTP (`refresh_tests.rs:755–870`). Its fixture persists/copies its own test key material; it is only a diagnostic baseline, **not** same-Installation join/private-store-independence evidence. It has no per-phase timing today and cannot by itself settle the joined-B timeout. Prefer the narrow timed public-boundary probe above for a causal measurement; no further giant qualification rerun is recommended.

## Authorized single-full-host diagnostic — two focused runs

The coordinator authorized at most two focused runs, with the existing shared target/standard profiles/4GiB/zero-swap/900s systemd limits and910000ms outer tool bound. Memory checked before both: approximately3.3GiB available, host swap effectively full. Neither scenario exceeded its unchanged **120s whole-test bound**. HTTP clients retain **10s**; no deadline inflation or production/persistence edit.

Owned source: `crates/unified-server/src/full_node_probe.rs`, wired as the dedicated `full_nodes::probe` child. Both probes use one native `Fixture` and `LocalProvisioner`, public login Client registration, explicit restriction grants attached via existing owner APIs, and production composed `UnifiedRuntime` plus background tasks. All three owner health endpoints return200. No second Installation, join/bootstrap/reopen, resource journey, matrix or owner baseline rerun. Method/path/begin/end/status/elapsed middleware exists only in the full-host **test helper**; it intentionally retains useful request diagnostics without queries, bodies, credentials, token values or secret hashes. No temporary production instrumentation was introduced.

### Run01 — minimal completed full host passes

Stable source `d1e5319178cb83e20c974eeec5e65f720a416b4f`. Exact test:

`local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put`

Compilation237s; **1 passed**,0 failed,76 filtered; test63.09s, systemd service300.392s, exit0. Complete exact command/output: [08-single-host-probe-run01.log](08-single-host-probe-run01.log).

- Local completed full host ready45.583s.
- Password issuance HTTP200, server1.851s.
- Refresh redemption HTTP200, server2.205s/client2.412s; replacement grant differs.
- Replay HTTP400, server1.969s/client1.970s; parsed `invalid_grant`, not outage.
- Management-targeted token exchange HTTP200, server2.141s.
- Real local Device restriction PUT HTTP204, server8.703s/client8.709s.
- Nested IdP service-token issuance2002.020s, introspection2002.759s, trusted Device lookup2001.748s.
- Normal managed runtime/listener shutdown completed63.084s.

This establishes that the baseline actual composed authorization chain works, with only approximately1.30s server-side margin under the fixture HTTP deadline. It does not qualify joined-B replay or a two-Node journey.

### Run02 — four additional independent service Clients reproduce the PUT timeout

Stable source `fc282922b194949a56341339a7c46726edbfbe73`. Exact test:

`local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put_with_extra_service_clients`

Compilation164s; **0 passed**,1 failed,77 filtered; test85.51s, systemd service250.114s, exit101. Complete exact command/output: [08-single-host-probe-run02.log](08-single-host-probe-run02.log).

The sole workload control adds exactly four service Client registrations from the existing public provisioning templates through ordinary `DbClientRepo::create_client` on the stopped native owner, with fresh distinct IDs/secrets/keys. It leaves live runtime service configuration unchanged. This mirrors B's extra service Client/key cardinality, **not** its authenticated import/history/second signer, OS provider, or completed join state. No private-store/database copying or synthetic public sync data. Both test variants share one implementation and the120s bound.

- Extra four Clients created32.748s; full host ready58.721s.
- Password issuance2002.710s server; refresh redemption2003.041s server/3.265s client.
- Replay **400 `invalid_grant`**,2.707s server/3.987s client. The exact joined-B replay timeout **did not reproduce** in this workload control.
- Management-targeted token exchange2003.190s server.
- Nested PUT calls all succeeded: service-token2003.158s, introspection2004.265s, Device identity2002.447s.
- PUT client reported `timeout=true` after12.042s with the configured10s bound. This is observed delayed timeout delivery, not a changed deadline or proof of a particular scheduler stall.
- **The same PUT then completed HTTP204 server-side at12.155s.** Its duration exceeded the client deadline; this was successful authorization/owner mutation after the client stopped waiting, not a denial, missing Device, resource grant mismatch or permanent HTTP broker deadlock.
- Probe awaited normal `host.stop()` before checking the stored PUT transport result; that result caused the assertion failure. The server204 trace was preserved before panic. Waiting for ordinary managed shutdown did not extend any HTTP request or whole-test deadline.

### Measured finding and explicit owner handoff

| Server timing                                         | Minimal inventory | Four extra service Clients |
| ----------------------------------------------------- | ----------------: | -------------------------: |
| Management→IdP token issuance                         |         2.019588s |                  3.157944s |
| IdP introspection                                     |         2.759190s |                  4.265413s |
| IdP trusted Device lookup                             |         1.747662s |                  2.447452s |
| Sum of nested IdP request intervals                   |     **6.526440s** |              **9.870809s** |
| Total restriction PUT                                 |     **8.703310s** |             **12.154562s** |
| Remaining PUT time (local work, HTTP gaps/scheduling) |         2.176869s |                  2.283753s |

Across these two runs the PUT grew3.451252s; nested IdP intervals account for3.344369s of that difference. The remaining time is not a measured exclusive RBAC/policy CPU bucket. This directly reproduces a bounded Management timeout without any second host, join transport or resource connection: cumulative successful authorization/API work exceeds10s. Hardware/scheduling variation is not controlled by these two runs; no precise per-function complexity, lock-wait or Automerge cost claim is made from HTTP aggregate timing.

**Owner handoff, not speculative patch:** the of IdP/Management composed authorization owner should profile the now-small failing extra-service-Client test, specifically repeated principal/Client/key/trust loading in token issuance, introspection and Device lookup. The native read/conflict admission/catalog/history mechanisms traced above are concrete suspects; generic ofdb persistence changes are not authorized by this evidence. Do not weaken validation, remove grants/assertions, prewarm away the cold-token requirement, widen the deadline, or treat a lost response as authorization denial. A caller timeout can coexist with a committed policy mutation; it cannot safely be treated as proof that no effect occurred.

**Remaining joined-B refresh handoff:** baseline and inventory-control replay return real denial. Four extra Clients alone are therefore insufficient to reproduce run07. Remaining distinguishing inputs include two current trusted signer/membership/Device records, authenticated imported public history, and concurrent second-host/background scheduling; none was measured separately here. A focused IdP public-bootstrap/trust-state probe with nonsecret principal/trust/transaction phase timing is the next measurement, not another completed-full-pair journey. No claim that replay waits for a missing credential, that rollback deadlocks, or that the restriction timeout and replay timeout have the same root cause.

No third Rust run or service-only baseline was performed. Final source/evidence remain pending full08 qualification. Test-only request traces are intentionally retained; production files and generic persistence owners are unchanged at this historical checkpoint. Coordinator retains root claim, review, merge and ticket acceptance/closure.

## Opt-in restriction-PUT stage instrumentation — source-only handoff, 2026-10-12

First merged integration tip `290738bb2aa8fdca1c3ee42ae2da4c2df7ee6eed` using `GIT_EDITOR=true git merge --no-edit offline-first-nodes-integration`; merge commit `6d6d032063147901372cdc164626bc4e626e3cee`. Worktree was clean before and after the merge; no reset, stash, owner write, cache/target cleanup or provider change. Read current spec/machine-local policy, issue08, evidence08 and shared glossary; loaded TDD and ponytail. Complexity: low instrumentation complexity; risk: log overhead and scheduling can perturb elapsed measurements, and authentication must remain unchanged; priority: localize the already reproduced cold-service-token restriction PUT before requesting generic-owner measurements.

The existing extra-service-Client probe is the user-selected public seam. Its four ordinary registrations, real authorization, refresh/replay assertions, background tasks, cold Management service-token acquisition, shutdown, 10s HTTP timeout and 120s whole-diagnostic bound remain unchanged. No new fixture/matrix, cache, prewarming, generic-owner change, deadline increase or authorization shortcut. TDD execution is deliberately deferred: the earlier control is the existing failing behavior, not a newly executed RED; no new GREEN or type-check result is claimed.

### Instrumentation and interpretation

Only `idp-service/src/oauth2/service.rs`, the IdP introspection and Device lookup route files, `unified-server/src/full_node_probe.rs` and this evidence change. Existing `log`/`env_logger` facilities are reused, without dependencies or manifest/lock edits. Fixed target `of::idp_stage_timing` emits fixed stage labels and integer elapsed microseconds only: no token, secret, verifier/hash, SQL, IDs, claims, request bodies or error details.

- Client credentials: Client lookup; synchronous authentication/secret verification (no repository await); principal root-key load; principal key/active-root/Client loads; live Client/principal revalidation; signer trust/private-key load; JWT encoding/signing.
- Introspection: caller authorization (JWT verification plus key/trust/principal loads); caller Client audience-allowlist load; actor authorization; Application/Client load.
- Device lookup: caller authorization; approved Device inventory load/filter; signer trust load/check; owner User info hydration.

These are **wall-clock intervals, not CPU samples or exclusive DB/lock timings**. In particular, the secret-verification interval isolates synchronous verification from repository loads but includes descheduling; authorization combines JWT verification and loads, signer loading combines trusted-public-state and private-provider loading, and live validation combines Client and principal reads. Those buckets guide owner measurement without pretending to attribute generic persistence cost. Success-only load markers disappear on early error/cancellation; authentication emits after its result is computed, before propagating it. Absence of a marker is not proof of a deadlock or a denied request. No request correlation IDs or general profiling framework. With the logger active, any concurrent call to these paths can also emit; the exact single-test window limits, but does not eliminate, background ambiguity.

`OF_IDP_STAGE_TIMING=1` installs a logger **immediately before the PUT**, after all existing setup/password/refresh/replay/actor exchange work, with the hard-coded filter `off,of::idp_stage_timing=info`; other log targets remain disabled. No RUST_LOG-wide diagnostic logging is requested. The logger remains enabled through ordinary managed shutdown, retaining any late server completion after client timeout. Initialization requires an unused process-global logger (the exact isolated test command below); it fails explicitly if another logger is already installed. Production callers can independently enable the same log target through their existing logger; the environment opt-in here is probe-only.

**Changed discriminator:** only the extra-service-Client test now uses `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`, matching the pair. Historical run02 used Tokio's default current-thread scheduler. Future results must be described as an instrumented **two-worker** control, not an identical run02 rerun or proof that inventory alone changed latency. The minimal-inventory test remains unchanged and is not requested for execution.

**Feature gating:** service timing is `#[cfg(feature = "std")]` so no_std builds have no Instant/log instrumentation. Probe logger initialization uses the existing Unified Server `cli` feature (optional env_logger); Unified Server defaults are empty, so the focused command explicitly adds `--features cli`. That feature selection is another changed build discriminator from historical no-feature commands, not a new feature or dependency. Without cli, the environment variable does not install the probe logger.

### Pending coordinator-authorized command

Do not run before coordinator grants the exclusive Rust slot and reviews this committed source. Available memory at assignment: approximately 2.9GiB, not a proven build budget. Proposed cap is 2500M with no swap and one build job; coordinator must recheck headroom/approve before executing. A resource-limit failure is not a test result; do not silently raise the cap or clean artifacts. Reuse original shared target, offline/locked and standard profiles; no feature powerset, full pair, owner baseline or CRAP sweep.

From `of/.worktrees/ticket08-full-nodes`, after recording/reviewing the instrumentation commit hash:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-idp-stage-timing-01 --property=MemoryMax=2500M --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS OF_IDP_STAGE_TIMING=1 RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --features cli --lib local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put_with_extra_service_clients -- --exact --nocapture --test-threads=1
```

Outer tool bound: 910000ms. Existing internal 120s/HTTP 10s bounds unchanged. Record literal command, reviewed commit hash, exactly one matched test, stage output, exit status and any deadline/resource failure before making causal claims. Stable source review must precede the run; no execution is part of this handoff.

### Source-only validation

Ran rustfmt on exactly the four changed Rust files (`--edition 2024 --config skip_children=true`), reviewed their full scoped git diff, and ran `git --no-pager diff --check`; passed. `git --no-pager diff --exit-code -- Cargo.lock Cargo.toml crates/idp-service/Cargo.toml crates/idp-server/Cargo.toml crates/unified-server/Cargo.toml` passed (unchanged). No Cargo/build/test/Clippy/runtime invocation, no new latency evidence and no ticket acceptance/closure. Scoped instrumentation commit is the stable source-review/run anchor; its hash is returned with the handoff rather than embedded self-referentially here.
