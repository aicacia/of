# Bounded 07: desktop local relationship audiences

Date: 2026-10-11. Initial implementer delivery was unvalidated; **authorized focused validation results are appended below**. Ticket/map and acceptance checkboxes are unchanged.

## Provenance and scope

- Confirmed base/integration tip at branch creation: `04b84d0cc14f85d50cf5d0f81f0858807909b602`.
- Branch: `offline-first-bounded07-local-audiences`; worktree: `of/.worktrees/bounded07-local-audiences`.
- Read ticket 07, spec including machine-local qualification policy, issue-tracker conventions, Glossary Map/shared glossary and IdP local-security contracts. Loaded `tdd` (including tests/mocking guidance) and `ponytail`.
- Complexity: low, one registration constructor and one focused HTTP regression. Risk: security-sensitive Client audience allowlists. Priority: blocker for ordinary desktop local permission evaluation/Storage token inspection.
- Source scope: `apps/app/src-tauri/src/app.rs` and sibling `service_relationship_tests.rs`; this evidence is the only documentation edit. No dependencies, provider/profile/system changes, GUI, migrations, compatibility wrappers or ticket/map edits.
- Root dirt preserved: ten pre-existing Storage client outputs/shims in `esm/`, `types/`, and `node_modules/.bin/`; root branch remains integration. No root merge or sibling repository write.

## Trace and exact fix

Both production desktop callers use `provision_service_clients`: `provision_initial_administrator` and `join_installation`. Existing ignored native retry/reset checks also call it. Its four sequential relationships all flow through `provision_service_client`, which now builds the owner request with the relationship-based `service_client_registration`. No other desktop registration callers exist. `unified_runtime_config`/`load_service_credentials` continue requesting the same issuance audiences.

The old registration helper accepted one audience, leaving the two introspection callers registered only for IdP issuance. IdP `/oauth2/introspect` authenticates the caller at its own service audience with `idp.token.validate`, then separately requires the inspected token audience in that Client allowlist. Management permission evaluation authenticates its `idp-management` evaluator bearer via that local IdP relationship. CLI `local_provisioning.rs` already adds these exact inspection audiences; this fix brings desktop requests into agreement without changing IdP authorization.

| Relationship | Exact allowed audiences | Unchanged scopes |
| --- | --- | --- |
| Management → IdP | configured local IdP audience, `idp-management`, configured local Storage audience | `idp.token.validate`, `idp.device.lookup` |
| Storage → IdP | configured local IdP audience, `storage:databases`, `storage:filesystems` | `idp.token.validate`, `idp.device.lookup`, `idp.device.list` |
| Storage → Management | configured local Storage audience only | `management.replication.read`, `management.replication.admit` |
| IdP → Management | `idp-management` only | `management.permission.evaluate` |

Application metadata, Client profile/type, grant/auth method, registration order, protected secret delivery and retry identity are preserved. The shared constructor replaces the old argument-driven request builder; there is no parallel old path. Existing persisted registrations are not migrated or automatically repaired. The existing exact setup owner contract can reject conflicting old requests; completed-runtime credential loading remains unchanged. The existing IdP contract uses the same allowlist for issuance and inspection; this change does not split or weaken that contract.

## Focused check design (unexecuted at initial delivery)

`app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers`:

- Uses the actual production request constructor for all four desktop relationships and registers them through `OwnerProvisioner::ensure_setup_infrastructure_client` with captured setup slots.
- Reuses native fixture patterns from desktop `setup_peer_revocation_tests.rs` and unified `permission_http_tests.rs`: isolated stores, adapter over an isolated mock keyring, real approved Node signer, real OAuth2 service/router, separate persistent Management owner and explicit administrator grant, and the normal `HostedControlPlane` relationship.
- Runs real loopback HTTP Client-secret authentication and signed token issuance for all four relationships. No mocked introspection, authentication or permission decisions.
- Sends the actual IdP→Management evaluator bearer to Management HTTP permission evaluation. The granted User must be allowed; an unassigned User must be denied. This exercises Management→IdP inspection of `idp-management` through the real consuming path.
- Direct real IdP introspection permits Management inspection of the evaluator and Storage→Management bearer; permits Storage inspection of database/filesystem bearers; denies both cross-relationship inspection directions and an unrelated-service bearer.
- Independently asserts exact audience and scope lists for all four requests, catching extra authority as well as missing authority.
- Uses the existing big-stack native-test pattern (one thread, two Tokio workers), 12-second HTTP deadlines and a 120-second test bound. Stops/joins the HTTP listener task, closes the identity endpoint and removes only its unique temporary owner roots on successful completion.

Limits: this tests desktop request construction and real local owner/Management consumption, not Tauri GUI, full desktop bootstrap, real OS provider delivery, HTTPS, Storage resource apply, restart or peer propagation. The mock store is process-global in the existing keyring API; run this exact test alone in a fresh test process, not alongside other provider tests. Failed/panicked runs may leave their uniquely named temporary fixture directories; no automatic profile/provider cleanup is authorized.

### Initial-delivery TDD and sensitivity status

Test source was authored before the production change. **No executable red or green was run** because Rust builds are prohibited at this implementer stage. Type-checking, native HTTP behavior, timing and sensitivity remain unverified; static formatting/metadata are not substitutes.

Coordinator sensitivity plan, after a successful baseline and with source restored between mutations:

1. In the Management→IdP match arm replace its audiences with only `vec![idp_audience]`. The real permission-evaluation HTTP 200 assertion should fail (the original defect).
2. In Storage→IdP replace its audiences with only `vec![idp_audience]`. Database/filesystem introspection success should fail.
3. Remove only Management’s Storage inspection audience. Its Storage→Management inspection should fail.
4. Add database/filesystem audiences to Management or `idp-management`/Storage audience to Storage. The cross-relationship denial controls should fail; exact-list assertions also reject widening.

These are planned red controls, not observed results. Restore the committed source, rerun green, and record actual results before merge acceptance. Do not mutate root or expand provider permissions to make tests pass.

## Lightweight validation actually run

From this dedicated worktree:

```sh
rustfmt --edition 2024 --config skip_children=true apps/app/src-tauri/src/app.rs apps/app/src-tauri/src/service_relationship_tests.rs
rustfmt --check --edition 2024 --config skip_children=true apps/app/src-tauri/src/app.rs apps/app/src-tauri/src/service_relationship_tests.rs
git --no-pager diff --check
cargo metadata --offline --no-deps --format-version 1 > /dev/null
```

All completed with exit 0. Metadata did not compile Rust. No Cargo test/build/check/Clippy, full sweep, Cargo Hack or CRAP ran.

## Initially proposed coordinator validation stage

Please authorize and serialize the following exact focused command after other Rust builds stop. It follows prior desktop resource bounds; it has **not been run**:

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers -- --exact --test-threads=1 --nocapture
```

Use an outer command wall bound of 910000 ms. Follow with the same exact test under the sensitivity mutations above, serially, with separately named systemd units and restored source. Applicable focused Clippy (also unrun, same serial bounds):

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences-clippy --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo clippy --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib --tests
```

Do not infer a passing test/build or ticket closure from this delivery. No root merge or push is requested.


## Authorized exclusive validation stage, 2026-10-11

Coordinator granted the exclusive Rust slot. No concurrent Rust build was started. All six runs used the documented systemd command, unchanged 4 GiB memory/zero unit swap/900-second runtime properties, one Cargo build job, and a 910000 ms outer tool bound. Before the first run `free -h` reported 30 GiB total, 26 GiB used, 489 MiB free, 4.6 GiB available; host 2 GiB swap was nearly full (40 KiB free). Later preflight observations reported 4.5 GiB available; no system/provider/profile changes or cap increases were made.

The attempted preflight reads of `/sys/fs/cgroup/memory.max` and `/sys/fs/cgroup/memory.current` each failed with `No such file or directory`. `systemctl --user show of-bounded07-desktop-audiences.service -p MemoryMax -p MemorySwapMax -p Result -p ExecMainStatus -p MemoryPeak -p ControlGroup` confirmed `MemoryMax=4294967296`, `MemorySwapMax=0`, `Result=exit-code`, `ExecMainStatus=101` after the first run. systemd reported only 256–516 KiB memory peaks and 0 B swap peaks; those implausibly small memory peaks are **not claimed as aggregate compiler/test memory measurements or independent proof of effective child-process accounting**. No timeout or OOM was reported by any run.

### Actual results and focused corrections

| Unit suffix | Source under test | Build time | Test time | Service runtime | Result |
| --- | --- | --- | --- | --- | --- |
| (none) | original committed `343ce08` | 8m45s | 14.83s | 9min 878ms | exit 101; 0 passed, 1 failed |
| `-fixture` | required initial administrator pairing grants added | 1m13s | 48.79s | 2min 3.445s | exit 101; 0 passed, 1 failed |
| `-target` | concrete Client read target added | 1m04s | 71.46s | 2min 15.924s | exit 0; 1 passed, 0 failed |
| `-red-management` | Management→IdP audience temporarily reduced to IdP only | 21.50s | 28.15s | 49.838s | expected exit 101; 0 passed, 1 failed |
| `-red-storage` | Management restored; Storage→IdP reduced to IdP only | 21.43s | 47.34s | 1min 8.968s | expected exit 101; 0 passed, 1 failed |
| `-final` | both mutations restored; corrected fixture | 22.07s | 71.33s | 1min 33.569s | exit 0; 1 passed, 0 failed |

Every run selected exactly one test; 0 ignored, 0 measured, 61 filtered out. Compilation succeeded in every run; no compiler warnings/errors appeared in the captured output.

First failure (fixture setup, before audience behavior), at `service_relationship_tests.rs:248:6`:

```text
real explicit local grant: Custom { kind: Other, error: InvalidInput("administrator requires valid IDs and both device-pairing permissions") }
```

Focused correction 1: add `DevicePairingRead` and `DevicePairingUpdate` to the isolated initial administrator grants, as required by the existing public provisioning contract. Production relationship scopes were not changed.

Second failure, at `service_relationship_tests.rs:332:9`:

```text
assertion `left == right` failed: Management must inspect the desktop evaluator's idp-management bearer
  left: 403
 right: 200
```

Inspection of `PermissionEvaluationRequest::policy_namespace` established that `InfrastructureClientsRead` requires `IdentityResource::Client { client_id: Some(nonempty_id) }`. Focused correction 2: use the actual evaluator Client ID instead of an absent create-style Client target. No owner authorization was bypassed or changed. These two fixture corrections exhaust the focused fixing attempts requested; subsequent baseline/final runs passed without further fixes.

Management red failure, at corrected test line 334:

```text
assertion `left == right` failed: Management must inspect the desktop evaluator's idp-management bearer
  left: 401
 right: 200
```

This red reaches real Management HTTP permission evaluation and its IdP introspection consumer before exact-list assertions. It demonstrates sensitivity to the original Management registration defect, not only to constructor metadata.

Storage red failure, at corrected test line 367:

```text
assertion `left == right` failed: least-privilege inspected audience
  left: 401
 right: 200
```

This is the first Storage success assertion (database-token inspection), after real Management evaluation and Management inspection succeed. Both red runs also emitted the expected outer test-thread propagation panic `desktop relationship check did not panic: Any { .. }` at line 66, plus Cargo's `error: test failed, to rerun pass -p lidp --lib`. Neither was a compiler, timeout, or OOM failure.

### Exact executed Rust commands

All commands ran from `of/.worktrees/bounded07-local-audiences`, serially, with outer `timeout_ms=910000`. Where noted above, `free -h` and targeted rustfmt/diff checks preceded the systemd command. The full commands were:

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers -- --exact --test-threads=1 --nocapture
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences-fixture --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers -- --exact --test-threads=1 --nocapture
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences-target --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers -- --exact --test-threads=1 --nocapture
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences-red-management --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers -- --exact --test-threads=1 --nocapture
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences-red-storage --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers -- --exact --test-threads=1 --nocapture
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences-final --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers -- --exact --test-threads=1 --nocapture
```

### Restoration, final checks and limits

After both red runs, `git --no-pager diff --exit-code HEAD -- apps/app/src-tauri/src/app.rs` passed, proving the production source matches `343ce08` exactly. Before final green, these commands also passed:

```sh
rustfmt --check --edition 2024 --config skip_children=true apps/app/src-tauri/src/app.rs apps/app/src-tauri/src/service_relationship_tests.rs
git --no-pager diff --check
```

Final green exercises all stated positive/negative HTTP cases, both permission decisions and exact audience/scope lists with the corrected fixture. This supersedes initial pending compilation/behavior statements for this focused seam only. It is observed mutation-red/restoration-green sensitivity, **not a claim that executable red preceded the original implementation**. The separate audience-widening and Management-Storage-only omission mutations were not run; their controls passed in final green but mutation sensitivity is not additionally claimed.

Clippy remains unrun; no full Cargo Hack/CRAP/workspace sweep, GUI, HTTPS or real provider qualification occurred. Failed tests can retain their uniquely named temporary fixture roots; no profile/provider reset or blanket cleanup was performed. Successful green runs execute the fixture cleanup path. Ticket/map remain unchanged; root dirt remains untouched. No root merge or push.

Post-run property probe: the successful final transient unit was collected (`LoadState=not-found`, `ActiveState=inactive`, `Transient=no`), so a later `systemctl show` returned default `MemoryMax=infinity`, `MemorySwapMax=infinity`, and `RuntimeMaxUSec=infinity`; these are not retained properties of the completed run. The failed Storage red unit remained loaded and confirmed `RuntimeMaxUSec=15min`, `MemoryMax=4294967296`, `MemorySwapMax=0`. The exact final command and its exit-zero systemd output remain the execution evidence; live final-run cgroup accounting was not independently sampled.

Git staging initially refused the ignored `.scratch` path without `-f`; explicit force-add of only this evidence file succeeded. Commit succeeded with a Git automatic-gc warning about a pre-existing failed gc log/too many unreachable loose objects. No gc-log deletion, pruning, cleanup or root mutation was performed. Final worktree status is clean and integration is already an ancestor; root remains `04b84d0` with its ten original Storage changes.
