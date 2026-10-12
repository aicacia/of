# Bounded 07: desktop local relationship audiences

Date: 2026-10-11. Implementer delivery; **Rust validation pending coordinator authorization**. Ticket/map and acceptance checkboxes are unchanged.

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

## Runnable focused check (not executed)

`app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers`:

- Uses the actual production request constructor for all four desktop relationships and registers them through `OwnerProvisioner::ensure_setup_infrastructure_client` with captured setup slots.
- Reuses native fixture patterns from desktop `setup_peer_revocation_tests.rs` and unified `permission_http_tests.rs`: isolated stores, adapter over an isolated mock keyring, real approved Node signer, real OAuth2 service/router, separate persistent Management owner and explicit administrator grant, and the normal `HostedControlPlane` relationship.
- Runs real loopback HTTP Client-secret authentication and signed token issuance for all four relationships. No mocked introspection, authentication or permission decisions.
- Sends the actual IdP→Management evaluator bearer to Management HTTP permission evaluation. The granted User must be allowed; an unassigned User must be denied. This exercises Management→IdP inspection of `idp-management` through the real consuming path.
- Direct real IdP introspection permits Management inspection of the evaluator and Storage→Management bearer; permits Storage inspection of database/filesystem bearers; denies both cross-relationship inspection directions and an unrelated-service bearer.
- Independently asserts exact audience and scope lists for all four requests, catching extra authority as well as missing authority.
- Uses the existing big-stack native-test pattern (one thread, two Tokio workers), 12-second HTTP deadlines and a 120-second test bound. Stops/joins the HTTP listener task, closes the identity endpoint and removes only its unique temporary owner roots on successful completion.

Limits: this tests desktop request construction and real local owner/Management consumption, not Tauri GUI, full desktop bootstrap, real OS provider delivery, HTTPS, Storage resource apply, restart or peer propagation. The mock store is process-global in the existing keyring API; run this exact test alone in a fresh test process, not alongside other provider tests. Failed/panicked runs may leave their uniquely named temporary fixture directories; no automatic profile/provider cleanup is authorized.

### TDD and sensitivity status

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

## Pending coordinator validation stage

Please authorize and serialize the following exact focused command after other Rust builds stop. It follows prior desktop resource bounds; it has **not been run**:

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::service_relationship_tests::desktop_relationship_audiences_authorize_only_local_consumers -- --exact --test-threads=1 --nocapture
```

Use an outer command wall bound of 910000 ms. Follow with the same exact test under the sensitivity mutations above, serially, with separately named systemd units and restored source. Applicable focused Clippy (also unrun, same serial bounds):

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-desktop-audiences-clippy --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-local-audiences -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo clippy --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib --tests
```

Do not infer a passing test/build or ticket closure from this delivery. No root merge or push is requested.
