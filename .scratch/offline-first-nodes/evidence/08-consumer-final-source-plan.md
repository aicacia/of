# Consumer final-source cleanup and parent validation plan

2026-10-12. **Source-only cleanup; no build, Cargo test/Clippy/metadata, boundary or client command executed.** Owner agent retains exclusive build slot until parent explicitly authorizes consumer validation. No main merge, tracker/spec closure, push or diagnostic-history retirement.

## Exact consumer source / main ancestry

Cleanup commit **`ba7cfc2d6b75fbfe9f71b8cfc93137fd85345101`** on existing `offline-first-ticket08-full-nodes`, parent diagnostic qualification checkpoint **`a361acaca8bc3e85f24ffa81790547a7ae1117ed`**. All diagnostic commits/receipts remain reachable through this branch history; no reset, rebase or ref deletion. Current main **`1ef85dd2f295694c96590f595e26fbd505b2e4a0`** is already an ancestor (integrated by f0be1aa); `HEAD..main` empty. No additional merge required; main not modified.

CRP: removal low complexity, preserving current-state authorization/cleanup/synchronization ordering high priority/risk. Main-to-branch diff reviewed before removal, not a blanket revert of feature work. Existing production seams and every pair/probe assertion retained. This final cleaned source is **not yet runtime-qualified against the owner's pending clean branch**; prior GREEN30–33 remains valid only at its recorded diagnostic consumer/owner sources.

## Removed / omitted instrumentation

- All temporary `of::idp_stage_timing` guards, timers and logs in IdP OAuth service client credentials, introspection and trusted Device lookup.
- Storage introspection local-owner timers, filesystem-create initial/mutation/response timers, Unified owner-policy cleanup admission/owner/reconciliation/policy timers.
- Security-sync schema/handshake/session phase logs and live-authorization timer; restored original direct owner-session return path. All reauthorization, schema/candidate/transport validation, permission and cancellation checks unchanged.
- `full_node_probe::install_stage_logger` helper and its four harness calls (probe, offline-B, grants reconnect, restrictions-B). No env-triggered logger or `cli` dependency needed by these tests now.
- Exactly three diagnostic `log` lock edges: `ofdb-btree-redb`, `ofdb-sql-engine`, `ofdb-sql-engine-automerge`. Lockfile is byte-identical to current main; normal existing logging/CLI dependencies retained.
- No standalone stage-timer module exists in consumer `crates`; no consumer timer module left wired. Owner's native stage-timer modules/manifests/source are owned by its separate cleanup agent and were **not touched** here. No compatibility wrappers for old low-level traits.

Production `devices.rs`, `introspect.rs`, `oauth2/service.rs`, `storage-server/idp_client.rs`, `storage-server/router/resources.rs`, `unified-server/security_sync.rs` are now byte-identical to main. Unified runtime implementation also equals main, except the retained test-only sibling fixture declaration.

## Meaningful final code delta from main

| File under `crates/unified-server/src/` | Retained behavior |
| --- | --- |
|`full_node_tests.rs`|Independent native-store full-Node join/partition/reopen tests; three exact pair slices, all trust/domain/grant/namespace/permission/retained-operation assertions and ordinary teardown. Test-only HTTP begin/end and progress/failure labels retained, including endpoint-connected versus security-sync distinction.|
|`full_node_probe.rs`|Two existing composed single-host regressions, including four-extra-service-Client workload; replay/restriction/status/ordinary-shutdown assertions and bounded request stage labels. No global stage logger.|
|`full_node_runtime_fixture.rs`|Test-only access to actual local Management database and shared endpoint server; no shared repositories/permissive adapter.|
|`local_provisioning_tests.rs`|Wires full-node tests and parameterizes existing login fixture grant types/audiences; existing rotation test keeps its original grants/audience.|
|`runtime.rs`|Only `#[cfg(all(test, unix))]` sibling fixture declaration; no new production runtime behavior.|

No lib.rs/mod.rs implementation introduced. No dependency manifests, owner routes/API/schema, clients/apps/packages, scripts or configuration differ from main. Existing evidence additions retained separately.

## Source-only checks actually performed

- Rustfmt applied/check passed for cleanup Rust files plus retained helper/fixture files, using edition2024; Git whitespace checks passed.
- Structural comparison: seven restored files (six production files + lock) exactly main; runtime exactly main plus test fixture wiring. Pair/probe content exactly prior checkpoint minus logger helper/calls; all assertions, request/grant logic, deadlines, test bodies and useful labels unchanged. Initial comparison script was corrected for a removed blank line; final comparison passed, no semantic correction required.
- Search of consumer source/manifests/lock: no `stage_timing`, `StageTiming`, `OF_IDP_STAGE_TIMING`, `install_stage_logger` or `elapsed_us` left. Historical docs/log text intentionally untouched.
- Ignored raw09–11/native-stage-run03 and GREEN30–33 hashes rechecked against receipts unchanged. No ignored logs overwritten/deleted/force-added; historical tracked logs/receipts untouched.
- Pre-existing Git GC/unreachable-object warnings retained; no pruning/cache/provider reset. No claim of tests/Clippy/boundary/client success on cleaned source.

## Final-source review first (parent)

Review `main..ba7cfc2` and `a361aca..ba7cfc2`, especially test fixture production seams/identity/permission/consumption/retained-socket assertions. Compare previous all-three+repeat receipt; do not transfer its runtime status silently to cleaned artifacts.

Wait for owner's independently reviewed clean-qualified branch/source and **explicit parent build authorization**. Verify both exact commits/clean statuses, literal resolved owner paths through existing sibling links, and final manifests versus consumer lockfile before launch. Do not restore removed lock edges or regenerate the whole lockfile to accommodate a transient diagnostic owner. If new clean-owner dependency differences genuinely require lock updates, record the exact minimal changes separately and have parent review them.

## Planned focused validation — NOT EXECUTED

Execute serially in this existing worktree only after authorization, using existing shared target and profiles. Retain MemoryMax4G, MemorySwapMax0, RuntimeMaxSec900, offline/locked/jobs1, RUST_MIN_STACK67108864, unset RUSTFLAGS, HTTP10s/pair360s/probe120s, test-threads1. No stage logger env or extra features required. Capture complete stdout/stderr, exact argv/exit/source and raw-log hashes under new non-overwriting names. Record failures; an explicitly authorized warm retry may separate combined compile+test service timeout, never raise caps.

Concrete first pair command:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-final-clean-restrictions --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::full_nodes::two_completed_full_hosts_learn_restrictions_on_retained_sockets -- --exact --nocapture --test-threads=1
```

Use that same resource/profile/package/feature envelope, replacing only unit and exact literal filter as follows. Separate pair invocations avoid combining multiple360s scenarios under one900s service; no operation/failure matrix or owner suite duplication.

| Planned unit | Literal exact filter |
| --- | --- |
|`of-ticket08-final-clean-restrictions`|`local_provisioning_tests::full_nodes::two_completed_full_hosts_learn_restrictions_on_retained_sockets`|
|`of-ticket08-final-clean-offline`|`local_provisioning_tests::full_nodes::two_completed_full_hosts_join_partition_reopen_and_learn_denial`|
|`of-ticket08-final-clean-grants`|`local_provisioning_tests::full_nodes::two_completed_full_hosts_reconcile_consumption_and_revocation`|
|`of-ticket08-final-clean-probe`|`local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put`|
|`of-ticket08-final-clean-client-inventory`|`local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put_with_extra_service_clients`|
|`of-ticket08-final-clean-rotation`|`local_provisioning_tests::local_provisioning_authorized_rotation_reopens_completed_host`|

Core final acceptance is three pair filters and ordinary teardown at one stable **clean** source pair. Probe filters cover retained controls/logger cleanup; rotation covers the changed fixture helper's existing caller. One prior diagnostic-source restrictions repeat already recorded; do not add default repetition/matrices beyond parent authorization.

Focused Clippy for the final meaningful package/test delta:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-final-clean-clippy --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo clippy --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib --tests -- -D warnings
```

Record actual inherited lint warnings/failures; fix only introduced issues. Production IdP/Storage/security-sync files now equal main, so do not rerun their full matrices merely because diagnostic instrumentation was removed. No workspace/all-targets/feature-powerset/CRAP sweep; no extra CLI/platform build unless its source changes or parent specifically requests it.

Formatting final meaningful source files (standalone, no build):

```sh
rustfmt --check --edition 2024 crates/unified-server/src/full_node_tests.rs crates/unified-server/src/full_node_probe.rs crates/unified-server/src/full_node_runtime_fixture.rs crates/unified-server/src/local_provisioning_tests.rs crates/unified-server/src/runtime.rs
git --no-pager diff --check
```

**Boundary gate, conditional:** final consumer server ownership/package dependency boundaries match main; only diagnostic native logging edges removed. No new architecture boundary here. If parent final integration changes a boundary/manifest graph, run `just boundary-check` (actual recipe `python3 scripts/check_server_dependencies.py`) and record result; do not use blanket workspace Clippy as substitute.

**Clients, conditional:** no public contract, generated client, `apps/` or `packages/` change in final diff. No client tests/build planned. Add only the affected client package's existing check if parent review introduces a real client/API change; do not invent or duplicate a client matrix now.

Final cleaned runtime qualification, focused gates and parent review remain pending. Owner retains exclusive build slot; consumer did not acquire or use it. No main/spec closure/push/worktree retirement.
