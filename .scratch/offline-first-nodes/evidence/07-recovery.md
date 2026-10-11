# Ticket 07: stopped same-Node filesystem recovery with retained provider

Date: 2026-10-11. Branch: `offline-first-node07-recovery`.
Worktree: `of/.worktrees/node07-recovery`.
Integration base: `80a050a96c4666166b4b1f2092e6af06a5d412e5`.
Initial documentation/availability delivery: `0cffb5c`.
Disposition: **actual isolated current-format stopped-filesystem recovery regression passes with the original mock protected provider retained. Not lost-provider or complete deployment recovery. Ticket 07 remains incomplete.**

This supersedes the earlier no-slot/docs-only disposition for this bounded filesystem gate only. The coordinator subsequently authorized this exclusive Rust slot and explicitly confirmed the TDD seams. Prior deployment/rotation evidence and tracker/map remain unchanged.

## Scope and CRP

Read ticket 07, operations, deployment/rotation evidence, shared glossary, CLI/config/local provisioner/endpoint, owner signer verification and private/raw keyring code. Desktop `service_secrets.rs` was inspected read-only for its distinct references. Invoked `ponytail` and `tdd`.

Changed only `crates/unified-server/src/local_provisioning_tests.rs`, `docs/operations.md` and this evidence. No production runtime/API changes, desktop edits, new dependencies, backup command or backup product abstraction. Reused the existing isolated `Fixture`, narrow mock protected provider and authenticated host exercise; two test-only stdlib tree helpers copy and verify stopped state.

Complexity: moderate for stopped-store capture/restore and denial controls; low production change complexity (none). Risk: high identity/authorization boundary, mitigated by same paths, retained provider and secret-safe assertions; this is not a deployed-profile recovery tool. Priority: prove this small existing-only seam rather than rebrand restart/static fixtures as recovery. No numerical CRAP/coverage claim, full Cargo hack or CRAP run.

Confirmed public seams: `LocalProvisioner::open_runtime`, `UnifiedRuntime::shutdown`/`serve`/`node_public_ready`/`endpoint_id`, `UnifiedEndpoint::persisted_endpoint_id`, `OwnerProvisioner::verify_node_signer`, authenticated IdP/Management HTTP and consuming `storage_server::IdpClient::approved_storage_endpoints`.

## Executed recovery behavior

Test: `local_provisioning_restores_stopped_same_node_filesystem_with_retained_provider`.

1. Create an operator-only disposable fixture parent and explicitly provision one real composed current-format Node. Derive the retained public signer binding from its public journal/endpoint and verify the original trusted signer using the owner API. Build the original runtime, check readiness/endpoint, then **await consuming shutdown**, drop the owner/runtime/provisioner handles and only then capture state.
2. Recursively copy **all five** filesystem roots into an operator-only stopped snapshot: full IdP, Management, Storage, endpoint and endpoint-adjacent provisioning directory. This includes IdP DB, owner setup inventory, all `local-client-key-references`, lock files, Management DB, whole Storage tree, protected endpoint bytes and journal. Check tree names/types, modes and file bytes; sensitive byte comparisons are boolean assertions, never operand-dumping assertions.
3. Displace each entire original root to a separate diagnostic tree inside the disposable parent. Existing-only startup with the original explicit signer binding refuses the missing recovery set. Assert every original root remains absent: no replacement identity/store is initialized.
4. Restore the same journal directory and move **the original** `operation.lock` inode into it. Copy every snapshot tree back to its exact original configured path, skipping replacement of that retained lock. Before constructing any owner/runtime, compare the full restored tree/modes/bytes to each snapshot and verify the persisted public endpoint identity. Original displaced files do not supply the restored DB/journal/endpoint bytes; those are copied from the snapshot. Only the cooperating lock inode is deliberately retained.
5. Reopen via actual CLI existing-only startup, compare endpoint and require current local readiness. The existing authenticated host exercise performs four normal Client token requests and actual Management permission evaluations for the retained initial User, including denied subject/application/scope controls. Shutdown joins the serving task; drop the provisioner guard.
6. Verify the restored trusted public signer via the public owner API with the same protected private capability, dropping the owner afterward. Reopen again, compare endpoint and make an actual authenticated consuming Storage-to-IdP endpoint-membership call; it returns the original Node endpoint. Cancel/join serving and drop the client/guard.
7. Check original lock device/inode, unchanged journal, owner inventory and all captured local key references. Check the same mock provider material remains unchanged using a secret-safe boolean comparison: no provider export/import, private-signer production/cloning or credential replacement.
8. After recovered shutdown, individually displace each restored IdP/Management/Storage/endpoint root. Every completed startup refuses, leaves the missing path absent and never initializes replacement state. Put only that isolated exact root back for the next control.
9. Corrupt the isolated restored endpoint with invalid-format bytes. Existing-only startup refuses and leaves those bytes unchanged; restore the exact endpoint from the protected snapshot. Corrupt the present journal; startup refuses without absent-journal fallback and leaves rejected bytes unchanged. Final provider comparison remains unchanged.

No central authorization service/peer configuration is introduced. This proves public local trust/readiness and authenticated owner usability after actual filesystem restoration, not an unchanged-root reopen. It does **not** assert network-level isolation: Iroh networking is not sandboxed as an air-gap test.

## Qualification limits

- **Filesystem recovery with original mock provider retained only.** The private Node signer/private-key capability remains in that same provider throughout. The four fixture Client credentials remain in unchanged in-memory configuration, not newly delivered/stored in the provider; secure credential delivery is not qualified. No real OS provider is reset, unlocked, queried for secrets, backed up or restored. Lost-provider recovery requires a separately approved same-Node platform procedure; copying data roots cannot substitute for it.
- Storage startup structure and the real consuming IdP call are qualified, but no SQL/KV/filesystem resource payload is created. This is not populated Storage content recovery or full resource/API backup coverage.
- Snapshot copying is test-only, stopped and same-format; it is not an fsync-backed durable archival product, live/crash-consistent/torn multi-context backup, schema migration, or universal detached-owner-task shutdown qualification.
- No intervening domain changes occur between capture and restore. Older deployed snapshots can roll back learned revocations, rotation or resources; stale-snapshot reconciliation and restored authorization history are not qualified.
- No signer cloning across Nodes, authority promotion, profile reset, setup replay, incomplete-journal repair, permission widening or fresh fallback. Missing/invalid restored state is explicitly rejected.
- No whole desktop/OS-process restart, Windows ACL, unattended keyring, image/TLS/proxy/Iroh deployment qualification. All whole-ticket acceptance checkboxes remain outside this delivery.

## Red / green / final commands and results

Every Cargo invocation used this literal prefix, same shared target, offline/single-job policy and unchanged test timers; `UNIT` below is the literal unit name in the table, not a shell variable:

```sh
systemd-run --user --wait --pipe --unit=UNIT --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-recovery -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::local_provisioning_restores_stopped_same_node_filesystem_with_retained_provider -- --exact --test-threads=1
```

Tool command bound: 910000 ms. Final regression and existing-host artifact control ran serially in one bounded tool call. No timeout/OOM was reported. Systemd printed tiny memory peaks; these are not credible measurements of compiler/test peak RSS and are not claimed as platform capacity evidence.

| Unit | Invocation ID | Result |
| --- | --- | --- |
| `of-node07-recovery-red` | `d1bb17562b944d47931c82b56bb55e89` | **Behavioral red**, exit 101. Initial test-only restore loop deliberately omitted Storage (index 2); existing-only complete-recovery expectation failed `NotFound`. Compilation 9m51s, test 42.10s, service 10m34.004s. This tests incomplete fixture restoration, not a newly found production defect. |
| `of-node07-recovery-green` | `af763c4278304580a375a5e6e4971e34` | Restore all five roots and assert full byte/tree/mode equality before reopening. **Exit 0, 1 passed**, compile 1m18s, test 171.64s, service 4m10.860s. |
| `of-node07-recovery-final` | `0ce852a48a5c4ef8bfc85a611decb64e` | Final source after iterator cleanup: **exit 0, 1 passed**, compile 26.47s, test 131.90s, service 2m38.482s. |

The new range-index loop was changed to enumerate the roots after Clippy flagged it. No behavioral/runtime implementation was changed to make the recovery gate pass.

Existing exact-host control, using the final artifact:

```sh
systemd-run --user --wait --pipe --unit=of-node07-recovery-exact-host-control --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-recovery -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env RUST_MIN_STACK=67108864 /home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-a4bf33735b2f05a3 local_provisioning_tests::local_provisioning_creates_exact_host_and_reopens_offline --exact --test-threads=1
```

Invocation `accd7d0da2f448cfb36334bf2f00c1f5`: **exit 0, 1 passed**, test 194.79s, service 3m14.797s. This is a separate continuity control, not substituted for the new restore regression.

Final artifact SHA-256: `d92e5f00e922276da73ed40de53c72c6d3d8f5310ae3cf55c8b0587a211136a4`.

Focused Clippy command, same bounded prefix/environment (replace the Cargo portion):

```sh
cargo clippy --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib --tests --no-deps
```

`of-node07-recovery-clippy`, invocation `c4c4dea66e894292ab9ee8026b16fc1a`: exit 0, 23.68s, included the new range-loop warning. Final `of-node07-recovery-final-clippy`, invocation `5a30d731a251417d93db1639b3c67ca9`: **exit 0, 3.16s**, lib-test 9 warnings/lib 1 duplicate, none in the newly added recovery block. Remaining warnings are existing fixture default-field reassignments, runtime collapsible condition, endpoint unnecessary allocation and interruption-fixture non-Drop drops; no unrelated lint cleanup.

`rustfmt --edition 2024 --check crates/unified-server/src/local_provisioning_tests.rs` and `git --no-pager diff --check` passed. Existing `python3 -B scripts/test_container.py` passed again: **3 tests, 0.014s**, static recipe checks only. No full feature-powerset/CRAP run.

## Deployment availability, not deployment acceptance

Initial bounded read-only checks (before the slot authorization) remain valid as availability observations, not runtime qualification:

- Docker client/daemon 24.0.5; `docker info --format` returned server version successfully. No Docker build/pull/run or registry image-tag check.
- Local `rustc 1.99.0 (b940084d7 2026-09-28)`, Python 3.12.3, `pkg-config --modversion dbus-1` 1.14.10 and OpenSSL 3.0.13. Docker, Rust/Cargo, pkg-config, dbus-send, secret-tool, openssl and systemd-run available; podman absent. Local Rust is not availability evidence for the Dockerfile Rust image tag.
- Read-only `org.freedesktop.DBus.ListNames` to the session bus daemon returned exit 0, configured-address true and already-registered Secret Service true; output was captured and only booleans/status printed. No provider activation, credential lookup, collection inspection, unlock or mutation. Registration is not unattended authorized/unlocked access or persistence proof.
- Initial disk check: 397G available; pre-build check: 388G available. Initial RAM observation was tight/full swap. Only the subsequent explicitly authorized 4G/zero-swap slot allowed the bounded compilation; no cache pruning/data deletion/cap increase.

## Delivery boundary

Three allowed files only: the existing unified-server test module, operations and dedicated recovery evidence. No tracker/map, desktop/production Rust, scripts, Cargo manifests/lockfile, Docker recipe or sibling source edits. No provider reset/profile mutation, secret printing, push or root merge. Commit hooks disabled to avoid implicit builds. Merge the then-current integration tip into this branch only; final commit/integration/status verification is reported in the delivery response.
