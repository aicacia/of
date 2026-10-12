# Ticket 07 — bounded static TLS/port path refusal

## Ownership and base

2026-10-11 implementer delivery, branch `offline-first-bounded07-tls-paths`, worktree `.worktrees/bounded07-tls-paths`. Confirmed base: `offline-first-nodes-integration` at `04b84d0cc14f85d50cf5d0f81f0858807909b602`. Ticket07 and the machine-local spec policy were read; tdd and ponytail were loaded. User-approved seams: certificate preparation, listener reservation, server startup and trust invalidation in the existing localhost-server test module.

Write scope: `apps/app/src-tauri/src/localhost_server.rs` and this evidence only. No app.rs/module-declaration, ticket/map, root integration, dependency, provider, system CA, migration, or cross-repository changes. Sibling sources remain accessible through the pre-existing worktree-parent links.

CRP: low complexity, high security/integrity risk, high priority. This fixes an actual static unsafe-path defect; it does not close the whole ticket.

## Trace and implementation

Runtime calls certificate preparation before startup; app.rs reserves the persisted localhost port and transfers its listener into server startup. Certificate preparation previously called create_dir_all through symlink ancestry, read certificates with following existence checks, and wrote certificate/trust paths without rejecting redirected entries. Private-key leaf checks did not protect directory ancestors. Port reservation followed an existing https-port symlink, and TLS configuration directly read certificate/key/CA DER paths.

Reuse the std-only component-by-component symlink_metadata pattern from `crates/unified-server/src/endpoint.rs::reject_symlink_ancestry`: reject parent traversal and every existing nonsymlink-directory violation before directory creation. Preflight all eight managed entries (CA key/PEM/DER/trust, server key/PEM/DER, https-port), accepting only absent entries or regular files. InvalidData errors include the offending path; non-NotFound filesystem errors propagate rather than pretending absence.

Run this preflight before certificate generation/key chmod/trust installation, port creation/binding, TLS configuration reads, and trust-marker invalidation. Saved-port fallback rechecks its leaf before reading. Server-start refusal drops the incoming listener before any task is spawned. Existing regular-file behavior, key protection, create_new and port-conflict behavior remain intact. No new identity fallback or repair was introduced.

## Test design and pending execution

Five Unix tests under `localhost_server::tests::tls_paths_` use UUID-isolated temporary roots and prepare_test_tls (no OS trust installation):

- Symlink TLS directory and ancestor: refuse all production seams, preserve the redirect and retained TLS/identity sentinels.
- Every managed entry redirected to a retained valid target or a dangling target: refuse without reading/writing through it, changing modes, replacing files, or removing trust.
- Every managed entry replaced by a directory or Unix socket: refuse before partial mutations; originals retained separately and unchanged.
- Missing descendants beneath a symlink, parent traversal, and a non-directory ancestor: refuse without creating redirected descendants.
- Safe regular-file reopen control: reuse actual generated TLS material and persisted port, start/close a real TLS listener, preserve state and rebind its port.

Snapshots compare names, bytes (or symlink destinations), Unix modes and inodes of retained state and redirect targets. Actual CA/server private-key bytes are included; setup-ids.json, endpoint.key and node-signer.key are identity-preservation sentinels, not provisioned domain owners. Fixture key modes are deliberately 0640 so refusal also exposes premature chmod. Refusal checks rebind the known saved port when readable and a separately transferred startup listener address; safe control closes and rebinds its exact port.

The first ancestry regression was written before the production guard. Per the explicit memory restriction, no Rust build, test, check, Clippy, Cargo Hack or CRAP ran. Red/green and sensitivity results are therefore PENDING, not claimed; subsequent cases are static-designed regression coverage, not executed TDD cycles. Do not run the whole localhost_server test module for this slice: its historical certificate tests can invoke system trust installation.

## Exact coordinator-only validation command (UNRUN)

Run only after granting the single Rust-build slot, from the dedicated worktree, using the previously qualified shared-target resource bounds:

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-tls-paths-validation --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-tls-paths -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib localhost_server::tests::tls_paths_ -- --test-threads=1
```

Tool timeout should be 910000 ms. The filter intentionally runs only the five new provider/CA-independent tests. This command is proposed, NOT executed. Compilation or runtime issues, if any, must be recorded by the coordinator.

## Lightweight checks and limits

`rustfmt --edition 2024 apps/app/src-tauri/src/localhost_server.rs` and `git --no-pager diff --check` passed. `rustfmt --edition 2024 --check apps/app/src-tauri/src/localhost_server.rs` also passed. Snapshot assertions deliberately avoid printing private-key bytes on failure. Staged provenance is restricted to the source and this evidence. File tools could not address the worktree hidden evidence directory although terminal ls confirmed it exists; the evidence was written via Python to that same scoped path.

Static pathname checks assume stable owner-controlled ancestry; they do not certify hostile concurrent directory/entry replacement, hard-link ownership, power-loss behavior, Windows/macOS protection, OS-provider availability, GUI/process lifecycle or whole-Node domain recovery. No such qualification is claimed. Root dirty Storage outputs/shims and other worktrees were not changed. The integration tip is merged into this branch before handoff; no root merge or ticket/map update is performed.

## Exclusive-slot validation — 2026-10-11 (supersedes pending execution above)

User granted the exclusive Rust slot for stable `a3ca27c81ebe402cd52a87aa23c2d832c602999b`, focused attempts and cheap relevant sensitivity, followed by restoration/final green. Reviewed the stable source and existing test seams before running. No introduced compile/runtime errors were found and no final source edits were necessary. The first source-equality check before final execution and the post-test check both passed:

```sh
git --no-pager diff --exit-code a3ca27c -- apps/app/src-tauri/src/localhost_server.rs
```

### Memory and execution discipline

`free -h` and `/proc/meminfo` were inspected before the first build: MemAvailable 4,867,644 kB (about 4.64 GiB), host memory about 26 GiB used out of 30 GiB, host swap about 2 GiB used with 72 kB free. Host swap is distinct from the zero-swap build cgroup. The first sensitivity check had about 4.3 GiB available; the final restoration check about 3.6 GiB. All three builds were sequential in the granted exclusive slot, each with MemoryMax=4G, MemorySwapMax=0, RuntimeMaxSec=900, one Cargo job, offline dependencies, unchanged profiles, shared approved target, and terminal timeout 910000 ms. No cap increase, host swap adjustment, process termination, or cache pruning occurred.

### Exact executed commands

Working directory: `/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-tls-paths`.

Initial stable-source green:

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-tls-paths-validation --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-tls-paths -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib localhost_server::tests::tls_paths_ -- --test-threads=1
```

Sensitivity red:

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-tls-paths-sensitivity --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-tls-paths -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib localhost_server::tests::tls_paths_reject_symlink_directory_and_ancestor_without_mutation -- --exact --test-threads=1
```

Restored final green (preceded in the same terminal command by the source-equality check and shell AND):

```sh
systemd-run --user --wait --pipe --unit=of-bounded07-tls-paths-final --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded07-tls-paths -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib localhost_server::tests::tls_paths_ -- --test-threads=1
```

### Observed results

| Run | Test result | Compile/profile completion | Test duration | Service runtime | Exit |
| --- | --- | --- | --- | --- | --- |
| Stable a3ca27c green | 5 passed, 0 failed, 61 filtered | 1m48s | 10.29s | 1m59.637s | 0 |
| Following-ancestry sensitivity | 0 passed, 1 failed, 65 filtered | 46.37s | 0.06s | 46.720s | 101 (expected) |
| Restored a3ca27c final green | 5 passed, 0 failed, 61 filtered | 42.52s | 0.23s | 43.012s | 0 |

Invocations respectively: `72b75c0fc519413ab4b70dbb04765783`, `a54534735b024cc8b29cd17b031c627e`, `641aae4191e94e8e9aac27b4a8469694`. Cargo ran `target/debug/deps/lidp-32f94624aa51d6c4`. No compiler warnings/errors, timeout or OOM were reported. systemd reported memory peaks 256.0K/260.0K/256.0K and swap peaks 0B; these tiny accounting values are recorded verbatim, not claimed as meaningful measured compiler RSS. The configured resource limits and normal completions are the bounded execution evidence.

The temporary mutation changed only ancestry inspection from `fs::symlink_metadata(&prefix)` to `fs::metadata(&prefix)`, reproducing the old following-ancestry behavior while preserving leaf checks. The single regression failed at `localhost_server.rs:552`, because certificate preparation returned the redirected certificate path instead of refusing the unsafe directory. This is test sensitivity for that specific ancestry defect, not a full pristine-old-source run or certification of every leaf guard mutation. Its existing CA/cert/trust fixture prevented any trust installation, and failure occurred before later listener/startup assertions.

The mutation was reversed immediately after the expected failure. The exact failed fixture `/tmp/tls-path-48bcd0a8-dca3-4b5d-9fda-91f98289de9a` was removed (no matching fixtures existed before the mutation). Final fixture inventory reports zero remaining tls-path roots. Final green exercises all five real public-seam tests, including retained state/redirect-target preservation and exact listener-port release. No private-key bytes were printed.

Final `rustfmt --edition 2024 --check apps/app/src-tauri/src/localhost_server.rs`, `git --no-pager diff --check`, source equality to a3ca27c, and clean status checks passed before this evidence-only update. No source change is committed in the validation handoff. No system CA trust, secure-provider/profile, GUI, root merge, ticket/map, dependency, sibling repository or sweeping validation operations occurred. Clippy, full module/workspace tests, Cargo Hack and CRAP remain unrun intentionally. Integration tip remains `04b84d0cc14f85d50cf5d0f81f0858807909b602`, already included by the earlier merge.

Disposition: the five bounded Ubuntu static-path/refusal and safe-reopen regressions are now qualified on the approved source; the prior unrun status is historical. Concurrent hostile replacement, hard-link ownership and all broader platform/provider/whole-Node limits above remain unchanged.
