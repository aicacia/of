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
