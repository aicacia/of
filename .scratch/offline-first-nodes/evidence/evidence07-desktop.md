# Ticket 07 — qualified desktop runtime-startup cleanup

## Scope, CRP and ownership

2026-10-11. Own worktree `.worktrees/node07-desktop`, branch
`offline-first-node07-desktop`, based on integration
`80a050a96c4666166b4b1f2092e6af06a5d412e5`. User confirmed the desktop
startup/close ownership seams and authorized an exclusive resource-capped Rust
build slot. This delivery qualifies a bounded production fix, **not completion
of ticket 07 or whole-Tauri/process/platform lifecycle acceptance**.

Writes: `apps/app/src-tauri/src/app.rs`, its dedicated
`desktop_lifecycle_tests.rs`, and this evidence only. No root integration merge,
other worktree edits, cross-repository writes, GUI/create/join/reset runs,
OS-provider operations, OS trust installation, pushes, Cargo hack, CRAP,
profile changes, product timer changes or authorization changes. Root's ten
pre-existing dirty Storage outputs/shims were not edited; status remains those
same ten paths. Sibling source repositories are read through the pre-existing
worktree-parent links. Compiler artifacts use the explicitly authorized shared
`of/target`.

CRP: **low complexity / high lifecycle risk / high priority**. One post-build
error boundary replaces scattered cleanup. No new dependency or lifecycle
framework. Existing-only setup and trust evaluation stay intact.

### Actual trace

- Before `UnifiedRuntime::build_on_listener`, the desktop owns only its incoming
  listener; ordinary errors drop it. Unified construction-error cleanup is owned
  by the already qualified shared-host implementation, not rewritten here.
- After build, the runtime owns contexts, the persisted-identity shared endpoint,
  cancellation token, and (after background startup) protocol router, Storage
  background work and peer refresh. `take_listener` transfers only the listener.
- The TLS server is managed by Tauri separately; until successful startup, the
  runtime remains **local**, not reachable by `app::close`.
- Previously, TLS/health verification and background-start failures executed
  `close(app_handle).await?` before local `runtime.shutdown()`. Listener join
  error therefore skipped local runtime shutdown. Readiness/TLS shutdown errors
  could replace the initiating error; `take_listener()?` had no explicit runtime
  cleanup. Completion-write failure also replaced its cause on close error.
- Production now evaluates readiness, listener transfer, TLS construction,
  health verification, background startup and completion write inside one
  borrowed startup future. On ordinary error, `finish_runtime_startup` awaits
  managed listener cleanup and **then always consumes local runtime shutdown**,
  logging secondary errors while returning the original error. Managed cleanup
  clears the advertised server state through existing `app::close`.
- Successful handoff does not poll cleanup. Runtime moves into managed state
  only after all fallible startup work, including completion persistence.
  Completion-write failure thus follows the same local-runtime cleanup path.
- Normal `app::close` already takes and closes the managed TLS owner, then takes
  and shuts down the managed runtime even when listener close returns an error,
  preserving its first teardown error. No change was necessary there.
- Create closes its temporary setup endpoint before owner provisioning. Join
  closes its temporary endpoint after either selected ordinary result or the
  explicit cancellation branch. `open_setup_endpoint` closes on retention or
  identity-check failure. Provision/join/retry close the previous managed owners
  before composing a new runtime. Reset does not delete stores after close error;
  retaining reset/retry evidence is intentional, not a cleanup bypass.

## TDD / real ownership qualification

Seams were explicitly confirmed before tests. To make the headless ownership
seam runnable without a Wry window, startup was mechanically routed through the
small `finish_runtime_startup` boundary **initially retaining the original
faulty `close_listener.await?; runtime.shutdown().await?` ordering**. The intended
red check is against that extracted production ordering, not a claim that the
pristine Tauri command was run or that a GUI fault was injected.

The first new regression provisions actual IdP/Management/Storage owner state
through public `LocalProvisioner` APIs in isolated stores. It starts the actual
TLS `LocalhostServer` using the runtime listener/router, starts actual runtime
background work, and injects an error **after real listener close**. It checks
that runtime cancellation is observed, the initiating PermissionDenied error
and message survive, the exact port can be rebound, and retained owner state
reopens with the same endpoint identity. The reopened runtime also exercises
successful handoff with a cleanup future that panics if polled.

A second control actually fails TLS construction with missing fixture TLS
configuration, then exercises the same runtime-startup error boundary. It
checks runtime cancellation, port release and absence of replacement TLS state.
The injected cleanup result is the only lifecycle fault adapter; runtime,
listener, TLS and persistent context ownership are real, not mocked task
counters. The mock credential adapter ignores unsupported entry modifiers as
existing owner fixtures do. It is **not** unattended OS-provider evidence.
TLS fixture generation does not install CA trust; no insecure client bypass is
introduced. Fixtures are Unix-only because protected password creation uses
Unix modes; Linux is the sole executed platform.

## Exact commands and results

Working directory for every command below:
`/home/nathan/code/rust/aicacia/of/.worktrees/node07-desktop`.
Every Cargo invocation used one job, offline shared target, unchanged profiles,
4 GiB maximum memory, zero swap, 900-second systemd runtime and 910000 ms tool
bound. Rust flags were explicitly unset, with `RUST_MIN_STACK=67108864`.

Intended red command:

```sh
systemd-run --user --wait --pipe --unit=of-node07-desktop-red-behavior --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-desktop -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::desktop_lifecycle_tests::desktop_startup_failure_closes_runtime_after_listener_cleanup_error -- --exact --test-threads=1
```

All preliminary/red/first-green commands used exactly this command and selector,
with only the `--unit` value changed as listed below. Source states/results are
kept distinct; compilation or fixture failures do not count as regression red.

| Unit suffix (`of-node07-desktop-`) | Invocation ID | Result |
| --- | --- | --- |
| `red` | `59d818a0d3a948ed99a167da6bd6c1e3` | Timeout at 900s compiling dependencies; test not reached. Reported memory peak 2.7G, swap 0B. |
| `red-warm` | `30a77cc2f5bd4460833657541fc0ffbb` | Timeout at 900s compiling dependencies; test not reached. Reported peak 3.2G, swap 0B. |
| `red-final` | `3ed98a57f2e3478d9575e222f7fc3524` | Exit101, fixture compile error: double Arc around mock store. Corrected fixture; not behavior red. |
| `red-assertion` | `f9f4ec49ae354a3f8c505d2a04d7d582` | Exit101, fixture failed because mock store rejects entry modifiers (3.19s). Added existing-style fixture adapter; not behavior red. |
| `red-behavior` | `0c802b8afc054af5938e1e646933f83a` | Exit101, intended assertion: `listener cleanup error must not bypass runtime shutdown`; 0 passed/1 failed/56 filtered, 38.39s. |
| `green` | `19b5c5c0483246db89f8dcd19d36945c` | Exit0 after removing cleanup short-circuits; 1 passed/0 failed/56 filtered, 53.08s. |

Final changed-source gate (includes successful handoff and pre-server TLS control):

```sh
systemd-run --user --wait --pipe --unit=of-node07-desktop-focused --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-desktop -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::desktop_lifecycle_tests:: -- --test-threads=1
```

Invocation `161f63802adb4515a7c4c87b10addf60`, exit0/systemd success:
**2 passed / 0 failed / 56 filtered**, 89.89s tests, 40.34s build, 2min10.381s
service runtime. Current artifact:
`of/target/debug/deps/lidp-32f94624aa51d6c4`.

Existing headless listener controls, using that same current artifact:

```sh
systemd-run --user --wait --pipe --unit=of-node07-desktop-listener-controls --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-desktop -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib localhost_server::tests::localhost_server_ -- --test-threads=1
systemd-run --user --wait --pipe --unit=of-node07-desktop-port-control --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-desktop -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib localhost_server::tests::fails_if_saved_localhost_port_is_occupied -- --exact --test-threads=1
```

- `ff2ce613e5f146af9fe0a1e3935feae1`: exit0, graceful listener close and missing
  TLS rejection, **2 passed/0 failed/56 filtered** (0.00s).
- `fdf3ff4f9a704f78b06ed081f4fb38d6`: exit0, occupied persisted port refuses
  fallback, **1 passed/0 failed/57 filtered** (0.00s).
- Formatting and whitespace checks passed:
  `rustfmt --edition 2024 --check --config skip_children=true apps/app/src-tauri/src/app.rs apps/app/src-tauri/src/desktop_lifecycle_tests.rs`
  and `git --no-pager diff --check`.

Later systemd runs report tiny transient memory peaks (256.0K/308.0K/512.0K);
those values are not treated as reliable compiler/test peak measurements. No
OOM was reported; the two initial 900-second build timeouts remain failures,
not qualified runs. Limits were never raised.

## Exact remaining limits

- These tests run the **production ownership handoff/error boundary**, real TLS
  listener and real shared runtime, not the complete AppHandle/Wry command or
  OS process. They do not inject actual GUI startup, TLS trust verification,
  completion-file failure, router panic or runtime-shutdown error. The ordinary
  error routes for those startup stages are verified by source inspection and
  compilation, not independently exercised end to end.
- Runtime cancellation plus port release/reopen does not independently count
  every endpoint close or every detached task. Existing shared-host router
  shutdown evidence remains separate. The owner mesh API still lacks universal
  detached-task join handles; no all-task/exactly-once process claim is made.
- Panic, dropped/cancelled startup futures, forced process termination and
  concurrent window-close versus setup commands are not covered. Local runtime
  ownership cannot be asynchronously cleaned up merely by Drop.
- `runtime.rs` initial Tauri setup can still fail after retaining a listener or
  runtime (including trust repair/window creation) without explicitly invoking
  `app::close`. Window-close still uses `expect` on a close error after preventing
  close, so an error can panic the detached close task without exiting. These
  broader GUI/event-loop lifecycle paths were not changed or qualified here.
- `restore_setup_listener` retains/advertises its server before verification;
  verification failure does not close that retained server. Setter replacement
  assumes serialized callers rather than closing a prior owner itself.
- TLS graceful shutdown can wait for active connections without a product
  deadline. A hung listener close, rather than a returned close error, can still
  delay runtime cleanup; no timer or forced abort was added.
- Real OS keyring/unattended operation, Windows ACLs, macOS/Windows lifecycle,
  whole-desktop/process restart, images, provider/TLS repair, crash cleanup,
  complete same-Node backup/recovery, peer propagation and interrupted
  multi-consumer rotation remain unqualified. No ticket acceptance box was
  checked and stable operations documentation was not edited.

Delivery: tested source and this evidence committed on the own branch; integration
merged into that branch before handoff (no root merge). The commit identity is
reported in the delivery response rather than self-referencing this file.
