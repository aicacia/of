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

## Exact remaining limits at the first qualified delivery (`418dba2`)

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


## Historical static handoff — three ordinary-error paths awaiting build slot

The user explicitly requested closing the remaining ordinary-error root causes,
confirmed the real startup/close seams, and assigned the Rust build slot to a
**different agent**. This follow-up is static implementation only on the same
branch/worktree, disjoint from recovery. **No Rust compilation, test execution,
commit, merge or shared-target write was performed for this follow-up.** Earlier
five passing checks qualify only commit `418dba240f72bfd27f956cbed6baee6606d84bbc`,
not these changed sources.

### Trace and minimal changes

- Initial Tauri `.setup` could retain the setup listener or completed runtime,
  then return from trust repair/verification or window creation with an error.
  The complete existing setup body is now evaluated as one synchronous Result;
  its final error boundary invokes `app::close` before returning that original
  boxed setup error. Early errors before ownership exists also safely use this
  idempotent close boundary. Successful setup never polls cleanup. The original
  certificate preparation, registration, fallback behavior and window creation
  order are unchanged.
- `restore_setup_listener` previously installed/advertised its TLS server before
  `verify_localhost_server` returned an error. Reservation, initialization and
  verification now return through the same `finish_managed_startup` boundary,
  which calls existing `app::close` on error. This clears advertised readiness,
  takes retained owners and attempts all their teardown. Secondary close errors
  are logged, not substituted for the verification/startup cause. An initial
  setup failure after failed restore can close again: taken Options are empty,
  so it does not close an owner twice.
- Window-close prevented closing, then used `expect` on `app::close`, so a
  returned teardown error panicked its detached callback before process exit.
  It still awaits actual close first, then `exit_after_close` logs any returned
  error and requests exit1; success requests exit0. The FnOnce exit callback is
  the narrow platform side-effect seam, not a task manager or timer abstraction.
  No timeout, abort, retry task, new dependency or alternate ownership system.

CRP remains low complexity / high ordinary-error lifecycle risk / high priority.
Files changed in this follow-up are `app.rs`, `runtime.rs`, the existing dedicated
`desktop_lifecycle_tests.rs` and this evidence only.

### Tests-first design and pending qualification

Each of the three regression slices was written before its corresponding
production route/fix. Execution of red/green is deferred because compiling is
not authorized while the other agent owns the slot. **There is no observed
red/green result for this follow-up.** The new tests are:

1. `desktop_initial_setup_failure_closes_retained_owners_and_preserves_cause`:
   real provisioned unified runtime, actual TLS listener and started background
   work; boxed initial-setup error plus injected cleanup-error return *after*
   actual owner teardown; preserves setup error, observes cancellation and
   rebinds exact port.
2. `desktop_restored_listener_verification_failure_releases_port`: actual TLS
   listener and actual existing setup verifier against an untrusted/invalid
   fixture server; original verification error survives and exact port is free.
   Also verifies successful managed startup does not poll cleanup. No OS trust
   installation or insecure verification bypass.
3. `desktop_window_close_error_still_requests_exit_after_teardown`: actual TLS
   listener close before injected returned cleanup error; exit side-effect seam
   must receive exactly one code1, normal return exactly one code0; port is free.
   Does not kill the test process or construct a Wry window.

When the exclusive build slot is reassigned, first establish test sensitivity
at these extracted production boundaries: temporarily retain the former
no-cleanup behavior in `finish_managed_startup` for the first two tests and the
former `expect` behavior in `exit_after_close` for the third. Expected failures
are uncancelled runtime, occupied retained-listener port, and panic/no-exit.
Restore candidate implementations exactly, then run all five dedicated desktop
regressions and the previously used three listener controls. Mutation runs are
not yet performed and must not be represented as pristine whole-GUI baseline
runs. Final changed-source qualification and commit remain pending.

Prepared focused green command, **not executed**:

```sh
systemd-run --user --wait --pipe --unit=of-node07-desktop-ordinary-focused --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-desktop -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::desktop_lifecycle_tests:: -- --test-threads=1
```

Lightweight checks actually run for this follow-up:

```sh
rustfmt --edition 2024 --check --config skip_children=true apps/app/src-tauri/src/runtime.rs apps/app/src-tauri/src/app.rs apps/app/src-tauri/src/desktop_lifecycle_tests.rs
git --no-pager diff --check
```

Both pass. These are parse/format/whitespace checks, **not Rust type checking or
runtime qualification**. The three formerly listed ordinary-error defects now
have production source fixes pending qualification. Whole-Wry/AppHandle/OS exit,
actual window-build fault injection, OS-provider/platform behavior, panic/drop/
forced termination, close/setup concurrency, hung graceful shutdown and universal
detached owner joins remain unqualified; no new timer or all-task guarantee is
claimed. Integration will be merged into the own branch before qualified
commit/handoff; root integration must not be merged or edited by this agent.


## Follow-up qualification — all five desktop ownership regressions pass

User reassigned the exclusive Rust build slot and authorized the focused three
new tests plus two previous ownership regressions, with the same systemd limits.
This section supersedes the **awaiting-build/unqualified** status of the historical
static handoff above. The initial-setup, restored-listener and window-close
ordinary-error defects listed at the first delivery are now fixed and qualified
at the confirmed headless ownership/exit seams. No broad suites were run.

### Executed sensitivity check

Before the final gate, a narrow mutation restored the former ordinary-error
behavior at the extracted production seams:

- `finish_managed_startup` dropped its cleanup future and returned the startup
  result without polling cleanup.
- `exit_after_close` used `result.expect("failed to close app"); exit(0);`.

These are sensitivity mutations, **not a pristine whole-GUI baseline run**.
A Python `try/finally` saved the two candidate source files in memory and restored
them exactly after the command, including on command failure. The shell command
executed by its literal subprocess argument list was:

```sh
systemd-run --user --wait --pipe --unit=of-node07-desktop-ordinary-red --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-desktop -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::desktop_lifecycle_tests:: -- --test-threads=1
```

Invocation `f05c130768cc4b199f0cc1b7927d2a7e`, exit101:
**2 passed / 3 failed / 56 filtered**, test time **167.75s**, build **1m06s**,
service runtime **3min54.533s**. Failures were exactly:

1. Initial setup: `initial setup error must close retained runtime` because the
   real runtime cancellation token was not cancelled.
2. Restored listener: exact-port rebind returned `AddrInUse` / OS error98 because
   the actual retained TLS listener was not closed.
3. Window close: `failed to close app` panic on the injected returned cleanup
   error, so the exit callback was not called.

Both previous ownership regressions passed under these mutations. Failed tests
may retain their isolated temporary fixtures because their final fixture removal
is after assertions; they contain only test-owned state and use the mock provider,
not production stores or OS credentials. The failed test process exited.

### Final restored-candidate gate

```sh
systemd-run --user --wait --pipe --unit=of-node07-desktop-ordinary-focused --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-desktop -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p lidp --lib app::desktop_lifecycle_tests:: -- --test-threads=1
```

Invocation `21f2370853684544b68bc0bf9d18303b`, exit0/systemd success:
**5 passed / 0 failed / 56 filtered**, test time **138.51s**, build **48.85s**,
service runtime **3min7.545s**. Cargo rebuilt the changed candidate and ran
`of/target/debug/deps/lidp-32f94624aa51d6c4`.

- `desktop_initial_setup_failure_closes_retained_owners_and_preserves_cause`
- `desktop_restored_listener_verification_failure_releases_port`
- `desktop_window_close_error_still_requests_exit_after_teardown`
- `desktop_startup_failure_closes_runtime_after_listener_cleanup_error`
- `desktop_tls_startup_failure_releases_runtime_and_reserved_port`

Both commands were single-job/offline with shared `of/target`, explicit unset
Rust flags, 64 MiB Rust minimum stack, MemoryMax4G, MemorySwapMax0,
RuntimeMaxSec900 and tool timeout910000. No timeout/OOM was reported in these
follow-up runs; earlier historical build timeouts remain recorded failures.
Reported transient memory peaks were 256.0K with swap0B, not independently
reliable compiler/test peak measurements. No limits or product timers changed.

Final formatting and whitespace checks passed:

```sh
rustfmt --edition 2024 --check --config skip_children=true apps/app/src-tauri/src/runtime.rs apps/app/src-tauri/src/app.rs apps/app/src-tauri/src/desktop_lifecycle_tests.rs
git --no-pager diff --check
```

### Qualified behavior and remaining acceptance boundary

All three requested ordinary-error root causes now have production wiring and
runnable regression evidence. Initial Tauri setup returns through managed-owner
cleanup even after trust repair or window creation error; restored-listener
startup/verification errors close retained owners and clear advertised readiness;
window close awaits attempted teardown and requests a nonzero exit on returned
cleanup error instead of panicking. Original startup errors survive secondary
cleanup errors. Success does not poll error cleanup. No timeout/task framework,
new dependency, OS trust/provider operation, GUI/create/join/reset run, broad test
suite, Cargo hack, CRAP, root merge, cross-repository source edit or push.

The Tauri `.setup`/AppHandle wiring compiles, but the tests exercise the production
error boundaries with real owned runtime/TLS state and an injected exit callback,
not an actual Wry window failure or real process termination. Actual whole-GUI
exit/restart, unattended OS providers, Windows ACLs and macOS/Windows behavior
remain unqualified. Panic/drop/forced termination, close/setup concurrency,
hung graceful shutdown and universal detached owner-task joins remain outside
ordinary returned-error acceptance. Stable operations docs and ticket checkboxes
are unchanged: ticket07's broader deployment, rotation rollout and backup/recovery
acceptance is not inferred from these five tests.

The four scoped files are committed on `offline-first-node07-desktop` after this
qualification. Current integration is merged into that branch before handoff;
root integration and its dirty Storage outputs remain untouched. Commit identity
and merge outcome are recorded in the delivery response.
