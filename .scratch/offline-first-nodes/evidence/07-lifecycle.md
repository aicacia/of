# Ticket 07 shared-runtime lifecycle slice

Date: 2026-10-11. Branch: `offline-first-node07-lifecycle`.
Base/integration tip: `fc74d950b4a8f64ebd806c7422982bbc89d3a6d7`.
Current disposition: **resumed qualification passed on unchanged source: exact lifecycle regression plus membership and two provisioning controls, 4 passed / 0 failed. Own slice committed as 2bd2661 and integration 8b1eb55 reconciled; ticket 07 remains open, partial lifecycle acceptance only.**

The three earlier 240-second failures and their then-current stop decisions are
preserved below. Their incomplete disposition was superseded only by the later
explicit 900-second authorization and the passing results recorded at the end.

## Scope and CRP

Read worktree `AGENTS.md`, `.scratch/offline-first-nodes/spec.md`,
`issues/07-node-operations-and-runtime-lifecycle.md`, `docs/operations.md`, and
root `GLOSSARY.md`; invoked `tdd` and `ponytail`.
Changes are confined to `crates/unified-server/src/runtime.rs` and this evidence.
No Docker, stable operations docs, map, ticket, GUI, reset, owner-source, or
other-worktree changes. Before coordinator permission, no Cargo build/check/test was run. After permission,
only the four separately authorized capped Cargo attempts recorded below ran. No full hack or CRAP command.
Initial worktree status was clean on the requested branch.

Complexity: moderate, existing composition with three async lifecycle transitions;
no dependency, trait, framework, timer, or compatibility layer added.
Risk: high, admission and task/endpoint teardown are security/resource boundaries;
deferred router creation changes when protocols become available. Compilation and
new assertion execution are mandatory before delivery. Priority: high, shared
host startup/teardown must preserve local trust and clean up on failure.
CRP is qualitative only; no numeric complexity/coverage score is claimed.

## Trace and proven gaps

- `UnifiedRuntime::build` binds the host listener and delegates to
  `build_on_listener`. Callers are `LocalProvisioner` startup/provisioning,
  desktop `start_composed_unified_runtime`, native desktop tests, unified runtime
  acceptance, and local provisioning tests. CLI serves through the same runtime.
- `UnifiedEndpoint::open` loads the existing protected key and binds one endpoint;
  `build_idp_runtime` receives its identity/server, and `build_storage_runtime`
  receives `Some(server.clone())`. Neither injected context creates or closes
  another endpoint. Storage shutdown aborts/awaits its sync task, not the endpoint.
- `compose_protocol_router` uses `Server::router_with_protocol` with the existing
  Storage/security data handler plus bootstrap ALPN. Owner helper registers
  pairing/data/mesh/bootstrap and calls `mesh.start()` immediately. Constructing
  this router in `build_on_listener` therefore started mesh background work before
  callers checked current local readiness.
- Build had multiple fallible operations after endpoint opening with no explicit
  endpoint close; failures after Storage construction had no owner shutdown.
  The async construction result now retains endpoint/Storage ownership for error
  cleanup, cancels the shared token, shuts down constructed Storage, and closes
  the endpoint. Successful construction leaves the protocol router unstarted.
- `start_background_tasks` formerly had no current readiness check, returned
  success after failed admission refresh, and returned success on repeated calls
  even when already cancelled. It now checks cancellation and the existing
  `node_public_ready` owner seam, refreshes admission, checks cancellation again,
  then composes exactly one router and starts Storage/peer refresh tasks.
  The existing peer-refresh handle remains the successful-start idempotency guard.
- `serve` formerly returned directly on taken-listener or background-start errors.
  Those paths now call shutdown; a spawned HTTP task is cancelled and awaited
  before shutdown on startup errors. Existing HTTP readiness handling remains.
- `shutdown` formerly dropped its router and explicitly closed the endpoint.
  A retained router clone kept its accept task alive. It now awaits owner
  `Router::shutdown`, which shuts handlers, closes the endpoint, aborts/joins
  remaining accept tasks. Host shutdown joins peer refresh and Storage first;
  explicit endpoint close is used only if no router was started. Consuming
  shutdown ownership prevents a second host shutdown. Errors from peer/Storage
  joins do not bypass router shutdown.
- Desktop already verifies public readiness and its HTTPS listener before calling
  background startup, and calls consuming shutdown on startup failure/close.
  Local provisioning checks public readiness and shuts down without starting
  background work. No desktop caller edits are included. Desktop early cleanup
  errors can still bypass later runtime cleanup in sequences using `close(...)?`;
  that caller behavior is outside this slice and is not qualified here.

## Admission restoration and independence

Build still restores locally trusted signer/Device endpoint IDs via
`IdpRuntime::approved_peer_ids` before ordinary protocol startup. It includes
self and does not admit Device-only approval. Startup refresh runs again before
router creation; periodic refresh updates learned membership, denying on an IdP
trust-query failure. No peer contact or authorization freshness lease is added.
Storage authorization/selection denial does not replace endpoint admission.
The new denied-readiness assertion retains independently approved peer admission;
no router/background work is started by that denied attempt. Actual per-operation
Storage/security authorization remains in existing adapters; handshake admission
is not substituted for it. Existing offline restoration/revocation tests are
retained, not rewritten as remote-authority checks.

## Tests first / red assertion analysis

Seams: existing host build, background start, serve and consuming shutdown;
existing local membership restoration. Lifecycle assertions extend
`runtime::tests::builds_three_prefixed_services_with_one_endpoint` using its real
isolated IdP/Management/Storage stores and existing narrow credential provider.
No collaborator mocks or new production test hooks are added. Router/endpoint
handles retained by the fixture are shutdown observers, not new public APIs.

The readiness/cancellation and retained-router assertions were written before their
fixes. The taken-listener and deferred-router assertions were added as the caller
and owner trace exposed those additional gaps. Baseline red assertion analysis:

1. Build must leave router/mesh work unstarted. Old build always installed a router.
2. Taking the listener then calling `serve` must return `AlreadyExists` and close
   the shared endpoint even with a retained endpoint handle. Old `?` bypassed close.
3. Removing the exact local public-context grant must make background startup fail,
   retain separately trusted admission, and leave the router unstarted. Old startup
   never consulted current public readiness and returned success.
4. Repeated successful background startup must retain the original router, observed
   through that original handle at shutdown; a replacement router would leave the
   original alive. Existing idempotency is preserved.
5. Cancelled background restart must fail even after prior startup. Old initial
   handle guard returned success.
6. Shutdown must cancel the retained original router and close the shared endpoint
   before returning. Old dropping behavior did not cancel a retained router.

**These are source-level red analyses, not executed red/green results.** The first capped attempt did not reach `unified-server` compilation; the warm and final
attempts reached its test build but did not finish. Successful changed-source
compilation and test execution remain unverified. The build-failure cleanup branch and background-failure
HTTP joining branch are source-traced, not independently fault-injected here.

## Exact executed checks and cached artifact limits

All commands below ran from `/home/nathan/code/rust/aicacia/of/.worktrees/node07-lifecycle`.
Host `free -h`: 30 GiB total, 23 GiB used, 1.6 GiB free, 7.3 GiB available;
2.0 GiB swap total/used, 18 MiB free. `df -h . /tmp`: 401 GiB available (55% used).
No caches or data were pruned.

Cached artifact inspected:
`/home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-d2ff4d244f2c2d5c`,
924658912 bytes, timestamp Oct 11 12:27. Its `--list` exited 0 and listed 69 tests.
Worktree has no `target` directory. Existing sibling dependency symlinks under
`of/.worktrees` are present and unchanged. Artifact provenance is not established
as the exact integration source, and it predates this slice; it cannot execute the
new assertions or qualify the changed source.

- `/home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-d2ff4d244f2c2d5c runtime::tests::native_membership_restores_offline_and_learned_revocation_removes_admission --exact --test-threads=1`
  (60 s tool bound): exit 134, test-thread stack overflow, abort/core-dumped message;
  no successful result. No deletion of core/cache files performed.
- `RUST_MIN_STACK=67108864 /home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-d2ff4d244f2c2d5c runtime::tests::native_membership_restores_offline_and_learned_revocation_removes_admission --exact --test-threads=1`
  (60 s bound): exit 0, 1 passed, 0 failed, 68 filtered; 31.66 s test time.
  This changes only the cached harness thread stack, not product timers/auth.
- `RUST_MIN_STACK=67108864 /home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-d2ff4d244f2c2d5c endpoint::tests::owns_one_persisted_endpoint_and_matches_idp_identity --exact --test-threads=1`
  (60 s bound): exit 0, 1 passed, 0 failed, 68 filtered; 0.03 s test time.
- `rustfmt --edition 2024 crates/unified-server/src/runtime.rs`: exit 0.
- `rustfmt --edition 2024 --check crates/unified-server/src/runtime.rs`: exit 0.
- `git --no-pager diff --check`: exit 0, no whitespace errors.
- `GIT_EDITOR=true git merge --ff-only offline-first-nodes-integration`
  (10 s bound): exit 0, `Already up to date.` Integration still points to fc74d95.

## Remaining qualification / coordinator handoff

Coordinator granted changed-source qualification only under a 4 GiB memory cap,
zero swap, 240-second runtime, one Cargo job, offline mode, the shared target,
existing profile/no rustflags, and a 250000 ms tool timeout. Instruction: stop on
timeout/OOM without widening the cap. The first authorized attempt was:

```sh
systemd-run --user --wait --pipe --unit=of-node07-lifecycle-regression --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-lifecycle -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=240 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib runtime::tests::builds_three_prefixed_services_with_one_endpoint -- --exact --test-threads=1
```

Tool timeout: 250000 ms. Exit: **1** from `systemd-run`. Invocation:
`ffecba1eb2e54b7ca9043ac0d4e18c71`. Result: **timeout**, main process killed by
SIGTERM. Service runtime **4min 202ms**, CPU **4min 848ms**, displayed memory
peak **3.2G**, swap peak **0B**. Follow-up bounded `systemctl --user --no-pager show
of-node07-lifecycle-regression.service -p Result -p ActiveState -p SubState
-p ExecMainCode -p ExecMainStatus -p MemoryPeak -p MemorySwapPeak -p RuntimeMaxUSec
-p MemoryMax -p MemorySwapMax` confirmed:

- `Result=timeout`, `ActiveState=failed`, `SubState=failed`.
- `ExecMainCode=2`, `ExecMainStatus=15`.
- `MemoryPeak=3498491904`, `MemorySwapPeak=0`.
- `MemoryMax=4294967296`, `MemorySwapMax=0`, `RuntimeMaxUSec=4min`.

The output compiled path-based owner and host dependencies, ending at
`495/498: idp-server`; no `Compiling unified-server`, test launch, compilation
diagnostic for the changed code, or test result was produced. No profile override,
new rustflags, network fetch, cache removal or cap increase was used. Shared
path-dependency compilation occurred despite reuse of the existing target.
This is a resource/time limit, **not a failing lifecycle assertion or OOM result**.
No immediate retry, membership test, or provisioning controls ran after the first
stop. The additional warm attempt below required separate coordinator permission.
No claim is made that an existing executable was updated to this source.

### Separately authorized warm-cache attempt

Coordinator authorized exactly one further warm-cache attempt with unchanged
limits, followed only on success by sequential current-artifact membership and
two provisioning controls. The first timeout above is retained unchanged in its
recorded results. Executed command:

```sh
systemd-run --user --wait --pipe --unit=of-node07-lifecycle-regression-warm --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-lifecycle -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=240 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib runtime::tests::builds_three_prefixed_services_with_one_endpoint -- --exact --test-threads=1
```

Tool timeout **250000 ms**, exit **1** from `systemd-run`; invocation
`7abfdf0caff14ed6aec8b9af5c5b371f`. Output compiled `idp-server`,
`management-server`, then `unified-server`, ending at
`497/498: unified_server(test)`. Result **timeout**, main process killed by
SIGTERM. Service runtime **4min 231ms**, CPU **4min 932ms**, displayed memory
peak **2.8G**, swap peak **0B**. No `Finished` Cargo build, executable launch,
compiler error, or test result was reported. No claim is made that a current
usable artifact was produced, or that borrowing/moves were compiler-validated.

A bounded `systemctl --user --no-pager show
of-node07-lifecycle-regression-warm.service -p Result -p ActiveState -p SubState
-p ExecMainCode -p ExecMainStatus -p MemoryPeak -p MemorySwapPeak -p RuntimeMaxUSec
-p MemoryMax -p MemorySwapMax` confirmed:

- `Result=timeout`, `ActiveState=failed`, `SubState=failed`.
- `ExecMainCode=2`, `ExecMainStatus=15`.
- `MemoryPeak=3019526144`, `MemorySwapPeak=0`.
- `MemoryMax=4294967296`, `MemorySwapMax=0`, `RuntimeMaxUSec=4min`.

Stopped immediately after the second compilation timeout as authorized: no
further Cargo attempt, membership test, or provisioning control. No cap increase,
profile/rustflags change, source edit, cache deletion, OOM result, or failing
lifecycle assertion. Both attempts used the same source and existing profile.
No commit: the qualification precondition remains unmet.

### Final authorized attempt — qualification closed incomplete

Coordinator authorized one FINAL attempt with identical caps and no further
compile retries. Source, existing profile, timers, authentication and test bounds
were unchanged. Exact command:

```sh
systemd-run --user --wait --pipe --unit=of-node07-lifecycle-regression-final --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-lifecycle -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=240 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib runtime::tests::builds_three_prefixed_services_with_one_endpoint -- --exact --test-threads=1
```

Tool timeout **250000 ms**, exit **1** from `systemd-run`; invocation
`3364b9ff84dd49e5bc37ea04ecb97151`. Only `Compiling unified-server` appeared,
ending at `497/498: unified_server(test)`. Result **timeout**, main process killed
by SIGTERM. Service runtime **4min 208ms**, CPU **4min 1.213s**, displayed memory
peak **2.2G**, swap peak **0B**. No completed Cargo build, test launch, compiler
error, or test result was reported. No successful changed-source compilation or
usable current-artifact qualification is claimed.

Bounded follow-up command `systemctl --user --no-pager show
of-node07-lifecycle-regression-final.service -p Result -p ActiveState -p SubState
-p ExecMainCode -p ExecMainStatus -p MemoryPeak -p MemorySwapPeak -p RuntimeMaxUSec
-p MemoryMax -p MemorySwapMax` confirmed:

- `Result=timeout`, `ActiveState=failed`, `SubState=failed`.
- `ExecMainCode=2`, `ExecMainStatus=15`.
- `MemoryPeak=2468917248`, `MemorySwapPeak=0`.
- `MemoryMax=4294967296`, `MemorySwapMax=0`, `RuntimeMaxUSec=4min`.

Stopped: no further compile retry, membership/control execution, source change,
cap increase, cache deletion, commit, or integration merge. First and warm timeout
records remain above. This is the final incomplete disposition, not a request to
continue retrying. Coordinator reports independent static review `99032af` found
no concrete blockers; that report is not independently inspected here and is not
compiled/test evidence.

### Ownership and cleanup review

`pending_storage` remains owned by the outer build function. The construction
future borrows it and installs the newly built Storage before later fallible
operations. The shared Storage borrow is last used by `storage_runtime.router()`;
on success, `pending_storage.take()` transfers ownership to `Self`, leaving no
second shutdown owner. On ordinary error return, the awaited construction future
is gone before the outer function takes and shuts down retained Storage. Endpoint
and cancellation token are cloned into successful `Self`, not moved out of the
outer cleanup scope. This is source review of intended non-lexical lifetimes,
**not completed rustc confirmation**: the warm and final attempts reached the
crate test build but were terminated before a successful build or diagnostic result.

Build and serve cleanup attempt all owned teardown while preserving the original
startup error; cleanup errors on those paths are intentionally not returned over
the initiating error. Normal shutdown accumulates the first peer/Storage/router
error while still attempting later teardown. Router shutdown owns the normal
single endpoint close; pre-router shutdown closes it directly. A panic/error in
owner router shutdown remains a limitation, not a claimed universal cleanup
success. No source edits were made during this qualification follow-up.

### Historical handoff after the three 240-second attempts

No commit made because changed-source qualification is incomplete. Source is
preserved unstaged; evidence is force-added because `/.scratch` ignores new files.
No pre-existing staged/dirty work was present in this worktree. Integration tip
and HEAD both remain `fc74d950b4a8f64ebd806c7422982bbc89d3a6d7`. Earlier
bounded merge checks reported `Already up to date.` No merge was run after the
FINAL compile authorization: dirty source remains unmerged as instructed. No
cross-worktree source edits were made.

Final handoff: preserve this dirty worktree. No further compile retries are
permitted; no commit or delivery merge because focused qualification never
passed. The changed-source lifecycle regression, membership test, and both
previously scoped provisioning controls remain **unexecuted**. Formatting and
diff checks pass, but those checks do not establish Rust compilation or lifecycle
acceptance. Historical cached baseline results are not substitutes. Ticket 07
remains open and unresolved; detached-mesh shutdown is not fully accepted.

## Resumed qualification — unchanged source, longer command wall time

Coordinator explicitly resumed implement-spec and authorized ONE additional
qualification build with the same 4 GiB memory limit, zero swap, single Cargo
job, offline shared target and existing profile. Only the systemd command wall
time increased from 240 to **900 seconds**; tool timeout **910000 ms**. No source,
product timeout, test bound, authentication, profile or rustflags change was
made. The first three failures and their stop decisions above remain historical
results, not failures of the lifecycle assertions. No diagnostic fix was needed.

Exact build/test command, workdir unchanged:

```sh
systemd-run --user --wait --pipe --unit=of-node07-lifecycle-regression-long --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-lifecycle -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs 1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib runtime::tests::builds_three_prefixed_services_with_one_endpoint -- --exact --test-threads=1
```

Invocation `e20d484419ca41cf9a1bcac6a3051277`, exit **0**, result **success**.
Cargo compiled `unified-server`, finished `test` profile `[optimized + debuginfo]`
in **4m 25s**, then ran the current artifact:
`/home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-a4bf33735b2f05a3`.
Lifecycle regression: **1 passed, 0 failed, 68 filtered**, **334.86s** test time.
Service runtime **10min 601ms**, CPU **10min 16.909s**. This demonstrates why the
previous 240-second compilation cutoffs could not finish this unchanged build.
No completed-build success was inferred from any of those earlier attempts.

### Sequential current-artifact controls

All three commands below executed that same newly built artifact directly,
without Cargo/rebuilding, sequentially, with **4 GiB / zero swap / 300-second
runtime** per test and **310000 ms** tool timeout. Each reported exit **0** and
systemd result **success**, with **1 passed, 0 failed, 68 filtered**.

```sh
systemd-run --user --wait --pipe --unit=of-node07-lifecycle-membership-current --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-lifecycle -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=300 env RUST_MIN_STACK=67108864 /home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-a4bf33735b2f05a3 runtime::tests::native_membership_restores_offline_and_learned_revocation_removes_admission --exact --test-threads=1
systemd-run --user --wait --pipe --unit=of-node07-lifecycle-provision-current --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-lifecycle -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=300 env RUST_MIN_STACK=67108864 /home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-a4bf33735b2f05a3 local_provisioning_tests::local_provisioning_creates_exact_host_and_reopens_offline --exact --test-threads=1
systemd-run --user --wait --pipe --unit=of-node07-lifecycle-existing-current --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/node07-lifecycle -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=300 env RUST_MIN_STACK=67108864 /home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-a4bf33735b2f05a3 local_provisioning_tests::local_provisioning_existing_cli_host_without_journal_starts_and_reopens --exact --test-threads=1
```

| Control | Invocation | Test time | Service runtime | CPU |
| --- | --- | --- | --- | --- |
| Offline membership / learned revocation | `edc81245c30e41ba9ed21bdb007ba1a3` | 28.69s | 28.699s | 28.245s |
| Exact provisioning / offline reopen | `e7be56cb2a174c81b277c905b307104a` | 156.51s | 2min 36.524s | 2min 31.432s |
| Existing host without journal / reopen | `ae0ac26c148047eaa9820746759004bb` | 157.28s | 2min 37.286s | 2min 32.542s |

`systemd-run` reported memory peaks **256.0K**, **308.0K**, **292.0K**, **256.0K**
for the successful build/unit and three controls respectively, and swap peaks
**0B**. These are reported tool values, **not independently reliable measurements
of compiler/test peak memory**. A post-run `systemctl --user --no-pager show` on
the four successful transient units returned inactive/default properties
(`MemoryPeak=[not set]`, `MemoryMax=infinity`, `RuntimeMaxUSec=infinity`), so those
post-unload properties cannot verify historical limits or substitute for the
explicit executed resource-capped commands. All four commands exited successfully;
no timeout/OOM was reported in this resumed qualification.

### Qualified source and acceptance limits

Runtime source SHA-256 (unchanged through all attempts and controls):
`d2f90e723a9916f4ffd7f7263e50050127bbda78428860db0a050b276a2f2253`.
Current test artifact SHA-256 after all controls:
`14778913bed33eef07f4df345304289f7155dcedb0cb1179868b1c7a522905be`.
No source modification occurred after compilation. The successful build confirms
the `pending_storage` borrow/ownership analysis; the exact regression executes
the added denied-readiness, admission preservation, startup idempotency,
cancelled-restart, taken-listener cleanup, retained-router shutdown and endpoint
closure assertions. Existing membership and provisioning/reopen controls pass on
this source. Build-error fault injection and background-failure HTTP task cleanup
remain source-traced only. No universal cancellation/crash or owner detached-mesh
join guarantee is inferred, and no full hack/CRAP/GUI/image/provider-reset test ran.

Formatting and whitespace validation after controls:
`rustfmt --edition 2024 --check crates/unified-server/src/runtime.rs`,
`git --no-pager diff --check`, and `git --no-pager diff --cached --check`:
exit **0**. Coordinator-reported independent static review `99032af` is retained
as a report, not substituted for the now-executed focused qualification.

### Commit and integration handoff

Own changes remain limited to runtime implementation/regression assertions and
this evidence. The coordinator explicitly requests merge of integration
`8b1eb55`. Comparing its lifecycle evidence with this worktree before the
successful-result append returned **byte-for-byte identical**: the integration
copy is exactly the complete previous three-attempt chronology. Keep the full
latest local evidence on add/add conflict; no integration history will be lost.
The integration delta from fc74d95 includes deployment/docs/tracker work, but
**no Rust source or Cargo files**; those are other contributors' changes to be
inherited by the requested merge, not edits authored by this lifecycle slice.
Commit the tested source/evidence first, then merge integration and verify the
runtime source hash is unchanged. Full ticket 07 remains unresolved.

Owner limitation: `ofnet` Mesh::start spawns a detached retry loop, and outbound
mesh registration also spawns detached connection work; there is no retained join
handle/mesh shutdown API. Endpoint closure makes the retry loop exit on its next
iteration, but awaiting the router cannot prove all owner-owned mesh tasks have
joined. Do not claim the full ticket's all-task shutdown acceptance. No cross-repo
fix, new framework, tracker edit, or invented trait is included. Cancellation by
dropping a construction/shutdown future, handler panic during owner shutdown,
actual desktop HTTPS/OS-process lifecycle, unattended keyring, Windows ACLs,
TLS/port matrix, pairing isolation, full existing-connection revocation matrix,
and recovery remain unqualified. Exactly-once endpoint close is supported by the
normal host ownership/owner-router path, not instrumented as a universal fault
or crash guarantee. Ticket 07 is not resolved by this slice.

## Delivery merge record

Own tested source/evidence commit:
`2bd2661ee6f601d4733978198113750132d643f7` (`Fix shared Node runtime lifecycle ownership`).
Requested integration parent:
`8b1eb55c6c203bb2c789ccd171127595f4d9bf1c`.
Command `GIT_EDITOR=true git merge --no-ff --no-commit 8b1eb55` produced the
expected add/add conflict only in this evidence. The incoming evidence was
verified equal to the previously captured complete three-timeout chronology;
retaining the full latest local record preserves all of it plus the resumed
successful build and current-artifact control results. No incoming deployment,
operations, map, or ticket changes were rewritten by this slice.

Conflict resolution restores the latest local evidence and adds this merge
record. Runtime source was verified byte-identical to own tested commit and
SHA-256 `d2f90e723a9916f4ffd7f7263e50050127bbda78428860db0a050b276a2f2253`.
Integration adds no Rust/Cargo delta, so the current-artifact qualification still
applies to the final merged runtime source without another build or broader
qualification. Final format/diff checks are recorded by the delivery command;
merge is committed with both parents. No root or older-worktree files were edited.
The merge commit itself identifies the final delivery tip; ticket 07 remains open
and this is only partial shared-runtime lifecycle qualification, not universal
owner detached-task/crash/desktop/deployment acceptance.
