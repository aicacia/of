# 04 local durable transition qualification — timeout, not qualified

## Provenance and assessment

2026-10-11. Dedicated worktree `of/.worktrees/bounded04-durable-evidence`, branch `offline-first-bounded04-durable-evidence`, base integration `04b84d0`. Revised ticket04 and machine-local spec read. Complexity moderate (reuse one real fixture); security/readiness risk high; priority closes the representative durable-publication evidence gap. TDD and ponytail loaded; user-requested production import/completion seams reused. Initial source delivery had no Rust slot. The subsequently granted exclusive slot and actual failures are recorded below; no production defect or RED/GREEN success is claimed.

## Source audit and added test

Existing `desktop_bootstrap_orchestration_completes_both_public_contexts_and_retries_offline` already drives real authenticated purpose-specific approval, both context imports, completion, source shutdown, native owner/policy reopen, disconnected exact retry and learned-revocation denial. This is source audit, not a new passing observation.

Added `production_durable_transitions_preserve_imports_and_verified_readiness_on_reopen`, reusing that fixture. One sequential representative scenario, not an exhaustive matrix:

- After actual IdP owner import and receiver verification, before `record_node_join_stage(Idp)`.
- After actual Management owner import and receiver verification, before its stage journal.
- After actual `verify_node_join_public_readiness`, before PublicReady publication.
- After successful PublicReady publication, before completion returns.

Private cfg(test) task-local one-shot errors occur at the actual production call sites; absent from non-test builds, no public hook or new framework. Every selected error must match exactly, so an earlier unrelated failure cannot masquerade as a checkpoint. Each interruption drops all joining owner database handles and reopens native owner/policy stores while retaining the same endpoint and injected private-key store. Assertions require exact request/receipt/member/endpoint/key references, actual imported trust and private signer verification, policy grants after policy import, missing journals before retry, and current readiness false until PublicReady exists. Actual production receive retries publish missing import journals. PublicReady exact retry and existing source-disconnected driver/reopen/revocation assertions follow. Exact trust validation includes unique member/signer/Device binding; no receipt-derived readiness is asserted.

The test was subsequently executed but timed out; these transition assertions have no confirmed passing observation. In-process errors/native database reopen are not process kill, power loss, partial-row import, endpoint-process restart, GUI approval or real OS-provider fault qualification. Existing partial-bootstrap work belongs to another branch and is not superseded here.

## Device completion assessment — separate seam

Read-only audit of `apps/app/src-tauri/src/setup_completion.rs` and `app.rs`:

- `interrupted_completion_resumes_and_corruption_is_preserved` covers both `setup-ready` and `device-setup-ready`: partial temporary marker retry, exact retry, Installation mismatch, corrupt-final preservation.
- `completion_never_follows_a_symlink` covers temporary/final Device marker symlink refusal and unchanged target.
- `completed_node_with_unavailable_local_contexts_preserves_completion_for_retry` covers retained markers and local unavailable/ready classification; it supplies readiness as a boolean, not a composed runtime success.
- `complete_device_setup` checks Installation completion, current composed runtime public readiness, nonempty localhost base and actual localhost verification before writing Device completion. This source ordering is NOT execution evidence for interruption between localhost verification and Device marker publication.

No Device/Tauri composed success claimed. Marker tests are marker-seam evidence only, not TLS/runtime/current-trust publication evidence. No app.rs, localhost_server.rs or setup_completion.rs edits or new profile/provider/CA operations.

## Validation — actual exclusive-slot results

Passed lightweight checks: scoped rustfmt (edition2024, skip_children), `git diff --check`, `python3 scripts/check_server_dependencies.py` (no direct server-to-server dependency edges). No ticket/map/status/checkbox change or root merge. Source commit tested: `37e4164`; no source corrections made after these runs.

User granted one exclusive Rust build slot and superseded the earlier unexecuted fresh-target/optimization command. Both actual runs used shared `of/target`, standard workspace profile, no added optimization/debug/incremental overrides, removed both Rust flag variables, one Cargo job, 64MiB worker stack, MemoryMax4G, MemorySwapMax0 and RuntimeMaxSec900. Terminal bound910000ms. Before initial run:30GiB total,4.1GiB available, swap effectively full; no cargo/rustc process. Before warm run:3.7GiB available, swap effectively full; no cargo/rustc process. Other existing editor/language-server processes were left untouched.

Exact cold invocation, from `of/.worktrees/bounded04-durable-evidence`:

```sh
systemd-run --user --wait --pipe --unit=bounded04-durable-focused --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded04-durable-evidence -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib security_sync::bootstrap::interruption_tests::production_durable_transitions_preserve_imports_and_verified_readiness_on_reopen -- --exact --test-threads=1 --nocapture
```

- Unit invocation `650967a501ad428b92fabd441cdcfe8c`.
- Compilation PASSED: `Finished test profile [optimized + debuginfo] ... in 11m21s`; no introduced compiler diagnostic.
- Exactly one test started; observed local IdP token HTTP200.
- Service timeout at15min214ms, TERM/status15 (terminal command exit1). CPU14min40.214s; reported memory peak3.2G, swap0B.
- Cold build consumed most of the900s service budget; remaining test time was less than its unchanged360s internal bound. No test verdict or checkpoint success observed.

One unchanged warm-cache run was made to allow the full internal test bound, not to raise either timeout. Exact command is the cold invocation above with only `--unit=bounded04-durable-focused-warm` substituted.

- Unit invocation `e454fcccda524d3fa47a674a1e4a1496`.
- Warm compilation PASSED in1.14s; exactly one selected test,72filtered.
- Observed local IdP token HTTP200, then panic at `node_bootstrap_interruption_tests.rs:83:10`: `representative durable transitions and offline retry complete: Elapsed(())`.
- FAILED:0passed/1failed/0ignored, test result elapsed380.94s, exit101. Service runtime6min22.207s; CPU6min13.081s. Systemd reported memory peak528.0K and swap0B; this accounting value is not interpreted as the actual test working set.

The output does not identify which transition (if any) was reached before timeout. Compilation and HTTP200 do NOT qualify authenticated approval/import/publication/reopen assertions. This is a harness runtime limitation with no isolated root cause, not proven production misbehavior. No speculative fix, deadline increase, weakened assertion, source instrumentation or additional repeated Rust run was made. The original control was NOT run because the new focused test did not pass. No TDD RED/GREEN production fix claimed.

## Remaining gate and preservation

Representative durable-transition evidence remains NOT QUALIFIED; existing source tests and prior observations retain their own boundaries. Further investigation/rerun needs renewed coordinator authorization and should first isolate the phase without claiming timeout diagnosis. Exact new filter is `security_sync::bootstrap::interruption_tests::production_durable_transitions_preserve_imports_and_verified_readiness_on_reopen`. Exact control filter, if later authorized, is `security_sync::bootstrap::interruption_tests::desktop_bootstrap_orchestration_completes_both_public_contexts_and_retries_offline`.

Both owned units are failed/inactive after termination; no cargo/rustc process remained in the final process check. Shared target retained, no cleanup or fresh target creation. Temporary isolated fixtures from interrupted tests may remain under the system temporary directory; no deletion or profile/provider/CA operation was performed. Device marker tests remain source-audited only in this slice; no Device/Tauri composed success, physical/process crash, OS-provider, full matrix, Clippy/hack/CRAP or root integration acceptance claimed.

## Read-only timeout diagnosis and pending stage diagnostics

User requested diagnosis without another Rust slot. Synced integration `8a70deeaf967dad1c9887a8d498dbeaa77a995ee` into this branch as merge `a1f8f36`; no root merge. App/listener changes entered only through that integration merge, not local edits.

Reviewed actual tool stdout from both runs, user-journal service results, current test stages, original `04b84d0` fixture, receiver/publication code and journal writer. `--pipe` test stdout is not retained in the user journal; journal adds termination timestamps/results, not missing phase output. No Rust command or executable rerun in this diagnostic pass.

### What concretely timed out

Warm panic is raised by the OUTER `tokio::time::timeout(Duration::from_secs(360), interruption_boundary(...))`, not by the15s reqwest timeout or an inner pairing deadline.380.94s is reported total test elapsed, not a380s imposed timeout; why elapsed reporting exceeded360s is not isolated. The observed HTTP200 is the API token-exchange response in `user_token`, whose client is configured with15s timeout. It does not locate subsequent pairing/import work by itself.

Read only filesystem metadata (names, sizes, mtimes; no file contents/database/provider access) for the two retained fixture directories matching those service intervals:

| Run | Joining request | Approval | IdP journal | Management journal | PublicReady |
| --- | --- | --- | --- | --- | --- |
| Cold fixture `01a12d98-a084-7123-a536-176310dff531` |20:52:54.534749|20:52:59.191830|20:55:26.023344|absent|absent|
| Warm fixture `01a12d9c-21c9-7089-a8f0-7db3238d91cf` |20:56:46.072702|20:56:50.998785|20:59:21.009310|21:01:25.059383|21:01:37.823596|

Times are local filesystem timestamps, 2026-10-11. Warm service ran20:56:08.164144–21:02:30.371356. Thus the warm failure is after durable PublicReady publication, not an outstanding pairing-approval or HTTP-token request. `persist_exact` publishes once via hard-link and exact retry only syncs the parent; retained marker mtimes are not rewritten by exact retry. The interrupted fixture writes PublicReady only in the fourth transition call after actual readiness verification (the preceding verified-readiness call is deliberately interrupted before publication). This narrows progress, but does not certify the fourth reopen/readiness assertion, exact completion retry, or original offline/revocation tail as passing. Cold observation reached the IdP journal before service termination; it is not upgraded to a successful test.

### Minimal difference from original fixture

Original complete path performs two owner imports in `join_from_trusted_peer`, publishes completion, then its existing retry/disconnect/reopen/revocation/teardown tail. New path first uses the same real signed approval exchange without auto-import, then performs IdP import interrupted before journal + full exact IdP retry, Management import interrupted before journal + full exact Management retry, and two completion publication calls with four separate native reopens. It then executes the original complete tail. Four full receive sessions replace two; reopens/current trust/signing verification and completion retries are additional. This is a concrete fixture-work difference, not a measured performance root cause. Stdout lacks phase markers, so the precise operation active at the whole-test deadline is still unknown. No HTTP/pairing failure, deadlock, CPU starvation, production defect or successful original control is inferred from that absence.

### Focused test-only edit, not a timing fix

Added a private optional current-phase Cell and fixed nonsecret stage messages to the existing test module. Original tests pass None; only the new fixture emits these phase logs. The injected checkpoint logs its enum only when reached. The unchanged360s timeout now reports the current phase explicitly. Logs distinguish initialization/token issuance, pairing offer/send/approval/admission, both interrupted imports and exact retries, publication, native reopens/current verification, production completion retry, router shutdown/endpoint close, disconnected retry, revocation and teardown. No bearer, password, issuer, endpoint, key or journal contents are logged. No new production/public hook, dependency, timeout/bound increase, weakened assertion or split fixture yet: first identify the precise suffix rather than assume four transitions must be split. These diagnostic edits are UNCOMPILED/UNEXECUTED until renewed authorization.

Scoped rustfmt, whitespace check and dependency-boundary check pass. No provider/profile/CA operation, root merge, Rust build, original control, marker test, Clippy or broad sweep.

Exact next focused diagnostic command ONLY after renewed coordinator slot, from this worktree; terminal bound910000ms:

```sh
systemd-run --user --wait --pipe --unit=bounded04-durable-diagnostic --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/bounded04-durable-evidence -p MemoryMax=4G -p MemorySwapMax=0 -p RuntimeMaxSec=900 env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib security_sync::bootstrap::interruption_tests::production_durable_transitions_preserve_imports_and_verified_readiness_on_reopen -- --exact --test-threads=1 --nocapture
```

Check available memory/no other Rust before running. Preserve the last phase and checkpoint messages on failure. If it reaches the original suffix within the unchanged deadline, use that actual stage evidence to choose the smallest independently bounded fixture; do not enlarge bounds or repeat blindly. Representative acceptance and Device composed success remain unqualified.
