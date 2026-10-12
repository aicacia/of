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
