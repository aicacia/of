# 04 local durable transition qualification — pending execution

## Provenance and assessment

2026-10-11. Dedicated worktree `of/.worktrees/bounded04-durable-evidence`, branch `offline-first-bounded04-durable-evidence`, base integration `04b84d0`. Revised ticket04 and machine-local spec read. Complexity moderate (reuse one real fixture); security/readiness risk high; priority closes the representative durable-publication evidence gap. TDD and ponytail loaded; user-requested production import/completion seams reused. No production defect or RED/GREEN execution claimed: coordinator has not granted a Rust slot.

## Source audit and added test

Existing `desktop_bootstrap_orchestration_completes_both_public_contexts_and_retries_offline` already drives real authenticated purpose-specific approval, both context imports, completion, source shutdown, native owner/policy reopen, disconnected exact retry and learned-revocation denial. This is source audit, not a new passing observation.

Added `production_durable_transitions_preserve_imports_and_verified_readiness_on_reopen`, reusing that fixture. One sequential representative scenario, not an exhaustive matrix:

- After actual IdP owner import and receiver verification, before `record_node_join_stage(Idp)`.
- After actual Management owner import and receiver verification, before its stage journal.
- After actual `verify_node_join_public_readiness`, before PublicReady publication.
- After successful PublicReady publication, before completion returns.

Private cfg(test) task-local one-shot errors occur at the actual production call sites; absent from non-test builds, no public hook or new framework. Every selected error must match exactly, so an earlier unrelated failure cannot masquerade as a checkpoint. Each interruption drops all joining owner database handles and reopens native owner/policy stores while retaining the same endpoint and injected private-key store. Assertions require exact request/receipt/member/endpoint/key references, actual imported trust and private signer verification, policy grants after policy import, missing journals before retry, and current readiness false until PublicReady exists. Actual production receive retries publish missing import journals. PublicReady exact retry and existing source-disconnected driver/reopen/revocation assertions follow. Exact trust validation includes unique member/signer/Device binding; no receipt-derived readiness is asserted.

These assertions remain UNEXECUTED. In-process errors/native database reopen are not process kill, power loss, partial-row import, endpoint-process restart, GUI approval or real OS-provider fault qualification. Existing partial-bootstrap work belongs to another branch and is not superseded here.

## Device completion assessment — separate seam

Read-only audit of `apps/app/src-tauri/src/setup_completion.rs` and `app.rs`:

- `interrupted_completion_resumes_and_corruption_is_preserved` covers both `setup-ready` and `device-setup-ready`: partial temporary marker retry, exact retry, Installation mismatch, corrupt-final preservation.
- `completion_never_follows_a_symlink` covers temporary/final Device marker symlink refusal and unchanged target.
- `completed_node_with_unavailable_local_contexts_preserves_completion_for_retry` covers retained markers and local unavailable/ready classification; it supplies readiness as a boolean, not a composed runtime success.
- `complete_device_setup` checks Installation completion, current composed runtime public readiness, nonempty localhost base and actual localhost verification before writing Device completion. This source ordering is NOT execution evidence for interruption between localhost verification and Device marker publication.

No Device/Tauri composed success claimed. Marker tests are marker-seam evidence only, not TLS/runtime/current-trust publication evidence. No app.rs, localhost_server.rs or setup_completion.rs edits or new profile/provider/CA operations.

## Validation and exact pending commands

Passed lightweight checks: scoped rustfmt (edition2024, skip_children), `git diff --check`, `python3 scripts/check_server_dependencies.py` (no direct server-to-server dependency edges). No Rust build/test/Clippy/hack/CRAP run; no TDD red/green result. No ticket/map/status/checkbox change or root merge.

After coordinator grants an exclusive slot, from `of/.worktrees/bounded04-durable-evidence`:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=1 RUST_MIN_STACK=134217728 cargo test -p unified-server --no-default-features --lib --offline --locked --target-dir /home/nathan/code/rust/aicacia/of/.worktrees/bounded04-durable-evidence/target production_durable_transitions_preserve_imports_and_verified_readiness_on_reopen -- --nocapture --test-threads=1
```

Use an outer 600000ms bound; internal test bound remains360s. Run existing orchestration regression separately with the same options and filter `desktop_bootstrap_orchestration_completes_both_public_contexts_and_retries_offline`. Both remain pending; do not report either as passing from source inspection. Dedicated target only; no shared target cleanup. Device marker/composed commands are not part of this pending Unified gate and require separate coordination if requested.
