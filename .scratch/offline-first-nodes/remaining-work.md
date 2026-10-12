# Scoped completion and follow-ups — ticket08, 2026-10-12

## Current completion

`of`01–08 and the [spec](spec.md#local-qualification-summary--2026-10-12) are resolved under the approved Ubuntu Linux x86_64 machine-local policy. [08 Answer](issues/08-offline-node-integration-and-final-validation.md#answer) maps all eleven criteria to final composed and inherited evidence, including ofdb05/offs03 and their concrete prerequisites. Ofdb06 consumes existing producer evidence; it is not a reverse acceptance gate. No speculative ofnet rewrite is needed.

This closure is **not** broader platform/provider/GUI/deployment/WAN or exhaustive recovery certification. No code or builds are part of this completion-doc pass. Existing consumer branch `offline-first-ticket08-full-nodes`, worktree `of/.worktrees/ticket08-full-nodes`, is retained; no main merge/push or worktree/archive retirement here.

## Exact qualifying source and command receipts

| Item                                                          | Exact source / receipt                                                                                                                                                                                 |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Clean consumer runtime                                        | `d9e40eb4e903f8e073e3a8c35fd879b6e1ad3806`, cleanup `ba7cfc2d6b75fbfe9f71b8cfc93137fd85345101`                                                                                                         |
| Original clean owner used by final runtime                    | `5b08d0ddc6e2c19a8be29af13fe5af6133b791a6`, clean implementation `72aae34b75f0fd65f4feadfb49e13ae948b41f6c`, `integration/native-catalog-reuse`                                                        |
| Clean all-three + repeat + probes + rotation, format/boundary | [08-final-clean-validation](evidence/08-final-clean-validation.md), receipt `4492dcc8ab6f524e44fd0136de993dacd7cb263c`; runs34–40 each1/0 exit0,43/44 exit0                                            |
| Final secret-safe assertion source                            | `6341cf1ec353dd4d73f93dd8879678f439af1978`, no production/permission/transport/scenario change                                                                                                         |
| Affected final assertion validation                           | [08-secret-safe-assertions](evidence/08-secret-safe-assertions.md), receipt `707e68bc008f907394442d76a964473a04beeb81`; offline45/grants46/probes47–48 each1/0 exit0                                   |
| Generic clean-owner qualification                             | [16-qualified-integration](../../../ofdb/.scratch/storage-sync/evidence/16-qualified-integration.md):30 passing focused tests, core/native/strict scoped Clippy/format and exact command/hash receipts |
| Final source ownership inventory                              | [08-consumer-final-source-plan](evidence/08-consumer-final-source-plan.md#meaningful-final-code-delta-from-main); historical planned checks superseded by actual final receipts above                  |

Literal filters, resource-bounded argv, actual dependency paths, wrapper exits, timings and raw hashes remain in the linked receipts and adjacent `.json`/`.status`/`.log` files. Rust invocations were serial, jobs1/offline/locked, existing shared target/profile,4G/zero service swap/900s outer bounds, unchanged10s HTTP/360s pair/120s probe bounds. These are executed-source samples, not universal latency/memory or zero-flake guarantees. No fresh execution or synthetic combined run is claimed here.

Final restrictions34/37 are retained at their producing clean source; affected45–48 qualify comparison-diagnostic-only6341cf1. Restrictions/control bodies and successful conditions were unchanged, not newly rerun. The pair proves learned fail-closed/no-overwrite on retained sockets after an actual pre-learning write/read success control, not a unique typed policy rejection versus every transport failure. Exact current-state policy/namespace/queued/in-flight SQL/KV/FS guarantees come separately from03. The fixture seeds the genuinely approved joined Device's empty policy through the existing repository; automatic join-policy creation is not proven by it.

## Reviews and remaining coordination

[Completed coordinator review-tool receipt](evidence/08-final-review.md): code QA `7473b005`, owner cleanup `e972727d`, security `d45a9bea`, design `777a9393`, architecture `3f5cf242` approve the scoped delivery with no new actionable blocker. Security follow-up on6341cf1 is complete: LOW assertion-output disclosure resolved, no actionable security issues; narrowed retained fail-closed/no-overwrite and the existing pre-learning success control confirmed exactly. These coordinator tool-result session IDs are distinct from Git source/runtime receipts, not user-authored source evidence or new test executions.

Later coordinator actions: review the completion-document diff, deliberately integrate qualified consumer/owner branches when authorized, archive raw evidence with source/argv/status/hash mapping before any retirement. No branch cleanup, reset/rebase, main merge, push, provider/profile/CA operation, cache pruning or target cleanup is implicit. Any new concrete review defect remains actionable; pending coordination is not falsely described as finished review.

## Baseline Clippy diagnostics — not all green

[Final gate attribution](evidence/08-final-clean-validation.md#focused-gate-results-and-inherited-lint-attribution): strict41 `cargo clippy --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib --tests -- -D warnings` failed exit101 on unchanged `runtime.rs:708` `clippy::collapsible_if`. Diagnostic42 with `--force-warn clippy::collapsible_if` also failed exit101, exposing eight inherited test errors:

- `endpoint.rs:646`: `unnecessary_to_owned`.
- `local_provisioning_tests.rs:77` and `runtime.rs:1181,1186,1190`: four `field_reassign_with_default`.
- `node_bootstrap_interruption_tests.rs:744,773,875`: three `drop_non_drop`.

Baseline attribution is documented structurally in the receipt. Neither command passed; no suppression, arbitrary unrelated repair or lint-clean claim. The spec requires recording existing diagnostics, and coordinator accepts scoped completion with those baseline failures explicit. Client/API/app/package source unchanged: no additional client build applicable;06's client evidence remains separately attributed. Format and `CARGO_NET_OFFLINE=true just boundary-check` actually passed. No full-workspace/all-platform/Cargo Hack/CRAP sweep was run for final08.

## Deferred qualification and exact limits

[Machine-local follow-ups](spec.md#deferred-qualification-follow-ups-not-ticket-closure-gates) remain:

- GUI approval/profile-B completion/two-profile GUI offline restart remain deferred, not observed.
- Real provider success is scoped to its recorded Linux session/Unix protection. Pair credential injection and fault callbacks do not establish OS-provider availability.07 stopped same-Node filesystem restore retains its original mock protected provider; no provider export/import/loss, populated-content, stale-snapshot or crash-consistent recovery claim.
- Windows/macOS, headless/unattended/container runtime, physical devices/WAN/NAT/relay, exhaustive feature/fault/crash/concurrency matrices require their intended environment before advertising support. Static recipes and same-host domain-protocol partition are not deployment or air-gap certificates.
- Detached owner mesh tasks lack a universal public join guarantee. Managed ordinary teardown does not prove OS-process exit or arbitrary forced-abort completion.
  -03 same-genuinely-issued-bearer expiry across a response gate remains supplementary unqualified evidence, not an added08 blocker. Exact pair rejection causality is inherited/seam-separated as above.
  -05 remote streaming and durable per-path Residency remain unsupported/unqualified seams; no remote erasure/global immediate revocation/global OAuth single-use guarantee. TLS hostile path races and interrupted concurrent multi-consumer rollout are not newly certified.

## Historical checkpoints and recovery — not current frontier

Historical failures and diagnostic state remain meaningful only at their source; do not relabel them as passes or reactivate obsolete instrumentation as a completion prerequisite:

- Initial pair `19db0df9e124c626bde56cde99d7133e3ab3e8b0`, checkpoint `57426e363d413d3f29b16665459605683e9ad52f`: [08-full-nodes](evidence/08-full-nodes.md) retains failed06–08, small controls, IdP instrumentation `d2720cb`, diagnostic lock `437c9bf`, native profiling compile-OOM and subsequent receipts. Earlier owner diagnostic `b1d957d8afb33b0cb9e6981d6a09793d97659e35` / receipt `b21c5839ee7f0578be891e9c8aae6d1b687e108f` can be retrieved read-only with `git --no-pager show b21c5839ee7f0578be891e9c8aae6d1b687e108f:.scratch/storage-sync/evidence/16-native-idp-stage-timing.md` from ofdb; no checkout change needed.
- [Reviewed owner rerun](evidence/08-reviewed-owner-rerun.md) retains `f0be1aa` / owner `6ffb434` control GREEN and failed pair09–11. Both offline reopens/A completion were partial progress then, not a completed B journey.
- Diagnostic consumer source `0dce5e0c1cd36cdb4e4e7f7ba81ce28f8e9073dd`, receipt `26ad55d740f99f3793d021722cd1f81b2d3b412e`: [08-consumer-diagnosis](evidence/08-consumer-diagnosis.md) preserves failed12–14 and generic timing handoffs; repeated live authorizations/native work were not deadlock or unique bottleneck proof.
- Field/table/raw-table/SELECT correction receipts and failed restrictions26 remain linked in [qualified owner provenance](../../../ofdb/.scratch/storage-sync/evidence/16-qualified-integration.md) and the adjacent consumer `08-reviewed-*-correction-rerun.md` records. Instrumented-source30–33 passes precede clean-source34–48 and are not silently substituted for them.
- [Coordinator cleanup/recovery receipt](../worktree-cleanup/2026-10-12/README.md) preserves archived auxiliary worktrees/user stashes and recovery-only refs. Old auth/partial-bootstrap drafts remain recovery material, not merge candidates.

Raw logs currently remain in **this consumer worktree's evidence directory**, including ignored final argv/status/log artifacts. Historical hashes remain unchanged. Preserve sibling links, shared targets, root dirty lock/user work, stashes, private stores and external provider state. Coordinator archive should retain exact tested revisions and raw hashes before later deliberate worktree/diagnostic-branch retirement.
