# Remaining spec work — ticket 08 handoff, 2026-10-12

## Current frontier

`of` tickets 01–07 are resolved within their recorded machine-local scopes. Ticket 08 remains claimed, with no Answer and no completion claim. `ofdb` consumer handoff 06 is now resolved from accepted of02/of03 evidence, not new test runs. Its qualification is not full-Node acceptance. `offs` extraction 03 is resolved; `ofnet` requires no speculative rewrite.

Finished `of` history through `290738b` is being consolidated into local main. The unqualified ticket08 source is **not merged**. Nothing is pushed.

## Exact source and receipts to retain

| Item                                                          | Location / revision                                                                                                        |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Live consumer worktree                                        | `of/.worktrees/ticket08-full-nodes`                                                                                        |
| Consumer branch / latest checkpoint                           | `offline-first-ticket08-full-nodes`, `57426e363d413d3f29b16665459605683e9ad52f`                                            |
| Pair slice source                                             | `19db0df9e124c626bde56cde99d7133e3ab3e8b0`                                                                                 |
| IdP stage instrumentation, independently source-reviewed      | `d2720cb7f759b825e613af5d8a4f1dde4be4e852`                                                                                 |
| Diagnostic consumer lockfile                                  | `437c9bf` adds three edges to the existing `log` crate                                                                     |
| Generic native instrumentation, independently source-reviewed | `ofdb`, branch `diagnostics/native-idp-stage-timing`, source `b1d957d8afb33b0cb9e6981d6a09793d97659e35`                    |
| Generic diagnostic receipt tip                                | `b21c5839ee7f0578be891e9c8aae6d1b687e108f`                                                                                 |
| Consumer full receipt and raw logs                            | [preserved worktree evidence](../../.worktrees/ticket08-full-nodes/.scratch/offline-first-nodes/evidence/08-full-nodes.md) |
| Generic diagnostic receipt                                    | `.scratch/storage-sync/evidence/16-native-idp-stage-timing.md` on the preserved ofdb diagnostics branch; retrieval below   |

Retrieve the diagnostic receipt without changing owner checkout state, from `ofdb`:

```sh
git --no-pager show b21c5839ee7f0578be891e9c8aae6d1b687e108f:.scratch/storage-sync/evidence/16-native-idp-stage-timing.md
```

`ofdb` root is now on **main**, without diagnostic instrumentation. The consumer dependency resolves to that original root through existing sibling links. For another profiling attempt, explicitly reactivate the owner diagnostic branch, or deliberately deliver its source into a suitable checkout; verify actual dependency paths and both source revisions. A clean consumer checkout alone does not establish the external owner source used. Its diagnostic lockfile is not the finished-main dependency graph.

Before implementation resumes, merge the updated `of` main into the ticket08 branch, and reconcile tracker/documentation changes without accepting the failing tests. Do not reset away its source or receipts. Owner diagnostics can similarly merge current owner main, retaining its instrumentation separately from finished work.

## Observed results, not inferred passes

- Three full-pair slices each failed under unchanged **360s scenario / 10s HTTP** bounds. Actual authenticated same-Installation join/import and both composed hosts' three-context readiness were reached. Source-A local refresh winner/replay denial was reached.
- Joined-B refresh competitor or sequential replay timed out; the restriction PUT timed out before reconnect. Pair offline reopen, post-reopen mutation/issuance, authenticated reconciliation and retained-connection learned denial remain unqualified.
- A minimal full-host probe passed in 63.09s. Adding four independent service Clients reproduced the restriction timeout; that earlier request later completed server-side HTTP204. **Caller timeout does not mean a mutation had no effect.**
- Latest two-worker IdP-stage probe built in 6m21s, then **0 passed / 1 failed, 81.06s, exit101**. Restriction PUT timed out at 10.001s. No restriction204 was logged in this run, so do not claim completed mutation for it.
- Latest timing buckets: service-token Client lookup **1.550s**, principal load **1.052s**, live validation **1.266s**; secret verification **0.164s**, JWT signing **0.0003s**. Introspection caller/actor authorization **2.517s / 1.356s**, additional Client loads **0.414s / 0.404s**; Device caller authorization **2.075s**. These are wall-clock buckets, not isolated DB/CPU costs.
- Native instrumentation retry was **OOM-killed during compilation** at 1500M, zero swap: 8m25.181s, memory peak1.4G. **The test never ran. No native bottleneck attribution or generic fix is established.**

## Smallest next investigations

1. Free sufficient machine memory before another build; last available memory was ~1.9GiB with full swap. Do not kill editor processes, prune caches or enlarge caps implicitly.
2. Reproduce the same four-extra-Client control with native timers. Separate transaction admission/begin-write/body/commit from conflict schema/catalog/document reconstruction. Log fixed stage labels/counts/elapsed time, not tokens, keys, secrets, SQL values or identity data. Logging itself can affect admission waits; do not treat missing records as zero cost.
3. Fix only the measured cause in its owning repository. Repeated Client/key/trust loading is observed; native read writer-admission/catalog/history costs remain hypotheses. Do not add caches, omit current permission/conflict checks, prewarm service tokens or increase deadlines to manufacture a pass.
4. Independently isolate joined-B refresh replay. Extra Clients alone did not reproduce it: single-host replay returned genuine `invalid_grant` within ~2–4s. Reuse production authenticated bootstrap into independent B native stores/private signer, retain the imported A refresh grant, then stop A and measure B alone. Distinguish imported history/two-signer trust from composed/background and two-host scheduling. Match the pair's two-worker executor. Use the native production IdP router first, then B-only full composition if needed; an IdP-only diagnostic is explicitly not completed-Node acceptance.

Relevant production symbols: `OAuth2Service::{refresh_token, verify_token_principal, validate_issuance_inputs, issue_tokens_with_refresh}`, `DbOAuth2RefreshTokenRepo::issue_refresh_token`, `DbReplicaSignerRepo::trusted_signers`, `KeyService::load_node_signer`, `UnifiedRuntime` peer-refresh task. In the consumer harness, reuse `Pair::new`, `join_host`, `NodeStores` and the native `issue_local_token` precedent. Replacement signing happens before consumed-state rejection; wasted work is source-proven, but is not yet the proven timeout cause. Preserve final atomic conditional consumption and replacement insertion.

## Required completion evidence after a real fix

Use the existing split tests and inherited acceptance, not a kinds × roles × failure matrix:

- Both completed Nodes restart while disconnected, then independently mutate identity/policy/resources and issue user/client tokens from persistent local trust.
- Durable local single-use/rotation, accepted partition divergence, independent private signers and approved issuer/JWKS; no global grant-consumption guarantee.
- Authenticated reconnect/reconciliation and a representative learned restriction/transfer followed by denial of the next operation on a retained connection.
- Reuse of03 SQL/KV/FS apply, queued-write, in-flight completion, cleanup, namespace and impersonation evidence; of05 policy/transfer/retirement evidence; of04/07 join/reopen/endpoint/TLS/provider/lifecycle evidence; ofdb05 and offs03 generic owner evidence. Do not rerun those matrices merely to duplicate attribution.
- Stable-source independent review of final ticket08 changes; integrate qualified work only.
- Applicable focused format/Clippy/client/boundary checks after acceptance. Record literal filters, provenance, failures and inherited warnings. No full Cargo Hack, CRAP, workspace/all-platform sweeps or deferred GUI retries.
- Append ticket08 Answer and update all acceptance boxes/map/spec only when actual results support them. Request final change review, then retire completed ticket08 worktree/diagnostic branches deliberately.

The machine-local policy narrows deployment/platform qualification, not authorization, confidentiality, integrity or persistence contracts. No secure-provider/profile reset, system CA mutation, new networking layer or generic owner rewrite is implied.

## Cleanup / recovery

[Cleanup receipt](../worktree-cleanup/2026-10-12/README.md) records archived auxiliary worktrees and preserved user changes. Historical branch work is not finished acceptance; do not merge obsolete drafts to reduce branch counts. Existing stashes, recovery refs, root targets, dependency symlink targets and external provider state remain preserved.
