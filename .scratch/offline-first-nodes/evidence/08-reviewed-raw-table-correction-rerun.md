# Reviewed raw-table correction — all three passing source-qualified runs; timeout retained

2026-10-12. Existing exact filters now each have a passing **unchanged-feature** run and ordinary pair teardown at one stable source pair. **Not a clean first-pass sweep or repeatability/deadline guarantee:** restrictions26 timed out, diagnostic28 passed, unchanged retry29 passed. No main merge, spec/ticket Answer/acceptance-box change or final-gate claim; parent review still required.

## Exact provenance / constraints

- Consumer clean and unchanged throughout all five runs: `377066b4452487e76a2e00208d51757cc6f8d3fc`, branch `offline-first-ticket08-full-nodes`, existing task worktree. No source/tests/instrumentation/manifest/lockfile edits in this session; evidence-only delivery.
- Owner clean before/after and unchanged: `e15424f3d29c0ee50ae31f84396fb4541d3465dc`, branch `diagnostics/native-idp-stage-timing`, includes independently approved same-operation raw-table snapshot correction `2bbb158` plus earlier reviewed corrections. User reports original largestUUID semantics preserved. Consumer compiled successfully against source-breaking low-level trait update; no public facade/consumer migration required.
- Realpaths for `../ofdb/crates/sql`, `sql-engine`, `sql-engine-automerge` each resolve original `/home/nathan/code/rust/aicacia/ofdb/crates/...`; compile output uses existing sibling `of/.worktrees/ofdb` links. No owner source edit/build by owner during slot.
- Exclusive serial builds; no other cargo/rustc observed at preflight/end. Preflight available17049MiB, host swap407MiB used. Each launch systemd **MemoryMax4G / MemorySwapMax0 / RuntimeMaxSec900**, terminal910000ms; jobs1/offline/locked/shared `/home/nathan/code/rust/aicacia/of/target`, unchanged optimized+debuginfo profile, RUST_MIN_STACK67108864, unset RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS. HTTP10s/pair360s/probe120s retained; no probe test run. No prewarming, shared repositories, cache/profile/provider reset, permission weakening or deadline change.
- CRP: validation through existing approved production seams low complexity; authorization/cleanup behavior high risk and left unchanged. No new test seam, matrix or diagnostic code.

## Actual results, including the failed attempt

All exact filters use prefix `local_provisioning_tests::full_nodes::`, package `unified-server`, `--lib`, `--exact --nocapture --test-threads=1`.25/26/27/29 retain historical no-extra-feature command.28 adds only existing `--features cli` and `OF_IDP_STAGE_TIMING=1` to profile26's continuing failure.

| Run | Literal filter suffix | Compile | Test result | Exit |
| --- | --- | --- | --- | ---: |
|25|`two_completed_full_hosts_join_partition_reopen_and_learn_denial`|9m58s|**1pass/0fail/77filtered,286.57s**; both disconnected journeys and final teardown.|0|
|26|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|0.41s|0pass/1fail/77filtered,193.73s; B filesystem-create transport timeout before reconciliation.|101|
|27|`two_completed_full_hosts_reconcile_consumption_and_revocation`|0.40s|**1pass/0fail/77filtered,293.42s**; learned B grant denials and final teardown.|0|
|28|`two_completed_full_hosts_learn_restrictions_on_retained_sockets` (diagnostic features)|4m17s|**1pass/0fail/78filtered,350.53s**; failure not reproduced, teardown completed.|0|
|29|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|0.46s|**1pass/0fail/77filtered,346.52s**; unchanged-feature qualification retry, teardown completed.|0|

Run25 service14min44.989s: compile+test fit900s, no cap interruption, warm offline retry unnecessary. Other service runtimes26:3min14.248s,27:4min53.928s,28:10min7.997s,29:5min47.079s. All ended exit-code/success as listed, not OOM or service timeout. Reported memory peaks256–292K are implausible, not actual RSS/headroom evidence; service swap accounting0B is not host-wide zero swap.

## Completed production-seam behavior

**Offline25:** both composed hosts ready139.267680s; local A/B concurrent grant winner/loser/replay checks completed143.071277s/148.743297s. Both stopped150.190267s and reopened disconnected174.286952s. Retained endpoint identities, local credentials/signer trust, public completion, consumed-grant denial and approved JWKS assertions completed. A independent identity/policy/resource/User+Client issuance journey complete217.961714s; **B complete285.124468s**. B resource POST2019.684547s under unchanged10s, resource socket write/read checks, deletion204 and GET404 completed. **Final ordinary pair teardown complete286.552274s**, test GREEN286.57s. Both reopened journeys genuinely completed, not inferred from readiness or a mutation timeout.

**Grants27:** authenticated IdP reconnect156.586483s, endpoint connected156.588840s, reconciled289.649857s. B then returned genuine HTTP400 invalid_grant for both learned consumption/revocation. **Ordinary pair stop293.410034s**, test GREEN293.42s.

**Restrictions29:** authenticated Management reconciliation277.236088s. Existing retained-socket learned restriction assertions, restoration/readback of committed content, resource deletion and404 checks completed for both hosts. **Ordinary pair stop346.512197s**, test GREEN346.52s. This qualifies the existing representative restrictions slice, not a new operation-kind/failure matrix or deployment/provider shutdown guarantee.

Together unchanged25/27/29 prove the existing three slices at stable consumer377066b/ownere15424f. They do not erase26 or replace parent source review/final gates.

## Restrictions26 failure and bounded existing-timer investigation

B restriction PUT2048.153402s, restriction GET2006.007018s, then B filesystem POST client timed out at helper366. Nested service token2001.681706s and introspections2002.204019s/3.162297s. A server POST4019.863735s was logged after panic during failure handling. `Host::drop` cancels the runtime; output ordering/cancellation races prevent attributing that401 to an independent pre-timeout permission rejection. No whole201/retained B resource/reconciliation/ordinary stop in26. Mutation no-effect cannot be inferred.

Existing timers were sufficient for28, no additional instrumentation. The diagnostic **passed**, so it did not reproduce or causally fix26. Its B filesystem path:

- Initial authorization **5.406767s**: service token1.530603s, introspection2.158467s, awaited local owner policy1.713785s.
- Resource mutation **0.011676s** completed.
- Fresh response authorization **3.924335s**: introspection3.179934s and local owner policy0.743617s.
- Whole POST201 **9.342915s**. Both required current-state authorization checks retained.

Same source, differing successful/failed wall intervals: no demonstrated consumer defect/fix or specific owner correction beyond approved code. Successful offline B POST9.684547s, diagnostic B POST9.342915s and restrictions29 near360s leave limited scheduling/latency margin. Report this variability to parent; do not call it universally stable10s behavior or retry away failed evidence. One explicit unchanged-feature retry29 after diagnostic GREEN distinguished the feature-qualified diagnostic from the actual requested filter; no hidden source/cap/fixture changes or further retry loop.

## Exact execution / compact raw provenance

Common exact argv shown for passing offline25:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-owner-raw-table-offline-25 --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::full_nodes::two_completed_full_hosts_join_partition_reopen_and_learn_denial -- --exact --nocapture --test-threads=1
```

Other units `of-ticket08-owner-raw-table-restrictions-26`, `of-ticket08-owner-raw-table-grants-27`, `of-ticket08-owner-raw-table-restrictions-stage-28`, `of-ticket08-owner-raw-table-restrictions-29`, with table filters.28 inserts `OF_IDP_STAGE_TIMING=1` after unset flags and `--features cli` before `--lib`. Ignored adjacent `.json` files retain exact argv; `.status` retain wrapper exit. Merged subprocess stdout/stderr captured/mirrored live, no pipeline masking. Only this receipt committed; raw artifacts/fixture IDs and pre-existing ignored receipts/logs preserved, not bulk-added.

| Raw basename (this evidence directory) | Invocation ID | SHA256 of `.log` |
| --- | --- | --- |
|`08-owner-raw-table-offline-run25`|654b69bab74e4aaaa3bce376a1fdf810|35e2e26280ebba47e2a19eec91cad0152742ef6fb7d3bb2e9890cd7450fee04b|
|`08-owner-raw-table-restrictions-run26`|e91100132c1641d4a6e5197699aa6d3c|e90182ef85d5e5da86a2dfa8a742864ca8ab2648847f737bfd90b09b0bc424e2|
|`08-owner-raw-table-grants-run27`|048ac0d011ce40dd9f16bf7a61578a00|f3fce19cbe70d8e676f648b1a60620c8f8235ee6c7f7bfd45ab93853f30881f7|
|`08-owner-raw-table-restrictions-stage-run28`|03c48b0da0954502975d444e1ce78b06|8011cb218fc31a393d1f99bbefe5d453a6a674acd433284c1035fe75ca9a16be|
|`08-owner-raw-table-restrictions-run29`|243df5abe1b6422fa9e5f768549efa3c|4c7e5bd2b4f3c7260a34beb3f491ad3d7c74f2f77c78503e1e89e71e01b5f062|

## Remaining review/gates

Git whitespace checks passed; no source edit or formatting change this session. No new instrumentation, permission/cache/deadline workaround, owner rewrite, Clippy/client/boundary/powerset/CRAP/full sweep or duplicated owner matrix. Previous ignored raw09–11/native-stage-run03 hashes rechecked unchanged. Pre-existing Git GC warnings retained without pruning.

All three unchanged-feature passing runs and teardown are now available for parent review at exact sources, **with restrictions26 instability explicitly retained**. Independent final consumer review, decision on this latency variability, inherited-evidence integration and applicable focused final gates remain outstanding. No ticket/spec closure/main merge/push. Exclusive build slot released; no build/test service left running.
