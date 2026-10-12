# Reviewed table-identity correction — restrictions/grants GREEN, offline RED

2026-10-12. **No stable all-three pass or ticket08 acceptance.** No main merge, spec/Answer/acceptance-box change. Parent review and final focused gates still required even after a future all-three pass.

## Source and execution provenance

- Consumer clean at requested `821be10`, existing `offline-first-ticket08-full-nodes` worktree. Runs20–23 use this unchanged source. Only later change is diagnostic `101aff8`: three lines enabling the existing opt-in stage logger immediately before joined-B offline filesystem creation. Run24 uses that committed source; no fixture/assertion/behavior changes.
- Owner clean before/after at `45b6ea759e268e74cc5611a8cfbfa1e9ca7949a2`, branch `diagnostics/native-idp-stage-timing`, containing independently approved `46fe260` and earlier approved corrections. No owner source changes or concurrent owner builds. Consumer `sql`, `sql-engine`, `sql-engine-automerge` dependency realpaths each resolve original `/home/nathan/code/rust/aicacia/ofdb/crates/...`; compile output uses existing `of/.worktrees/ofdb` links.
- Exclusive slot; five launches sequential, no other cargo/rustc observed at preflight/end. Preflight available17381MiB/host swap401MiB used. All services **MemoryMax4G / MemorySwapMax0 / RuntimeMaxSec900**, terminal910000ms, offline/locked/jobs1/shared `of/target`, unchanged optimized+debuginfo test profile, RUST_MIN_STACK67108864, unset RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS. No cache/profile/provider reset, prewarming, shared repositories, deadline or permission changes. Existing HTTP10s/pair360s/probe120s retained; no probe test run.
- CRP: existing-seam validation and logger enablement low complexity/risk; trust/authorization/cleanup behavioral changes high risk and not justified here. User-approved seams remain composed owner HTTP, independent native stores, authenticated DATA/security sync and retained operations. No new matrix or test seam.

## Literal filters and actual outcomes

All filters below have prefix `local_provisioning_tests::full_nodes::`, exact/nocapture/test-threads1, `-p unified-server --lib`. Runs20–23 retain historical **no-extra-feature commands**; only24 adds `--features cli` and `OF_IDP_STAGE_TIMING=1` for diagnostic logging.

| Run | Literal suffix | Compile | Actual outcome | Exit |
| --- | --- | --- | --- | ---: |
|20|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|9m31s|Service900s timeout after Management reconciliation and substantial retained-socket/recovery progress; **no test result**.|1|
|21|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|0.51s|**1pass/0fail/77filtered,345.39s**, ordinary pair teardown.|0|
|22|`two_completed_full_hosts_join_partition_reopen_and_learn_denial`|0.39s|0pass/1fail/77filtered,263.91s; B offline filesystem POST timeout.|101|
|23|`two_completed_full_hosts_reconcile_consumption_and_revocation`|0.40s|**1pass/0fail/77filtered,294.10s**, learned B grant denials and ordinary teardown.|0|
|24|`two_completed_full_hosts_join_partition_reopen_and_learn_denial`|4m30s|0pass/1fail/78filtered,285.25s; same B resource-create timeout with stage logging.|101|

Run20 service15min35ms/TERM, reported memory peak4.0G: combined compile + test900s timeout, not OOM or a360s scenario failure. Management reconciled278.687021s; final test result/teardown not reached. Explicit warm retry21 retained the same command/caps/semantics; not a hidden deadline increase. Later memory peaks256–512K are implausible, not actual RSS/headroom evidence.

### Genuine passes, limited to their exact scopes

Run21 Management reconciled277.001226s, retained-socket learned restriction assertions/recovery/readback and resource deletion/404 checks completed, `focused slice stopped`345.376133s, test GREEN345.39s. This is ordinary pair teardown for the restrictions slice, not deployment/provider qualification.

Run23 IdP reconnect156.785212s, endpoint connected156.786453s, reconciled290.041949s. B returned two genuine invalid_grant HTTP400 responses for learned consumption/revocation. `focused slice stopped`294.084433s, test GREEN294.10s. Both passes share unchanged consumer821be10/owner45b6ea7; no all-three claim follows.

### Offline progress and remaining failure

Run22 both completed hosts144.582534s; A/B local concurrent refresh winner/loser/replay completed149.199687s/156.561656s. Both stopped157.574701s and reopened without DATA sessions182.004588s. A completed independent identity/policy/resource/user+client issuance227.875263s. B reached identity mutation, client issuance, restriction PUT2048.106347s and restriction GET200, then filesystem creation timed out at helper366. Nested storage service token2001.760666s/introspection2004.327753s/response introspection2002.544716s; not the whole request. No B filesystem201, B journey-complete or final offline teardown marker.

Run24 also completed local races, both stopped/reopened disconnected196.684252s and A's full journey245.835412s. No B journey completion/final teardown. Logger activates only after B storage-token exchange, immediately before its resource POST; no prewarming or Management/token assertion changes.

## Exact offline B stage attribution at current owner

Production `storage-server/src/router/resources.rs::create_file_system` still performs initial token/local-owner authorization, resource mutation, then fresh response authorization. `IdpClient::introspect` retains current local owner-policy validation. No check cached/reused/removed across operations.

Run24:

- `filesystem_create.initial_authorization` **7.839503s**. Nested service token HTTP200 **3.750878s**; introspection HTTP200 **3.225871s**; awaited `storage_introspect.local_owner_policy` **0.860036s**.
- Within service issuance, signer/trust/private-key load **1.997057s**, Client lookup0.549765s, principal key/Client0.374878s, live validation0.558257s, secret verify0.175190s, root key0.095256s, JWT sign0.000224s. These buckets include waits, not isolated CPU.
- `filesystem_create.resource_mutation` **0.011995s**, completed. This is internal mutation progress, not a whole HTTP201, restart/read qualification or no-effect proof.
- Response introspection HTTP200 **2.518443s** during failure handling; response local-owner/authorization completion not logged. Initial authorization + mutation + response introspection already total10.369941s before further local policy. Client10s limit unchanged; no POST201.
- Completed cleanup-admission records during this logger interval are1–4us; the earlier restrictions-run19 ~0.818s local cleanup wait is not reproduced here. Owner-policy labels are interleaved/background, so do not attribute every nearby record or infer an absent timer is zero work.

Raw24 final-create interval (from last `08 HTTP begin: POST /storage/filesystems` through raw end):330 native admissions sum4.208823s/max1.632112s;213 rollback bodies sum5.136642s;117 commit bodies sum6.602428s.1369 catalog reconstructions sum7.309823s;198 conflict-schema records sum4.243780s;198 codec records sum0.351661s;365 schema-column catalog records sum7.457629s. These include both hosts/background/failure aftermath and nested wall times; **not exclusive B CPU/request latency**. `row_conflicts count=0` remains timing default, not actual conflict cardinality.

Current generic seams: `sql-engine/src/executor.rs::row_conflicts` -> `schema::table_schema_with_fields` still materializes current raw fields/schema per conflict operation; `sql-engine-automerge/src/codec.rs::columns` and schema column reads still have remaining catalog work; `btree-redb/src/database.rs::transaction` measures real writer admission. The approved same-operation identity fix is present and consumer compile succeeded. Residual catalog/admission cost is measured, not proof of a particular sufficient next owner correction. Investigate these current hot paths separately without changing snapshot/conflict/candidate/mutable-kernel contracts. Consumer source provides no proven authorization or deadline shortcut; no generic owner rewrite absorbed here.

## Commands, status and raw integrity

Common exact command, shown for passing restrictions21:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-owner-table-restrictions-21 --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::full_nodes::two_completed_full_hosts_learn_restrictions_on_retained_sockets -- --exact --nocapture --test-threads=1
```

Other units `of-ticket08-owner-table-restrictions-20`, `of-ticket08-owner-table-offline-22`, `of-ticket08-owner-table-grants-23`, `of-ticket08-owner-table-offline-stage-24`, with table filters.24 inserts `OF_IDP_STAGE_TIMING=1` after unset flags and `--features cli` before `--lib`. Adjacent ignored `.json`/`.status` files retain exact argv/wrapper exit. Merged subprocess stdout/stderr captured and mirrored live; no pipeline masking. Only this compact receipt is committed, not wholesale raw artifacts or fixture data.

| Raw basename in this directory | Invocation ID | SHA256 of `.log` |
| --- | --- | --- |
|`08-owner-table-restrictions-run20`|da558cb583b34f68b71fbf47586e8d19|326ebad87e323059eab6d713830829f129bc768cfc1d58bd9759988d226b6b9a|
|`08-owner-table-restrictions-run21`|d4750e5754a243cfb9d4c177cd818668|5c248cf751298284aadba3f8aaeee79ecceceaeaebc52d9aacdf7518832a852b|
|`08-owner-table-offline-run22`|d19fb05ea6a84aed918f7db89dfa3708|09921f9dd269ba7b4c1abea8c28ab3d0867ab1b07a6c429d4e0cf062a7ea9738|
|`08-owner-table-grants-run23`|22cfabe68b6c432e8ea83931dedacee7|ceba0019f38e5fcf7ee2759df01869f9faa5c90b1d28890516bc2f34716745e9|
|`08-owner-table-offline-stage-run24`|dcff8164b9594f10bf44c2a67a3a9794|9f7d3f23ed663f1a4127de6df9582a28b72cfa1446f224b849a72ac3f4d39186|

Aggregates group raw lines matching `\] (\S+) elapsed_us=(\d+)` within the stated interval. Fixed labels/counts/time only; no new token/secret/SQL-value logger. Previous ignored receipts/raw09–11/native-stage-run03 preserved; hashes still match reviewed receipt.

## Validation / next blocker

Changed-file rustfmt and git whitespace checks passed. Diagnostic101aff8 compiled/exercised in24; independent diagnostic review not claimed. No Clippy/boundary/client/powerset/CRAP/full sweeps or duplicate owner matrices. Pre-existing Git GC warnings retained without pruning.

Required stable **all-three passing source plus ordinary teardown is not achieved**: restrictions21 and grants23 pass at821be10/45b6ea7, offline22 fails at that exact source and24 confirms the remaining resource authorization latency with diagnostics. Offline B journey/final teardown, parent review and final focused gates remain outstanding. No speculative behavioral fix or closure. Exclusive build slot released; no build/test service left running.
