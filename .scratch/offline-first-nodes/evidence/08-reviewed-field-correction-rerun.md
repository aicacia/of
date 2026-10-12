# Reviewed owner field correction — grants GREEN, restrictions still RED

2026-10-12. No main merge, ticket/spec closure or acceptance-box change. Consumer diagnostics only; no speculative behavioral fix. Offline not run: the user-conditioned grants + restrictions pass prerequisite was not met.

## Provenance / constraints

- Consumer initially clean `26ad55d`, existing `offline-first-ticket08-full-nodes` worktree. Runs15–17 use that unchanged source. Run18 uses diagnostic-only `096daee` (filesystem-create initial authorization/mutation/response authorization timers); run19 uses diagnostic-only `99d8710` (Storage introspection local-owner timer and owner-policy cleanup admission/IdP owner/reconcile/policy timers). No fixtures, assertions or behavior changed.
- Owner clean before/after at `1ae1ba26d6610e547013c777ccb21a5515e1ae31`, branch `diagnostics/native-idp-stage-timing`, containing independently approved `89e85d39e1f8ea700ddb1239d02a1f1c327b108a`. No owner edits/builds by owner during this slot.
- `realpath ../ofdb/crates/{sql,sql-engine,sql-engine-automerge}` individually verified to original `/home/nathan/code/rust/aicacia/ofdb/crates/...`. Compile output uses existing `of/.worktrees/ofdb` links. Low-level signature change compiled through the consumer; no public-facade migration or consumer RowCodec implementation change needed.
- Exclusive serial builds, preflight/end no other cargo/rustc process. Preflight available17423MiB, host swap414MiB used. Every launch systemd **4G / MemorySwapMax0 / RuntimeMaxSec900**, terminal910000ms, offline/locked/jobs1, shared `/home/nathan/code/rust/aicacia/of/target`, unchanged optimized+debuginfo profile and RUST_MIN_STACK67108864, unset RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS. No cache/profile/provider reset, prewarming, shared stores, permission weakening or deadline increase. HTTP10s / pair360s / probe120s retained; no probe test run.
- CRP: existing-seam reruns and fixed-label timers low complexity; authorization/reconciliation behavioral changes high risk. Approved test seams remain composed public owner HTTP and authenticated DATA/security synchronization. No new test/behavior seam invented.

## Outcomes

Filters below have prefix `local_provisioning_tests::full_nodes::`; all launches `-p unified-server --lib`, exact/nocapture/test-threads1. Runs15–17 use historical **no extra features/environment**. Runs18–19 diagnostic only add `--features cli` and `OF_IDP_STAGE_TIMING=1`.

| Run | Literal filter suffix | Compile | Actual result | Wrapper exit |
| --- | --- | --- | --- | ---: |
|15|`two_completed_full_hosts_reconcile_consumption_and_revocation`|9m56s|Service900s timeout during final B refresh; **no test result**.|1|
|16|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|0.50s|0pass/1fail/77filtered,210.26s; B filesystem creation HTTP timeout.|101|
|17|`two_completed_full_hosts_reconcile_consumption_and_revocation`|0.41s|**1pass/0fail/77filtered,305.44s**, including ordinary pair shutdown.|0|
|18|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|5m42s|0pass/1fail/78filtered,219.77s; same B filesystem timeout with stage logging.|101|
|19|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|5m14s|0pass/1fail/78filtered,223.35s; same B filesystem timeout with finer local-policy logging.|101|

Run15 timeout is compile + runtime combined, not a 360s scenario failure or OOM. Both hosts ready151.784400s; reconnect163.892147s, endpoint163.894319s, reconciled300.213718s; B consumed-grant denial returned, final revoked-grant request then service killed TERM at15min180ms. Peak4.0G reported; timeout status is not evidence of OOM. The explicitly reported warm retry17 retained all caps/semantics, not a hidden retry/deadline increase.

Run17 both hosts ready152.037534s; reconnect163.931360s; connected163.933018s; **reconciled298.537458s**. B then returned two HTTP400 invalid_grant responses for learned consumed/revoked grants. `focused slice stopped`305.426156s and test GREEN305.44s. This establishes ordinary teardown for this grants slice, not all final pair slices or deployment/provider shutdown qualification.

Run16 A restriction2044.504328s, B restriction204**7.263916s**. B restriction GET2006.907454s. B filesystem POST entered; nested service token2002.704670s and two introspections2002.457413s/2.480449s before helper366 transport timeout. Management reconnect/retained-socket learned denial unreached. No storage POST201 logged. Client timeout does not prove no mutation.

## Exact stage attribution of the continuing Storage failure

Production path `storage-server/src/router/resources.rs::create_file_system`: initial `authorization` -> namespace/write checks -> `ScopedFileSystemRuntime::create_resource` -> `authorize_response` (current token/namespace/action recheck). No check removed or cached. `IdpClient::introspect` also calls `LocalReplicationAuthorizer::local_owner`; the production Unified callback serializes local cleanup, reads current approved Device/owner, reconciles transfer cleanup, evaluates current replication policy and activates the owner.

Run18 B restriction2048.984622s. B filesystem:

- Initial authorization **6.711317s**; nested token1.727109s and introspection2.939369s. Remaining time includes current local owner policy, not identified by old IdP-only timers.
- Resource mutation **0.009671s** completed.
- Response introspection200 **3.117298s**; response-authorization completion absent before failure.

Run19 B filesystem:

- Initial authorization **6.707333s**; service token200 **1.841292s**, introspection200 **3.236278s**, `storage_introspect.local_owner_policy` **1.627140s**.
- Within that awaited local policy, cleanup admission **0.817840s**, approved Device/owner **0.619024s**, reconciliation **0.059989s**, replication policy **0.129678s**. These adjacent stages explain essentially the measured local-policy interval; other owner-policy records are interleaved/background and must not be attributed to this request.
- Resource mutation **0.009848s** completed. This is a completed internal mutation stage, not an HTTP201, durable restart/read qualification or proof of no effect.
- Response introspection returned200 **3.634124s** during failure handling; response local-owner/authorization completion absent. Initial authorization + mutation + this HTTP interval already total10.351305s, before further response local-policy work. Caller10s timeout retained; no whole POST201 marker.
- Some cleanup-admission intervals around0.819s are interleaved with background policy work; do not identify their holder/host solely from label order. No deadlock is proven.

The old cold B Management PUT bottleneck did not recur in16/18. The remaining failure is accumulated successful current-state authorization on B's resource-create path, not a reported invalid grant, unauthorized Device or slow filesystem mutation.

## Generic residual / consumer boundary

Owner correction removes the duplicate field reconstruction inside conflict codec: run18 complete logger interval has650 `conflict_document_columns` records sum0.870569s/max0.002323s and678 codec records sum1.005393s; old run13 had224 column records sum4.036619s. Different workloads/windows: not an isolated before/after benchmark.

For the narrower run19 interval from the last `08 HTTP begin: POST /storage/filesystems` through raw-log end:1933 catalog reconstructions sum7.562160s;198 engine conflict-schema records sum4.643144s;198 codec records sum0.336346s;331 native admissions sum2.162318s/max1.018761s. Includes two hosts/background/failure aftermath, nested stages; not exclusive request CPU. Generic remaining schema/catalog costs are real; not proof of a sufficient next correction.

Exact owner seams at `1ae1ba2`: `sql-engine/src/executor.rs::row_conflicts` -> `schema::table_schema_with_fields` still reconstructs schema for each conflict operation; codec now receives that operation's raw fields. `sql-engine-automerge/src/codec.rs::columns` still performs other current catalog reconstruction; `btree-redb/src/database.rs::transaction` still measures real writer admission. Consumer owner-policy serialization also contributes, as measured above. Any further optimization needs its own root-cause evidence and tests preserving current trust, conflict/snapshot semantics, transfer cleanup, post-mutation authorization and mutable-kernel/fallback contracts. No generic rewrite or consumer shortcut absorbed here. `row_conflicts.* count=0` remains the timing default, not a conflict count.

## Exact command / raw provenance

All commands use this common literal argv, with unit and filter chosen by table:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-owner-field-grants-17 --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::full_nodes::two_completed_full_hosts_reconcile_consumption_and_revocation -- --exact --nocapture --test-threads=1
```

Units15/16/18/19: `of-ticket08-owner-field-grants-15`, `of-ticket08-owner-field-restrictions-16`, `of-ticket08-owner-field-storage-stage-18`, `of-ticket08-owner-field-policy-stage-19`. Diagnostics18/19 insert `OF_IDP_STAGE_TIMING=1` after unset flags and `--features cli` before `--lib`. Adjacent raw `.json` files retain exact argv and `.status` files the wrapper exit. Subprocess captures merged stdout/stderr, mirrors live, no status masking. New raws stay ignored; only this compact receipt is committed.

| Raw basename (under this evidence directory) | Invocation ID | SHA256 of `.log` |
| --- | --- | --- |
|`08-owner-field-grants-run15`|1614cc12325a47a1953abaa8cc8466ef|b163d2f9272483fa73c55f05a4ade74f05a80ed91d69b98b78f2bd41a97fa5b1|
|`08-owner-field-restrictions-run16`|291674b353e8411c98a2c13d9f91046f|5bb5ea0c910191cc927145c445966855c8b48a1ddcb9640b5266416bf04124a5|
|`08-owner-field-grants-run17`|8cd94569764d440ea7b256c2faedfabc|453a2bc650ef5397b859a823b43e7be19b4550acb9f179847fbada04dab96db3|
|`08-owner-field-storage-stage-run18`|5ac9dc6ef66b44c2903a8b2603b716dc|e4a60981346b9ecb57e59adaa42af474f5aebc884486f9b699b06fe34c7519fa|
|`08-owner-field-policy-stage-run19`|2e2b50e55ce64707a9761468d48ba5b4|3f61152f3c2352e78946ed51f3c758d720c0cf37e39cff5bc9adb912f59c94a1|

Stage aggregates obtained by grouping raw lines matching `\] (\S+) elapsed_us=(\d+)`; no secret/token/SQL values added. Old ignored reviewed receipt/raw09–11/native-stage-run03 untouched; checked SHA256 still matches the earlier reviewed receipt. Implausible256–512K memory peaks on later services are not RSS/headroom guarantees.

## Remaining gates

Changed-file rustfmt check and git whitespace checks passed. Compiled and exercised both diagnostic commits in18/19. No Clippy/boundary/client/full sweeps or independent review of new timers claimed; no behavioral-fix green claim. Pre-existing git GC/unreachable-object warnings retained without pruning.

Grants/revocation reconciliation + ordinary grants pair teardown now GREEN at the exact source above. Restrictions still RED before Management reconciliation; learned denial/retained data and restrictions ordinary teardown unqualified. Offline not executed this session; previous offline09 failure remains. Final pair ordinary teardown across relevant slices, independent final source review and applicable focused final gates remain outstanding. No main merge, tracker Answer or spec closure. Exclusive build slot released; no build/test service left running.
