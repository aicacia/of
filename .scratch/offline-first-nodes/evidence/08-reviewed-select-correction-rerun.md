# Reviewed SELECT catalog correction — all three plus one restrictions repeat GREEN

2026-10-12. Requested bounded sequence completed: unchanged restrictions30, offline31, grants32, restrictions-repeat33 all GREEN at one unchanged source pair, including ordinary pair teardown. No retry, failure, diagnostic-feature run or instrumentation/source change this session. Historical restrictions26 failure remains retained; four passes are local qualification, not a universal deadline/repeatability guarantee. No main merge, ticket/spec closure or acceptance-box change; parent review/final focused gates remain separate.

## Exact source / resolved paths

- Consumer clean and unchanged for all four launches: **`be22adc86e1b1a375f65b0d544fde08f54a434ed`**, branch `offline-first-ticket08-full-nodes`, existing worktree `of/.worktrees/ticket08-full-nodes`. Evidence-only commit follows execution; no tests, fixtures, assertions, manifests, lockfile or deadlines changed.
- Owner clean before/after and unchanged: **`3ec105590794331d62f67f33ccc4a7f56e623351`**, branch `diagnostics/native-idp-stage-timing`, contains independently approved `defd321` plus earlier approved corrections. User reports nonjoin SELECT passes a same-operation complete raw catalog to codec, retaining original lookup/decoding rules and decoding all rows before predicates; semantic/sync-catalog tests independently accepted. No owner source review/test duplication or owner edit performed here.
- `realpath ../ofdb/crates/sql`, `sql-engine`, `sql-engine-automerge` each verified original `/home/nathan/code/rust/aicacia/ofdb/crates/...`; actual compile output uses existing `of/.worktrees/ofdb` sibling links. Source-breaking low-level trait update compiled through the consumer; public facade consumption unchanged.
- Exclusive slot: four sequential services, no other cargo/rustc observed at preflight/end. Preflight available15243MiB, host swap421MiB used. Each invocation **MemoryMax4G / MemorySwapMax0 / RuntimeMaxSec900**, terminal910000ms, offline/locked/jobs1/shared `/home/nathan/code/rust/aicacia/of/target`, unchanged optimized+debuginfo test profile, RUST_MIN_STACK67108864, unset RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS. Historical **no-extra-feature/no-stage-logger commands** preserved. HTTP10s/pair360s/probe120s unchanged; no probe test run.
- No cache/profile/provider reset, prewarming, shared repositories, permission weakening, new diagnostic code or matrices. CRP: existing approved seam verification low complexity; authorization/snapshot/cleanup behavior high risk and left unchanged. Independent full-Node production stores/HTTP/authenticated DATA/current-state authorization and existing retained-operation tests reused.

## Literal filters / exact results / margins

Filters have prefix `local_provisioning_tests::full_nodes::`; package `unified-server`, `--lib`, exact/nocapture/test-threads1. Each result **1passed/0failed/77filtered**, wrapper/systemd exit0.

| Run | Literal filter suffix | Compile | Test seconds | 360s minus reported test duration | Service seconds | 900s minus service duration |
| --- | --- | --- | ---: | ---: | ---: | ---: |
|30|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|9m47s|265.88|94.12|853.493|46.507|
|31|`two_completed_full_hosts_join_partition_reopen_and_learn_denial`|0.49s|223.51|136.49|224.114|675.886|
|32|`two_completed_full_hosts_reconcile_consumption_and_revocation`|0.35s|247.39|112.61|247.841|652.159|
|33|`two_completed_full_hosts_learn_restrictions_on_retained_sockets` (one explicit repeat)|0.41s|267.68|92.32|268.212|631.788|

Reported runner durations include harness/teardown and are rounded; arithmetic margins are descriptive, not isolated exact scenario deadline slack.30 compile+test fit900s, so no unchanged warm retry needed. No OOM, timeout, failing first attempt or hidden retry in this sequence. Service memory peaks256K are implausible, not actual RSS/headroom evidence. Service swap accounting0B is not host-wide zero swap.

### Observed HTTP-duration margins

Maximum of all completed `08 HTTP end` wall intervals in each raw log; these are **server middleware intervals, not client elapsed/deadline slack**, and include nested owner API requests. No whole HTTP request timed out in these four tests.

| Run | Max logged server HTTP seconds | Arithmetic10s minus max | Max operation | Joined-B filesystem POST201 seconds |
| --- | ---: | ---: | --- | ---: |
|30|6.264478872|3.735521128|Restriction PUT204|5.843433892|
|31|6.988472556|3.011527444|Filesystem POST201|6.988472556|
|32|1.729631832|8.270368168|Token POST200|Not exercised|
|33|6.242697233|3.757302767|Filesystem POST201|6.242697233|

Headroom is materially larger in these observed intervals than prior narrow-margin runs, but this is not an isolated CPU benchmark or promise for other host loads/fixtures. Historical run26 timeout at ownere15424f remains in its raw log and preceding receipt; this one restrictions repeat did not reproduce it at current3ec1055. Do not erase or relabel earlier failure as a pass.

## Completed behavior and ordinary teardown

**Restrictions30:** Management reconciliation219.701805s; existing learned restriction/retained-socket denial checks, restoration/readback of committed data, resource deletion and404 assertions completed for both hosts. Ordinary pair stop265.869200s, test GREEN265.88s.

**Offline31:** both full hosts118.246756s, A local concurrent grant winner/loser/replay complete120.929381s, B complete125.308013s. Both stopped126.161606s and reopened **without DATA sessions**146.197033s. Retained endpoint identities, private local credentials/signer trust, public completion, consumed-grant denials and approved JWKS assertions completed. A identity/policy/resource/User+Client issuance journey complete177.192230s; **B complete223.242402s**. Both independently created/wrote/read/deleted their resource and checked404. **Final ordinary pair teardown complete223.501007s**, test GREEN223.51s. Both disconnected offline journeys completed, not inferred from readiness or mutation timing.

**Grants32:** authenticated IdP reconnect129.437369s, endpoint connected129.438462s, reconciled244.369353s. B returned genuine invalid_grant HTTP400 for learned consumption/revocation. Ordinary pair stop247.379877s, test GREEN247.39s.

**Restrictions repeat33:** Management reconciliation218.586871s; same retained-socket/recovery/resource cleanup assertions completed, ordinary pair stop267.667904s, test GREEN267.68s. Exactly one bounded repeat after all three passed, not a matrix or retry-until-green loop.

These are machine-local representative full-Node tests at exact source. They do not prove a global single-use guarantee, all platform/provider/deployment behavior, or every owner operation/fault matrix; earlier owner/ticket evidence remains inherited rather than duplicated.

## Exact argv / raw integrity / status

Common exact command shown for30:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-owner-select-restrictions-30 --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::full_nodes::two_completed_full_hosts_learn_restrictions_on_retained_sockets -- --exact --nocapture --test-threads=1
```

Other units `of-ticket08-owner-select-offline-31`, `of-ticket08-owner-select-grants-32`, `of-ticket08-owner-select-restrictions-repeat-33`, with literal table filters. No extra features/environment/instrumentation. Adjacent ignored `.json` files retain each complete argv, `.status` each0. Subprocess captures merged stdout/stderr and mirrors live; no pipeline status masking. Only this compact receipt committed; new raw logs and old ignored artifacts preserved, no bulk artifact/fixture/secret commit.

| Raw basename (this evidence directory) | Invocation ID | SHA256 of `.log` | Status |
| --- | --- | --- | ---: |
|`08-owner-select-restrictions-run30`|cbd99488bbd6428e80f9f4c98add8c82|39f67dd8c227136690495e774f262199f696e05827aa4f3467ad24a1d62fd223|0|
|`08-owner-select-offline-run31`|5318b5df5fba4957ba617926717e6b4b|1bd80df3baad1e7a2a422c6eee81cc7b89dfdcf844c9776ffce6ed67d5a6183c|0|
|`08-owner-select-grants-run32`|72e868d1163f4c6480dc5e28f381dfb4|76d651a2fa5385b7c3affe1845466e325b3929315ed7d7b4a75f3c792fea7f4e|0|
|`08-owner-select-restrictions-repeat-run33`|73f4493ea5de4a669bad6934beb15118|36c9942fbedcaa5e00facb0c017566c26b38f168d6971e43f4a8eb430fb010b8|0|

HTTP maxima parsed from raw `08 HTTP end: ... elapsed=...`, converting s/ms/µs/ns, selecting max per log. No invented exclusive timings. Previous ignored raw09–11/native-stage-run03 and failed restrictions26 hashes rechecked unchanged; prior receipts/failed outcomes retained.

## Validation boundary / next gate

All requested tests ran and passed; Git whitespace checks passed. No source edit, formatting change, new instrumentation, Clippy/client/boundary/powerset/CRAP/full sweep or duplicate owner matrix this session. Pre-existing Git GC warnings retained without pruning.

Bounded current-source all-three plus one restrictions repeat and final ordinary teardown are now GREEN for parent review. Independent final consumer source review, inherited-evidence integration and applicable focused final gates still separate; no main merge, tracker Answer, spec closure, push or worktree retirement. Exclusive build slot released; no build/test service left running.
