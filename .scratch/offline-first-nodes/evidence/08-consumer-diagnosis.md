# Ticket08 consumer diagnosis — failures retained, owner hot paths measured

2026-10-12. Diagnostic delivery only. **No proven behavioral fix; ticket08 remains blocked/unqualified.** No main merge, ticket Answer, spec/acceptance change, owner edit or provider reset.

## Provenance and constraints

- Existing worktree `of/.worktrees/ticket08-full-nodes`, branch `offline-first-ticket08-full-nodes`, initially clean at `f0be1aa8fc89ab0bcde8ce284892159e010a1beb` (main already merged).
- Owner root clean at `a6f23119257b591023b17da550bfc2ba7460231b`, branch `diagnostics/native-idp-stage-timing`, before/after execution. Includes reviewed scan-local correction `cce094c` and instrumentation. Dependency `realpath ../ofdb/crates/sql` resolves original `/home/nathan/code/rust/aicacia/ofdb/crates/sql`; no owner worktree/source modification.
- Runs12/13 used `f0be1aa` plus working-tree diagnostic edits: endpoint-connected marker and inline opt-in logger immediately before B's existing restriction PUT. No behavior/assertion/filter/deadline changes. Commit `0dce5e0c1cd36cdb4e4e7f7ba81ce28f8e9073dd` then extracted the identical logger into the existing probe module and added security-sync phase/authorization timing. Run14 used that clean committed source.
- CRP: diagnostics low complexity; security/reconciliation behavior high risk; priority isolate the measured failure before proposing changes. Approved seams are existing composed public owner HTTP and authenticated DATA/security synchronization. Existing failing pair tests provide the red reproduction; there is no green behavioral-fix claim.
- Exclusive builds, three serial launches, no other cargo/rustc observed at preflight/end. Preflight available memory17039MiB, host swap390MiB used; no claim of zero host swap. Each service capped **MemoryMax4G / MemorySwapMax0 / RuntimeMaxSec900**, terminal910000ms, jobs1/offline/locked/shared `of/target`, unchanged optimized+debuginfo test profile, no RUSTFLAGS. Existing HTTP10s/pair360s/probe120s unchanged. No 120s single-host probe was run in this session.
- Run12 preserves historical no-extra-feature grants command. Runs13/14 add `--features cli` and `OF_IDP_STAGE_TIMING=1` solely to install the existing stage logger; they are diagnostic pair executions, not unchanged-feature acceptance reruns. No full sweeps, provider reset, cache/profile changes, prewarming, shared repositories, admission/permission weakening or retries.
- Full raw logs remain ignored locally. New committed argv/status/summary files reproduce commands and retain exact exit status; no pipeline masking. Existing receipt08-reviewed-owner-rerun and raw09–11 remain untouched.

## Executed outcomes

All three compiled and ran one exact test, then failed (exit101); no OOM or service900s timeout.

| Run | Filter suffix under `local_provisioning_tests::full_nodes::` | Compile | Test | Result |
| --- | --- | --- | --- | --- |
|12|`two_completed_full_hosts_reconcile_consumption_and_revocation`|2m53s|361.60s,0pass/1fail/77filtered|Endpoint connected; security sync hit scenario bound.|
|13|`two_completed_full_hosts_learn_restrictions_on_retained_sockets`|2m53s|248.21s,0pass/1fail/78filtered|Cold B restriction PUT transport timeout; Management reconnect unreached.|
|14|`two_completed_full_hosts_reconcile_consumption_and_revocation`|4m09s|360.27s,0pass/1fail/78filtered|Both generic owner sessions entered, no session end/reconciled marker before bound.|

Exact argv: [run12](08-consumer-reconnect-run12.json), [run13](08-consumer-management-run13.json), [run14](08-consumer-security-run14.json). Adjacent `.status` files each contain101. Run12 service runtime8m55.015s; run13 7m1.487s; run14 10m9.517s. Reported memory peaks256–312K are implausible, not real RSS/headroom evidence. Service swap accounting0B is not host-wide swap evidence.

## Endpoint versus security synchronization

Run12 reached both full hosts197.445484s; source/joined shared refresh redemption and replay denial, plus source consumption/revocation and denial, all returned genuine HTTP results. Reconnect started214.036585s; endpoint-connected marker214.038331s: **1.746ms** between markers. Security synchronization did not return before360s. Thus this reproduction stalls after `endpoint.connect`, not inside it.

Run14 reached both full hosts188.983914s, again completed the same refresh/revocation work. Reconnect205.895639s; endpoint connected205.896817s (**1.178ms**). Logs then reached:

1. Initiator schema validation and local handshake.
2. Initial authorization, handshake send and received accepted handshake.
3. `security_sync.owner_session_start role=Responder context=Idp`.
4. `security_sync.owner_session_start role=Initiator context=Idp`.
5. Repeated completed live authorizations until the scenario bound.

29 completed `security_sync.authorize` records: aggregate77.293693s, max9.387604s. Both roles share the same label; these are overlapping/interleaved wall intervals, not exclusive latency or role attribution. Native admission7404 records sum162.393639s/max29.960290s; native body rollback6302 records sum140.058900s; body commit1102 records sum83.447663s/max9.807403s. This proves ongoing authorization/native work and entry into both owner sessions, **not a proven deadlock or exact remaining session subphase**. Neither owner-session-end nor learned B grant denials/shutdown completed.

Consumer code: `security_sync.rs::authorize` still checks local signer trust, remote trusted endpoint/member, approved Device, current conflict-clear User, context-specific current local permissions and cancellation. `AuthorizedSecurityTransport::send` and the owner pre-apply callback still reauthorize. No check was removed/reused across operations to manufacture progress.

## Joined-B cold Management profile

Run13 kept A's preceding restriction/resource/socket path intact. A PUT204 server7.290532s. Both full hosts ready191.832186s. Logger installed only after the existing B actor exchange, immediately before its first Management request at236.238771s. B's Management service token was not prewarmed.

Nested B HTTP successful stages: client credentials2.649012s, introspection3.343580s, Device lookup5.000798s (sum10.993390s excludes other PUT work). Caller timed out at unchanged10s; Device lookup completed during cancellation/failure aftermath. No B PUT204 appears, so neither no-effect nor completed mutation is established.

| Existing IdP bucket | Wall seconds |
| --- | ---: |
|Service Client lookup|0.708493|
|Secret verification|0.180828|
|Principal root/key-Client load|0.111398 /0.464806|
|Live Client validation|0.664006|
|Signer trust/private-key load|0.518753|
|JWT signing|0.000273|
|Introspection caller/actor authorization|1.734910 /1.168853|
|Introspection allowlist/application Client loads|0.229298 /0.210146|
|Device caller authorization|3.930221|
|Approved Device /signer trust /owner User loads|0.330595 /0.550350 /0.189436|

Native interval:350 completed admission records sum9.084997s/max3.161481s;106 body commits sum5.828450s;244 body rollbacks sum9.226770s. Includes two hosts/background/shutdown, not exclusively B/PUT. Existing catalog labels show mixed catalog inventories13 tables/81 fields and34 tables/331 fields; counts alone do not identify a host. Catalog reconstruction2233 records sum9.396726s; conflict-document reconstruction232 records sum0.035867s; conflict-document **columns**224 records sum4.036619s; engine conflict schema232 records sum4.622949s; conflict codec232 records sum4.087092s. Nested totals must not be added as exclusive CPU time.

## Separate generic-owner correction handoff (no owner edits)

The accepted scan-local correction remains installed. There is direct source and timing evidence of expensive generic work **outside that corrected scan-local layout seam**:

- `ofdb/crates/sql-engine/src/executor.rs:1247–1271`, `row_conflicts`: resolves table, obtains full `table_schema`, then calls codec `conflicted_columns`. Schema and codec measurements are separately logged for each call.
- `ofdb/crates/sql-engine-automerge/src/codec.rs:776–804`, `conflicted_columns`: reconstructs a document, then calls `document_columns`; the latter at510–524 calls `Self::columns(transaction, table, 0)`.
- `codec.rs:154` onward, `columns`: for non-catalog tables reconstructs/scans the table and table-field catalogs. Scan-local reuse in `scan_rows`/`scan_row_states` does not reuse this independent conflict-introspection path's layout work. Run13 directly measures4.036619s in conflict document columns versus0.035867s in document reconstruction; schema rebuilding is a separate4.622949s nested stage.
- `ofdb/crates/btree-redb/src/database.rs:27–45`: transactions hold asynchronous writer admission then begin a redb write transaction; long body intervals serialize subsequent transactions. Run13 has admission waits3.161481s,2.581121s,1.914089s; run14 max29.960290s. Logger lacks database/request correlation, so these are real generic waits but do not identify their holder.
- `ofdb/crates/sql-sync/src/session.rs:640–685`: scoped manifest construction uses per-table read transactions/export work; long generic session/body work is a relevant next owner measurement, not proven to be the sole stall.

**Ask the owner to isolate conflict/schema reconstruction and session transaction-holder work at these exact production seams, with generic red/green checks preserving snapshot/schema/conflict/candidate validity and mutable-kernel/fallback contracts.** Do not absorb a generic codec/native/session rewrite into the consumer branch. Current measurements do not justify choosing a specific generic fix or asserting it alone will make the pairs pass. Repeated consumer authorization is also measured; it is required current-state work, not permission checks to drop or cache.

Important instrumentation caveat: `ofdb.row_conflicts.* count=0` is the StageTiming default (`sql-engine/src/stage_timing.rs:18`); those call sites do not set count. It is **not** evidence of zero conflicts or zero queried rows. Missing/incomplete timing records are not zero cost.

## Raw integrity and reproducible summary

| Raw log | Invocation ID | SHA256 |
| --- | --- | --- |
|`08-consumer-reconnect-run12.log`|ff3ed1c441aa4b3c8706eab8b16729b8|e58948386d7aadf45b377f37e86ed566737aaadb7c672c819ff25096111fd009|
|`08-consumer-management-run13.log`|a86b23aa2b70442493df79e9bcfa6ab5|c959cd2d710e5035aba25fbec7a44e18093bd6dce9d139344fbd8503f5831b87|
|`08-consumer-security-run14.log`|9896908f98e04562969f6a143fc5247c|b4d062a51289a425e0c40a2418191806e7b40cf809768f2a196742354677cb75|

[Stage summary](08-consumer-diagnosis-stage-summary.json) groups all raw13/14 lines matching `\] (\S+) elapsed_us=(\d+)` by fixed label and records number/sum/max in integer microseconds. Includes nested/interleaved/cancellation work. No invented exclusivity or CPU attribution.

Rechecked preserved raw09/10/11 SHA256 against reviewed receipt: all three match exactly. Old ignored receipt/logs not force-added or overwritten. New raw logs retained ignored, not bulk-added to Git.

## Validation and remaining blockers

Changed-file `rustfmt --check --edition 2024` passed for `full_node_tests.rs`, `full_node_probe.rs`, `security_sync.rs`; `git diff --check` passed. Run14 compiled the committed diagnostics and exercised them; pair acceptance remains RED. No Clippy/client/boundary/powerset/CRAP sweeps or independent source review claimed. Git commit reported pre-existing GC/unreachable-object warnings; no prune/cache cleanup performed.

No proven consumer behavioral root-cause fix is available from these measurements; no qualifying post-fix unchanged-feature acceptance rerun was possible. Offline run09 remains the latest offline slice (328.94s failure) and was not rerun gratuitously. Next work is separately owned generic investigation/correction plus review, then relevant unchanged pair filters after a proven fix. Both offline journeys, learned grant denials, retained-socket learned restrictions and ordinary completed-pair shutdown remain unqualified. Diagnostics are compiled evidence, not a security/performance fix or08 closure. Exclusive build slot released; no service/build left running.
