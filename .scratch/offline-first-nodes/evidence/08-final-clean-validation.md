# Final clean consumer/owner validation — runtime GREEN, strict Clippy inherited blockers

2026-10-12. All three clean-source pair filters plus one restrictions repeat, two probes and the affected rotation regression passed. Formatting and boundary check passed. **Strict Clippy failed on inherited baseline code; not an all-gates GREEN or ticket08 closure.** No source edit, suppression, main merge, Answer/spec/acceptance-box change or push. Parent final review remains required.

## Exact stable clean source / ownership

- Consumer **`d9e40eb4e903f8e073e3a8c35fd879b6e1ad3806`**, branch `offline-first-ticket08-full-nodes`, existing worktree. Clean before/after all validation; source cleanup `ba7cfc2` removes temporary instrumentation. Evidence-only commit follows execution.
- Owner **`5b08d0ddc6e2c19a8be29af13fe5af6133b791a6`**, branch `integration/native-catalog-reuse`, clean before/after; tested clean-source implementation **`72aae34b75f0fd65f4feadfb49e13ae948b41f6c`**. User reports independent owner qualification. No native timers/log-only dependencies; no diagnostic logger reintroduced or owner edit/build by owner during this slot.
- `realpath ../ofdb/crates/sql`, `sql-engine`, `sql-engine-automerge` individually verify original `/home/nathan/code/rust/aicacia/ofdb/crates/...`; compile output uses existing `of/.worktrees/ofdb` sibling links. Consumer manifest/lockfile equal main before/after (including boundary metadata command). No dependency regeneration/compatibility wrapper.
- Main ancestry unchanged: current main already integrated; diagnostic qualification history/receipts remain reachable. Historical ignored raw09–11/native-stage-run03/failed restrictions26 hashes rechecked unchanged. New raws remain ignored, not wholesale committed or overwritten.

## Resource envelope / scope

Exclusive build slot, Rust services serial with **MemoryMax4G / MemorySwapMax0 / RuntimeMaxSec900**, terminal910000ms, offline/locked/jobs1/shared `/home/nathan/code/rust/aicacia/of/target`, unset RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS and RUST_MIN_STACK67108864. Original optimized+debuginfo test profile; Linux supported default/no-extra-feature unified-server library/tests. No feature/platform matrix, no CLI/logger env, no profile/cache/provider reset, prewarming, shared stores, weakened checks or deadline increase. HTTP10s/pair360s/probe120s unchanged. Preflight available16485MiB, host swap2042MiB used out of2047MiB; zero-swap **service** cap does not mean host swap zero. No other cargo/rustc observed at preflight/end.

Boundary43 separately bounded60s (terminal65000ms), same4G/zero service swap, `CARGO_NET_OFFLINE=true`; actual requested `just boundary-check`. Formatting44 subprocess commands bounded60s each. No client builds: apps/packages/public contracts unchanged. CRP low-complexity existing-seam validation, high-risk security behavior left intact. No owner matrices duplicated.

## Literal tests and actual results

Every test launch: `-p unified-server --lib`, exact/nocapture/test-threads1, **1passed/0failed/77filtered**, exit0. No runtime test failures, OOM, service timeout or warm retry in this session. First compile+runtime fit900s with only9.805s service headroom; a retry was not needed or hidden.

| Run | Literal filter | Compile | Test seconds | Service seconds | Scenario arithmetic headroom |
| --- | --- | --- | ---: | ---: | ---: |
|34|`local_provisioning_tests::full_nodes::two_completed_full_hosts_learn_restrictions_on_retained_sockets`|10m24s|265.42|890.195|94.58s vs360|
|35|`local_provisioning_tests::full_nodes::two_completed_full_hosts_join_partition_reopen_and_learn_denial`|0.48s|226.26|226.862|133.74s vs360|
|36|`local_provisioning_tests::full_nodes::two_completed_full_hosts_reconcile_consumption_and_revocation`|0.38s|248.02|248.521|111.98s vs360|
|37|`local_provisioning_tests::full_nodes::two_completed_full_hosts_learn_restrictions_on_retained_sockets` (one repeat)|0.38s|264.18|264.673|95.82s vs360|
|38|`local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put`|0.41s|29.90|30.426|90.10s vs120|
|39|`local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put_with_extra_service_clients`|0.38s|33.29|33.777|86.71s vs120|
|40|`local_provisioning_tests::local_provisioning_authorized_rotation_reopens_completed_host`|0.40s|60.98|61.486|Service900s cap; not a pair/probe scenario|

Reported test duration includes harness/teardown, is rounded and is not exact isolated deadline slack. Reported memory peaks256–512K are implausible, not actual RSS/headroom guarantees; services report swap0B accounting only.

### Completed behavior / teardown

- **Restrictions34:** Management reconciliation217.292444s; both retained-socket learned denial/recovery/readback/resource deletion/404 checks completed; ordinary pair stop265.410565s.
- **Offline35:** both full hosts119.949025s; local concurrent grant winner/loser/replay A/B complete122.770319s/127.260769s; both stopped128.276481s and reopened **without DATA sessions**147.405842s. Retained endpoint/private credential/trust/public completion/post-reopen grant denial/JWKS assertions completed. A independent identity/policy/resource/User+Client issuance journey complete178.729915s; **B complete225.958283s**; **final ordinary pair teardown226.243363s**. Both genuinely completed disconnected journeys and resource write/read/delete/404 checks, not inferred from readiness.
- **Grants36:** reconnect127.197242s, endpoint127.199219s, IdP reconciled245.434130s, then two genuine B invalid_grant HTTP400 responses for learned consumption/revocation. Ordinary stop248.008675s.
- **Restrictions repeat37:** Management reconciliation216.005866s, same representative retained-operation/cleanup assertions, ordinary stop264.169057s. Exactly one repeat, not retry-until-green or matrices; old26 failure remains preserved.
- **Probe38:** replay genuine HTTP400/client0.679155s, restriction204/client2.721059s, managed shutdown29.895610s. **Probe39:** four-extra-service-Client control, replay400/client0.717150s, restriction204/client2.554785s, managed shutdown33.282343s. **Rotation40:** existing authorized rotation/reopen test GREEN60.98s against parameterized fixture helper.

Maximum completed server middleware HTTP intervals in pair34/35/36/37: **6.273518876 /7.235603862 /1.614547118 /5.999218730s**. Arithmetic10s headroom3.726481124/2.764396138/8.385452882/4.000781270s. These are server intervals (including nested APIs), **not client elapsed/deadline slack** or universal scheduling guarantees. B filesystem POST2016.273519s/7.235604s/5.999219s in34/35/37. No request timed out in these final pair runs.

## Focused gate results and inherited lint attribution

| Run | Command/gate | Result | Service/runtime |
| --- | --- | --- | --- |
|41|`cargo clippy --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib --tests -- -D warnings`|**FAIL exit101**, inherited `collapsible_if` in library; stops before test linting.|22.941s|
|42|Same command plus `--force-warn clippy::collapsible_if` (diagnostic only)|**FAIL exit101**, original lint remains visible as warning; eight inherited test errors exposed. Not a strict pass or source suppression.|26.663s|
|43|`CARGO_NET_OFFLINE=true just boundary-check`|**PASS exit0**, "No direct server-to-server dependency edges found."|0.107s,60s cap|
|44|Changed-final-source `rustfmt --check --edition 2024` and `git --no-pager diff --check`|**PASS exit0** for both commands.|Each subprocess60s cap|

Strict41 baseline lint: `crates/unified-server/src/runtime.rs:708`, `clippy::collapsible_if`. Diagnostic42 keeps that warning visible and exposes:

- `endpoint.rs:646`: `unnecessary_to_owned` (`to_vec`).
- `local_provisioning_tests.rs:77`: `field_reassign_with_default` in existing Fixture constructor.
- `runtime.rs:1181,1186,1190`: three `field_reassign_with_default` errors in existing tests.
- `node_bootstrap_interruption_tests.rs:744,773,875`: three `drop_non_drop` errors.

Baseline attribution verified structurally: endpoint/interruption files byte-identical to main; runtime byte-identical to main plus final test-fixture declaration; local provisioning fixture prefix through the changed rotation helper byte-identical to main. No lint points to new full-node pair/probe/fixture code in these runs. Do not infer a full lint-clean result from absence of new errors: strict Clippy **remains blocked**. No existing lint cleanup, source allow/suppression, behavioral fix or additional relaxed rerun. Parent must decide how to handle inherited baseline gates; this receipt does not waive them.

Boundary recipe runs `python3 scripts/check_server_dependencies.py` -> cargo metadata/no-deps; env enforces offline operation. Lockfile still matches main afterward. Clients/apps/packages/scripts/config/public API unchanged; no client build. No extra CLI/platform checks, workspace/all-targets/feature-powerset/CRAP sweeps.

## Exact command provenance / raw hashes

Common actual test34 argv:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-final-clean-restrictions-34 --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::full_nodes::two_completed_full_hosts_learn_restrictions_on_retained_sockets -- --exact --nocapture --test-threads=1
```

35–40 same envelope and table filters, units `of-ticket08-final-clean-offline-35`, `...-grants-36`, `...-restrictions-repeat-37`, `...-probe-38`, `...-client-inventory-39`, `...-rotation-40`.41/42 same Rust envelope, units `...-clippy-41`/`...-clippy-diagnostic-42`, exact gate commands above.43 unit `of-ticket08-final-clean-boundary-43`, RuntimeMaxSec60, env unset Rust flags plus `CARGO_NET_OFFLINE=true just boundary-check`.44 records two complete standalone argv arrays: rustfmt on `full_node_tests.rs`, `full_node_probe.rs`, `full_node_runtime_fixture.rs`, `local_provisioning_tests.rs`, `runtime.rs`, then git whitespace check.

Each adjacent ignored `.json`/`.status` file retains exact complete argv and wrapper exit. Subprocess captures merged stdout/stderr and mirrors live; no pipeline status masking.44 logs command-specific exits plus aggregate0. Only compact receipt committed; no wholesale fixture/secret/artifact commit.

| Raw basename in this evidence directory | Invocation ID | SHA256 of `.log` | Exit |
| --- | --- | --- | ---: |
|`08-final-clean-restrictions-run34`|7c6cd3e9c0084c07afab34b7d0bf895d|710f3d881a0797dea29c4c3af2d6c1371ea1a080571076af06c5a6f5bd3f8f31|0|
|`08-final-clean-offline-run35`|54760e057acd42c48344895b51d1cc26|9a1844429f0ab7cf23b6c969b847b39529027d5f7ec58caf3481136725d0c66b|0|
|`08-final-clean-grants-run36`|2a584748b56044b89d108b2828d00642|21c7cb0fa9954415048c0a0857cd790adfd88fc0766eff38ff6baa815aa8ab35|0|
|`08-final-clean-restrictions-repeat-run37`|7a5720d91db8438db27dac8a07f4569d|937b901aaa9217c8bea8e6b0162dd7cfdd3c8d3f1b3bded487775b8364515f60|0|
|`08-final-clean-probe-run38`|d64dc6946f834ed1beb315d881a68b31|4081bc48e32cf1f1c46100353b29c06d4cb07e2ed10ecf68817cfc3abee86832|0|
|`08-final-clean-client-inventory-run39`|ee920517a5bc4c919ef7df8bf8c4a5fb|6e2d87240c1bc2547ce557afb441699cab9553bace03b9a04ac91c447f1817ca|0|
|`08-final-clean-rotation-run40`|296e7c92e8574ee9bf1c477fa2f7f60b|4a6ea04dc969a9676c9dab695b99843c32c22c866aa629761e8412cd51ed77c8|0|
|`08-final-clean-clippy-run41`|99da8fbfb3794613a34083f8ea4702cc|b043624d4549439e6b9310469c2033da882de93ed6f5cbafbe07f6c5e6e1c32c|101|
|`08-final-clean-clippy-diagnostic-run42`|af3e7ef711dd420395d668c52c6400f3|7c7e458c85d0d41c23fbefa71579a5e2a53806146138604efc937af7d53893a0|101|
|`08-final-clean-boundary-run43`|4da7fdd9facc42a28724b67c66187272|30a5c85ea5cb5d828355930f66065163238eed112f4049cbcef890973ddba7fe|0|
|`08-final-clean-format-run44`|Standalone bounded subprocesses|085d15bb2103b9676f890c1da889766d9f26eb2862c3ea12ef9f14648664377f|0|

No historical failures erased, ignored logs overwritten/deleted, provider state reset, or caches pruned. Pre-existing Git GC/unreachable-object warnings retained. No source changes needed/justified by final runtime tests or inherited lint diagnostics.

## Parent review boundary

Clean-source machine-local all-three + one repeat and representative controls/rotation are GREEN, all ordinary pair teardowns complete; boundary/format GREEN. Strict Clippy baseline failures remain explicit. This is not full-platform/provider/deployment or global grant-single-use qualification. Parent source review, inherited-evidence integration and decision on existing lint gate blockers remain outstanding. No ticket/main/spec closure/push/worktree retirement. Exclusive build slot released; no build/test service left running.
