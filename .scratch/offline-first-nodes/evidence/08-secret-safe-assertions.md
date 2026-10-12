# Security review LOW — secret-safe harness assertion failures

2026-10-12. Targeted comparison-diagnostic fix only. No production/socket behavior, permissions, transport, test scenarios, matrix, deadlines or instrumentation added. All four requested affected filters passed. No main/ticket/spec closure, push or lint cleanup; parent review remains required.

## Source / exact targeted changes

Source commit **`6341cf1ec353dd4d73f93dd8879678f439af1978`**, parent `4492dcc`, branch `offline-first-ticket08-full-nodes`. Only `crates/unified-server/src/full_node_tests.rs` and `full_node_probe.rs` changed. Owner clean unchanged **`5b08d0ddc6e2c19a8be29af13fe5af6133b791a6`**, `integration/native-catalog-reuse`, implementation72aae34. Consumer clean and unchanged during all validation; evidence commit follows.

Replaced six directly sensitive `assert_eq!`/`assert_ne!` comparisons with boolean `assert!` and fixed non-secret messages:

- Offline reopen's two private credential inventory equality checks.
- Concurrent-refresh winner's replacement-token inequality check.
- Shared versus consumption-target grant inequality and consumption versus revocation-target inequality.
- Probe refresh replacement versus consumed-grant inequality.

All equality/distinctness conditions and expected invariants preserved. Failure messages do not format/evaluate secret operands for output; no check dropped or widened.

Also removed three related response comparison-output channels:

- `json`: expected-status assertion no longer prints URL/body (helper processes bearer/refresh token responses); boolean status equality and fixed message retained. Body still read/parsed normally for the successful response.
- `denied_grant`: literal invalid_grant comparison no longer Debug-prints the dynamic JSON error value; fixed message, exact value check retained.
- `restriction`: no-content status check no longer prints a response body on assertion failure; same status condition, fixed message. Only failure diagnostic/body read removed, no successful operation semantics changed.

Comparison-focused audit of new pair/probe/fixture code and changed login helper: no remaining explicit `assert_eq!`/`assert_ne!` operands are private inventories, bearer/refresh tokens or private signing key material. Public IDs/endpoints, typed `JwkPublic` (RSA n/e, EC crv/x/y, OPK crv/x only), public join approvals and known fixture-content/status comparisons remain. No private JWK/TokenResponse Debug comparison added. This is not a blanket guarantee for every third-party error's Debug formatting; unrelated error paths and production code were not rewritten.

CRP: low-complexity diagnostic-only edit; high-priority confidentiality risk on failure. Pre-agreed production seams and all successful-path conditions retained. Rustfmt/whitespace checks passed. Structural comparison against parent confirms `learned_restrictions` and `create_written_resource` **byte-identical**, including the sensitivity control and retained-socket logic. No production file or manifest/lock/client delta.

## Contextual restriction QA — deliberately narrow claim

Existing `create_written_resource` is the **pre-learning same-connection success sensitivity control**: it opens the real authorized Storage socket, successfully writes the known `committed offline` content, then reads that exact content on **the same connection** before retaining it. Both hosts do this before Management reconciliation. An always-denying/broken admitted socket cannot satisfy that baseline.

After learning, the retained connection's next write must fail closed (error response, close/transport error or end accepted by existing loop). Restoring permission and reading through a fresh authorized connection proves the attempted denied write did **not overwrite the previously committed content**. The composed pair therefore qualifies **learned fail-closed/no-overwrite with an actual pre-learning retained-connection success control**, not an exact typed policy-rejection reason versus every possible transport failure. No socket production change, assertion strengthening/weakening, new failure matrix or claimed exact-cause proof introduced.

Exact current-state policy, namespace, queued/in-flight and owner-apply guarantees are inherited separately from [of03 execution completion evidence](03-completion/README.md), especially its exact authenticated identity/both selections/restrictions checks, local-failure negatives, pinned-namespace socket checks and admitted-completion/next-denial gates. Its concrete owner-clock/expiry qualification limitations remain unchanged; do not silently expand those claims. Previous clean restrictions34/37 in [final validation](08-final-clean-validation.md) remain recorded at their actual source. No gratuitous restrictions repeat here: test body/control byte-identical and shared status comparisons keep identical success criteria.

## Execution envelope and actual results

Exclusive serial Rust build slot; no concurrent cargo/rustc observed. Existing task worktree/production independent native stores; `realpath ../ofdb/crates/sql` verified original owner root via existing sibling links. Each service **4G / MemorySwapMax0 / RuntimeMaxSec900**, terminal910000ms, jobs1/offline/locked/shared `/home/nathan/code/rust/aicacia/of/target`, original optimized+debuginfo profile, unset RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS, RUST_MIN_STACK67108864. No extra features, logger env, provider/cache/profile reset, prewarming or shared stores. HTTP10s/pair360s/probe120s retained.

Each test **1passed/0failed/77filtered**, exit0. No runtime failure, OOM, service timeout or warm retry. Memory accounting256–512K is implausible, not a headroom guarantee; service swap0B is not host-wide zero swap.

| Run | Exact literal filter | Compile | Test seconds | Service seconds |
| --- | --- | --- | ---: | ---: |
|45|`local_provisioning_tests::full_nodes::two_completed_full_hosts_join_partition_reopen_and_learn_denial`|3m06s|217.71|403.877|
|46|`local_provisioning_tests::full_nodes::two_completed_full_hosts_reconcile_consumption_and_revocation`|0.36s|252.42|252.870|
|47|`local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put`|0.32s|28.80|29.219|
|48|`local_provisioning_tests::full_nodes::probe::single_full_host_refresh_replay_and_restriction_put_with_extra_service_clients`|0.31s|31.71|32.107|

Offline45 both full hosts114.338902s; A/B concurrent grant race/replay complete116.988845s/121.281610s; both stopped121.335632s and reopened disconnected140.583309s. Private inventory equality invariants passed without operand-dumping macros. A/B complete identity/policy/resource/User+Client issuance journeys170.490046s/**217.455961s**, final ordinary teardown217.698839s. Grants46 reconciled IdP248.631240s, returned genuine learned B consumption/revocation invalid_grant denials, ordinary teardown252.408886s. Probes retained rotation inequality/replay400/restriction204 checks and managed shutdown; PUT client2.377561s/2.470951s. All comparisons remain real checks, not logging-only replacements.

## Exact command / compact raw integrity

Common actual offline45 argv:

```sh
systemd-run --user --wait --pipe --collect --unit=of-ticket08-secret-safe-offline-45 --property=MemoryMax=4G --property=MemorySwapMax=0 --property=RuntimeMaxSec=900 --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RUST_MIN_STACK=67108864 CARGO_BUILD_JOBS=1 cargo test --offline --locked --jobs=1 --target-dir /home/nathan/code/rust/aicacia/of/target -p unified-server --lib local_provisioning_tests::full_nodes::two_completed_full_hosts_join_partition_reopen_and_learn_denial -- --exact --nocapture --test-threads=1
```

46/47/48 same envelope with table filters and units `of-ticket08-secret-safe-grants-46`, `of-ticket08-secret-safe-probe-47`, `of-ticket08-secret-safe-client-inventory-48`. Adjacent ignored `.json` files retain exact complete argv; `.status` each0. Merged stdout/stderr captured/mirrored live, no pipeline masking. No forced secret-bearing assertion failure/log created. Only compact receipt committed; raws/old ignored artifacts preserved, not bulk-added or sanitized in place.

| Raw basename in this evidence directory | Invocation ID | SHA256 of `.log` | Status |
| --- | --- | --- | ---: |
|`08-secret-safe-offline-run45`|1cbcc786e5aa475494c2df88e9a887b6|8ed905ff597636cc5675c84481f7c29b273a865a6536c3c8936f5c30276da9b9|0|
|`08-secret-safe-grants-run46`|a4217bc2c155409788ae5cb2ff144417|e79f46eddf22ff7bbb425953743a6d87b1621aaeb0cb2d334e7c88469da79a07|0|
|`08-secret-safe-probe-run47`|95820c0c607e4f3fa48c64ededbddd3c|a7996023257c1d2f2ed61ef2d701a44059e130e3337264e12ab326845123ce2c|0|
|`08-secret-safe-client-inventory-run48`|77de3e85708240efab367ab4455e968b|631eeb446f2ec17ea6554ea8cc85b9e770ebf6b6095a4dfba7b022cc8c69f176|0|

## Remaining review / gate policy

Affected source formatting and Git whitespace checks passed. No restrictions, rotation, owner suite, boundary/client/full-workspace/Clippy rerun requested or needed for comparison-only diagnostics; existing final receipts remain intact. No matrix invented.

[Final clean validation](08-final-clean-validation.md) retains strict Clippy failure at unchanged runtime collapsible_if plus eight inherited test errors exposed diagnostically (unnecessary_to_owned1, field_reassign_with_default4, drop_non_drop3). They remain a parent policy decision, **not fixed/waived/passed** here. No suppression or unrelated lint cleanup.

Parent security/source review of6341cf1, prior clean restrictions evidence plus the narrower QA interpretation, inherited03 exact-policy evidence and lint gate decision remain pending. No production behavior changes, main/ticket/spec closure/push or worktree retirement. Exclusive build slot released; no build/test service left running.
