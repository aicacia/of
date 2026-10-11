# Ticket 06 live client generation acceptance — 2026-10-11

Worktree: `of/.worktrees/ticket06-clients`; branch: `offline-first-ticket06-clients`; starting base: `2e67ed5`. This qualifies the owned client-generation slice, not resolution of ticket 06 or its deferred ticket 04 dependency. Apps/shared frontend and domain-document changes remain with their owners.

Complexity: bounded extension of the existing unified listener fixture plus two focused scripts. Risk: publishing stale/incomplete contracts or changing auth/transport semantics. Priority: qualify actual generation and destructive-failure safety. No new dependency, fake router, saved-document input, alternate authorization, production auth/TLS change, install, native GUI, Cargo hack, CRAP, profile or cross-repository edit.

## Delivered and verified live input

The existing `runtime::tests::builds_three_prefixed_services_with_one_endpoint` fixture owns isolated native context stores, the real UnifiedRuntime, and one actual loopback HTTP listener. A test-only `OF06_CLIENT_QUALIFICATION` hook runs a Node script on a blocking worker while the real public routers remain live; failed script status is asserted after the existing listener/runtime/store cleanup. Production composition is unchanged.

On the successful execution, HTTP 200 documents were fetched and checked at:

| Service | Actual endpoint | Registered operations | Document server |
| --- | --- | ---: | --- |
| IdP | `http://127.0.0.1:46035/idp/openapi.json` | 50 | `https://idp.example/idp` |
| Management | `http://127.0.0.1:46035/management/openapi.json` | 24 | `https://management.example/management` |
| Storage | `http://127.0.0.1:46035/storage/openapi.json` | 14 | `https://storage.example/storage` |

The fixture serves current router-generated documents, not exported JSON. `scripts/qualify-openapi-clients.mjs` checks exact operation counts, server prefixes, unprefixed operation paths, absent internal routes, current transfer operation and absent bootstrap route/models, then invokes the EXISTING `scripts/generate-openapi-client.mjs` with service-specific `OPENAPI_SPEC_URL`. Its existing inventories require all 88 operations across 9 API groups and format staged output before publication. No generated TypeScript was hand-edited.

Actual generation succeeded for all three services. IdP now exports `transferDevice` and `DeviceTransferRequest`; `SuperRoutesSetupApi`, its barrel export, and `SetupBootstrapRequest` are deleted by replacement. Management permission/restriction/selection and Storage resource/Residency APIs are regenerated. Only Storage `src/generated` is replaced; its handwritten client is untouched. The generator uses the document server as the overridable base URL, so checked-in example fixture defaults are not production deployment addresses.

## Exact bounded Rust and live execution

All commands below ran in this worktree. No other Rust build was started by this agent. Compilation used the shared `/home/nathan/code/rust/aicacia/of/target` and `CARGO_BUILD_JOBS=1` only.

```sh
systemd-run --user --unit=of06-clients-compile --wait --pipe --collect --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket06-clients --property=MemoryMax=6G --property=TasksMax=512 --property=CPUQuota=200% --property=RuntimeMaxSec=240 --property=TimeoutStopSec=5 /usr/bin/env CARGO_TARGET_DIR=/home/nathan/code/rust/aicacia/of/target CARGO_BUILD_JOBS=1 /home/nathan/.cargo/bin/cargo test --offline -p unified-server --lib --no-default-features runtime::tests::builds_three_prefixed_services_with_one_endpoint --no-run
# Timed out after 4min; build progressed through storage-server (494/498).
# Not a test failure or qualification success; peak memory 2.4G.

systemd-run --user --unit=of06-clients-compile-retry --wait --pipe --collect --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket06-clients --property=MemoryMax=6G --property=TasksMax=512 --property=CPUQuota=200% --property=RuntimeMaxSec=600 --property=TimeoutStopSec=5 /usr/bin/env CARGO_TARGET_DIR=/home/nathan/code/rust/aicacia/of/target CARGO_BUILD_JOBS=1 /home/nathan/.cargo/bin/cargo test --offline -p unified-server --lib --no-default-features runtime::tests::builds_three_prefixed_services_with_one_endpoint --no-run
# Successful cached retry: 9m47s; no diagnostics.

systemd-run --user --unit=of06-clients-live --wait --pipe --collect --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/ticket06-clients --property=MemoryMax=6G --property=TasksMax=512 --property=CPUQuota=200% --property=RuntimeMaxSec=600 --property=TimeoutStopSec=5 /usr/bin/env PATH=/home/nathan/code/rust/aicacia/of/packages/idp-client/node_modules/.bin:/home/nathan/code/rust/aicacia/of/node_modules/.bin:/run/user/1000/fnm_multishells/1034680_1791734967229/bin:/usr/local/bin:/usr/bin:/bin npm_execpath=/run/user/1000/fnm_multishells/1034680_1791734967229/bin/pnpm OF06_CLIENT_QUALIFICATION=/home/nathan/code/rust/aicacia/of/.worktrees/ticket06-clients/scripts/qualify-openapi-clients.mjs /home/nathan/code/rust/aicacia/of/target/debug/deps/unified_server-d2ff4d244f2c2d5c runtime::tests::builds_three_prefixed_services_with_one_endpoint --exact --nocapture
# 1 passed, 0 failed, 68 filtered; 361.24s; service exit 0.
```

The no-default unified fixture avoided the separately CLI-feature-gated IdP fixture build. It also completed the existing live token, exact permission, denial, readiness, admission/revocation, persistence and restart checks. The listener is test-local plain HTTP; production TLS was not weakened. Existing fixture scopes/audiences and production provisioning were not changed. In particular `idp-management` remains the evaluator Application/audience, not a transport prefix; ordinary local service-client scope separation remains intact.

## Generator/tool invocation and real negative paths

Existing Node `v26.5.0`, pnpm and root package toolpaths were reused. Existing cached OpenAPI Generator `7.26.0` was selected through temporary worktree-only `openapitools.json` files (`generator-cli.version=7.26.0`; `generator-cli.storageDir` pointed to the already-present `setup-completion` worktree generator versions directory). Its jar was read, not installed or modified. Temporary root/package dependency symlinks allowed existing local tooling to resolve; pnpm exec refreshed bin shims through the dependency-directory symlinks. Cleanup reversed only this run worktree-prefix substitutions in root IdP/Management shims, and restored six worktree Storage shims plus its tracked generator config from the clean starting HEAD. Root Storage dirty bytes stayed untouched. Future isolated runs should use worktree-local bin directories rather than writable whole dependency-directory symlinks.

For each service the qualification script executes:

```sh
# cwd packages/<service>-client, actual endpoint substituted for that service:
OPENAPI_SPEC_URL=http://127.0.0.1:46035/<service>/openapi.json node ../../scripts/generate-openapi-client.mjs <service>
# npm_execpath and PATH are supplied by the exact systemd command above.
```

The generator executes the existing pnpm `exec openapi-generator-cli generate` typescript-fetch command and staged Biome formatting. It was invoked directly rather than package post-generation hooks, avoiding package-wide lint/build side effects. The generator emitted its upstream OpenAPI 3.1 beta/schema-name warnings; these were not TypeScript errors.

After EACH actual successful generation, the script reserved and closed an ephemeral loopback port, then invoked the SAME real generator with `http://127.0.0.1:<closed-port>/<service>/openapi.json`. Each failed nonzero with a real Java connection-refused/ConnectException and the existing generation failure message. Every path and byte under that service source was hashed before and after; all three digests were identical. Temporary staging and backup directories were absent after each failure. These were NOT fake-generator negative tests.

Run-time SHA256 digests (including then-present ignored generator metadata; that temporary metadata was subsequently removed during cleanup):

- IdP: `4ddac4d7828caf754c2062b6dc5ee7c31f739bf64ac7d0821f24d724b0f79b2f`
- Management: `b75f454360d8aa8360424c01501f1a870d66e255083f7ef0974b87cf2df6b5a6`
- Storage: `82512a77797445917f92082a79046cf560895fcd821d462ec28d6148765664ca`

## Focused client checks

```sh
node --test scripts/generated-clients.test.mjs
# Red before generation: 4/4 stale-output assertions failed.
# Final: 7 passed, 0 failed/skipped, 0.93s.
# Executes generated TS in memory through existing TypeScript; no emitted package output.

GENERATOR_TEST_BIOME=/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome node --test scripts/generate-openapi-client.test.mjs
# 147 passed, 0 failed/skipped; 11.81s.

/home/nathan/code/rust/aicacia/of/packages/idp-client/node_modules/.bin/tsc --project packages/idp-client/tsconfig.json --noEmit --incremental false
/home/nathan/code/rust/aicacia/of/packages/management-client/node_modules/.bin/tsc --project packages/management-client/tsconfig.json --noEmit --incremental false
/home/nathan/code/rust/aicacia/of/packages/idp-client/node_modules/.bin/tsc --project packages/storage-client/tsconfig.json --noEmit --incremental false
# All three exit 0; full package source checks, no emitted files or tsbuildinfo.

/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome check scripts/generated-clients.test.mjs scripts/qualify-openapi-clients.mjs
/home/nathan/.cargo/bin/rustfmt --edition 2024 --check crates/unified-server/src/runtime.rs
git --no-pager diff --check
# Passed.
```

The generated-client tests verify obsolete export/model removal; no duplicated service prefix in generated routes; actual generated health requests at exactly one prefix; bearer-only protected request options; encoded Device transfer URL `/devices/{device_id}/owner` and exact ownerSubject body; and Management subject/action/target serialization retaining the actual User and installation Device target. Test literals were corrected against current Rust route/domain definitions, not accommodated by changing generated code. A preliminary in-memory loader used the unavailable Node 26 transform mode; switched to the already-installed TypeScript transpiler without adding dependencies. These test-harness failures did not change contracts.

## Cleanup and limitations

The test joined the listener, shut down background/runtime/endpoint tasks, and deleted its isolated native stores. `systemctl --user list-units of06-clients* --all --no-pager` returned zero loaded units; no `/tmp/unified-runtime-*` directories remained. Temporary untracked configs, dependency symlinks and ignored generator metadata created by this slice were removed after checks; the existing tracked Storage generator config was restored; shared Cargo caches and existing worktree Storage shims were retained. No Storage client build/clean command ran and no root output was generated.

Root pre-existing Storage esm/types output and node_modules shim dirt was not written, stashed, reset or cleaned. No other agent-owned source was changed. Application/UI qualification, named docs, wider artifact audit, ticket 04 and ticket-wide resolution are not claimed here. The current integration tip is merged before reporting; only this evidence is force-added from ignored scratch content.

Post-cleanup: an extra Biome invocation from the root against worktree paths refused the nested root configuration. The same focused check rerun from the worktree passed; no configuration migration was run. Integration merge was already up to date at `2e67ed5`; ancestry check passed and scoped worktree status was clean. Root tracked dirty status remained identical to the initial inventory. Cleanup removed all live units, fixture stores, source backups and staging directories.
