# Ticket 06 obsolete contracts/configuration checkpoint — 2026-10-11

Integration: `offline-first-nodes-integration`.
Source cleanup: `6ddd54dbda5b674df1af94f8ffd1928ef009d0f1`, parent `635b978`.
Config cleanup: `6c6b70f8a62847368b67c349aa6caa1f40f18b8d`, parent `6ddd54d`.

## Scope and disposition

Partial ticket 06; 04 remains incomplete under the user-directed verification deferral. No acceptance criteria promoted. Complexity low (deletion and inventory alignment); risk generated-client drift and removal of misleading launch paths; priority retire obsolete contracts without compatibility wrappers. No GUI, full Cargo hack, CRAP, dependency installation or cross-repository edits.

Deleted the always-denied `/setup/bootstrap` HTTP handler, runtime/OpenAPI registration and obsolete 403 test block. Deleted unused `SetupBootstrapRegistration`, `SetupBootstrapRequest`, `SetupJoinRequest`, `SetupJoinState`, `SetupJoinStatus`, `SetupNewRequest`, `SetupResidency`, `SetupDeviceRequest` and `SetupDeviceStatus` definitions/declarations/reexports after caller audit. Retained active `SetupStage`, `SetupStatus`, local setup status/IPC, exact-permission `/replica-signers` operations and actual filesystem Residency.

Generator inventory now follows 88 current operations in 9 groups (IdP50, Management24, Storage14); no obsolete setup group. Independent read-only source review approved deletion/inventory alignment and found no remaining Rust callers.

Removed obsolete `config.yaml`, `config/primary/config.yaml`, `config/secondary/config.yaml` and ambiguous `api`/`api-secondary` just recipes. These used obsolete top-level bootstrap/database/UI fields. Preserved configuration data and the current `config/unified/example.yaml`, separate context roots, service-client audience/scopes and environment secret references. Generic CLI default/Docker mount path expectations remain; users must supply valid owner configuration. The unified example contains placeholders and is not a ready deployment or credential provisioning claim.

## Focused validation

Coordinator independently ran in `of/.worktrees/api-contract-cutover`:

```sh
GENERATOR_TEST_BIOME=/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome node --test scripts/generate-openapi-client.test.mjs
# 147 passed, zero failed/skipped; 14.29 seconds.
```

Implementer focused rustfmt, Biome and whitespace checks passed. Early offline single-job Rust attempts did not complete: route build twice timed out at90s, CLI-enabled check at90s, model-only check at30s. These were build timeouts, not test failures or validation successes.

One final cached focused attempt passed under systemd resource limits:

```sh
# Working directory: of/.worktrees/api-contract-cutover
systemd-run --user --unit=of-api-contract-route-validation --wait --pipe --collect --working-directory=/home/nathan/code/rust/aicacia/of/.worktrees/api-contract-cutover --property=MemoryMax=6G --property=TasksMax=512 --property=CPUQuota=200% --property=RuntimeMaxSec=240 --property=TimeoutStopSec=5 /usr/bin/env CARGO_TARGET_DIR=/home/nathan/code/rust/aicacia/of/target CARGO_BUILD_JOBS=1 /home/nathan/.cargo/bin/cargo test --offline -p idp-server --lib --no-default-features router::openapi_router::tests::excludes_obsolete_bootstrap_and_keeps_idp_signer_routes -- --exact
# Build3m33s; test1 passed,0 failed,39 filtered; service runtime3m34.369s, exit0.
```

No warnings/errors emitted. This qualifies the changed no-default-features library regression, not the separately feature-gated CLI test.

Implementer and coordinator each ran `just --list`, `just --dry-run unified config/unified/example.yaml` and `git --no-pager diff --check`: passed. A dry run is not a launched host.

## Remaining work and preservation

No current live endpoint verified and no generated client changed. The live IdP fixture is CLI-feature-gated, unavailable in the just-built test binary. No further feature-set build attempted. Checked-in IdP client still advertises `SuperRoutesSetupApi`/`registerBootstrap` and must be regenerated through the existing generator from a verified endpoint; no active application caller was found. TypeScript/current HTTP contract qualification, prefix/probe clarification and the wider artifact/document audit remain pending.

Docker source review also found pre-existing `idp-unified` project/bin defaults despite current `unified-server`; this is a separate runtime/deployment follow-up, not fixed or accepted by config deletion.

Both scoped commits were fast-forwarded by a merger with hooks/maintenance disabled; original root storage-client dirty bytes/status and retained worktree/native-target metadata stayed unchanged. No stash/reset/clean/Git maintenance. Only the clean fully integrated api-contract-cutover worktree is removed after verifying no ignored/untracked artifacts; the reused shared Cargo target is preserved, not cleaned.
