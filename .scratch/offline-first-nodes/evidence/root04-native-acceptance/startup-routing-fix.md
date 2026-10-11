# Native initial auth startup routing fix

## Qualification

Implemented only in the new `of/.worktrees/rootintegrationlatest` worktree, branch `rootintegrationlatest`, based on root integration commit `dd18105` (`Isolate native profile CA trust entries`; includes CA collision fix `fed34ac`). No root merge, GUI launch, Rust/CA modification, or client generation was performed. Root's existing dirty package outputs and other worktrees were not touched.

This is a frontend routing regression qualification, **not native GUI acceptance**. The reported two blank native windows and repeated TLS requests were the input symptom; no new native-window probe was run. Complexity is low (one setup-stage gate and deletion of eager hydration), risk is startup ordering/security readiness, and priority is blocking first-run setup. Public-load regressions cover routing and fail-closed behavior without weakening ready-state authorization.

## Verified root cause

- Before the fix, `apps/app/src/routes/(auth)/+layout.ts` awaited IdP URL discovery, desktop OIDC client ID, and Management URL discovery without querying setup readiness. Missing credentials then routed to sign-in, too late to avoid discovery.
- `apps/app/src/lib/common/state/localhostBaseUrl.svelte.ts` performs browser `fetch` against `/idp/health` and `/lidp/setup/status`, with 300 attempts at 100 ms intervals. Neither a setup HTTP success nor a stored bearer proves full local readiness.
- `apps/app/src-tauri/src/app.rs::init_setup_router` nests the setup router at `/lidp`; `setup.rs::router` exposes only `/setup/status` and has no CORS layer. It does not expose IdP health. `get_desktop_client_id` reads persisted `setup-ids.json`, unavailable before Installation setup.
- Merely adding a guard to `load` was insufficient: both IdP and Management state modules launched native localhost discovery at module import. The root layout's `ConfigForm.svelte` also imports both modules. Their eager hydration would continue probes even when auth load redirected promptly.
- The existing `getSetupStage` uses `get_setup_stage` IPC. Native `local_setup_stage` distinguishes incomplete Installation, unavailable local contexts, incomplete Device setup, and ready state. Ready checks local public context state and Device completion, not a remote peer's availability.
- Existing routes already cover the required UI: `/setup/installation` accepts `installation` and `unavailable`; unavailable renders `Retry local services`, invoking `retry_local_runtime`. `/setup/device` handles Device completion. No new route or HTTP setup bypass is needed.

## Bounded change

1. Native auth load queries `getSetupStage` before any owner discovery, OIDC client-ID lookup, credential read/clear, or owner userinfo request.
2. `installation` and `unavailable` redirect to `/setup/installation`; `device` redirects to `/setup/device`. These paths do not clear credentials, set a sign-in return target, or claim authenticated readiness.
3. IPC failure or an unknown stage fails closed with HTTP 503 and an explicit Retry message, using the existing root error UI.
4. Only `ready` continues the original local client initialization, Installation issuer guard, token exchange, and userinfo verification. Local ready verification needs no remote peer. An existing bearer alone still cannot grant access; authorization rejection and malformed/unverifiable userinfo remain denied.
5. Deleted the native import-time hydration functions/calls in IdP and Management state. Their existing explicit ensure functions remain responsible for endpoint discovery after readiness. Web hydration remains unchanged. Consequently, merely importing these modules no longer probes native localhost; config defaults remain empty/cached until explicit discovery.

## Agreed seam and TDD evidence

Tests exercise exported auth `load` through the real setup IPC wrapper, localhost discovery, IdP state/client, token exchange/userinfo, and Management state/client. Only host IPC, session storage/OIDC holder, navigation, and network boundaries are substituted. `vitest.auth.config.ts` adds a Management source alias; no generated client is edited.

Red: the new fresh-Installation test, with real localhost discovery and Management state, timed out at 5 seconds in the old retry path. Green: after the guard and deletion of import-time probes, that test passed in 24 ms; the complete suite passes **25 tests**.

Coverage includes zero import-time discovery requests, fresh Installation with no bearer/client prerequisites, Device routing, unavailable routing with session preservation, IPC failure/unknown-stage denial, unavailable-to-ready retry, completed offline local-owner verification, unavailable UI's explicit service retry, all existing owner outage/rejection/malformed-response cases, and missing-bearer/other-Installation denial.

## Validation results

All commands ran in this worktree, not root.

- `pnpm install --frozen-lockfile --offline`: passed. This fresh worktree needed a local ignored `apps/app/node_modules/vitest` symlink to the already-installed workspace IdP Vitest package; no dependency/lockfile change.
- From `apps/app`: `../../packages/idp-client/node_modules/.bin/vitest run --config vitest.auth.config.ts`: **25/25 passed**. Final captured rerun also reports 25/25 (2.31 seconds).
- Initial `pnpm build` failed on stale Storage package exports (`ResidencyMode`, `ResourcesResidencyApi`, `StorageOwnerConfiguration`); initial `pnpm check` lacked package declarations. These were fresh-worktree package-output prerequisites, not frontend source changes.
- From worktree root: `pnpm packages:build`: passed. Used existing build scripts only, no OpenAPI/client generation or hand-edited outputs. Package-build outputs and tracked install-generated bin scripts are excluded from the commit and restored to this worktree's baseline after validation.
- From `apps/app`: subsequent `pnpm build`: **passed**, including `Using @sveltejs/adapter-static`, `Wrote site to "build"`, and `done` (44.46-second server build).
- From `apps/app`: `pnpm check`: **0 errors, 0 warnings**. Final captured rerun reports the same.
- `npx --yes @sveltejs/mcp svelte-autofixer` on both changed state modules and existing Installation setup component: no issues/suggestions. On unchanged root error component, the analyzer flags `goto(page.url)` for missing `resolve`; the argument is an existing URL rather than a route literal. Left outside scope; type check passes.
- `git diff --check`: passed.

A final parallel log-capture repeat exceeded terminal limits (60 seconds for tests/check command, 120 seconds for build). Tests/check had printed PASS and their logs contain successful results. The repeated build log stops after client compilation (`built in 3m 22s`) and does **not** establish a second completed adapter build; it is not counted as a pass. The earlier completed production build above is the build qualification. Local `startup-routing-*.log` files are retained as ignored artifacts, not committed.

No Rust tests/feature powerset or Rust complexity run: this fix changes frontend code only. No actual-window acceptance claim is made. The remaining acceptance step is a deliberate native GUI rerun after integration; it was explicitly excluded from this task.
