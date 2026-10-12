# Bounded04 frontend Residency/cleanup qualification

Date: 2026-10-11. Branch: offline-first-bounded04-residency-ui.
Worktree: of/.worktrees/bounded04-residency-ui.
Base: integration 04b84d0cc14f85d50cf5d0f81f0858807909b602.

## Scope and interpretation

Read revised ticket04 criteria8/9 and spec Machine-local qualification policy. Loaded tdd, ponytail, svelte-code-writer and svelte-core-bestpractices before component analysis. Complexity low; authorization/readiness interpretation risk high; priority focused qualification. No production defect established, so no production fix or speculative refactoring.

Only source change: apps/app/src/lib/common/state/ownerClients.test.ts. Reuses the existing Vitest configuration, generated source clients, desktop localhost/client seam and Svelte SSR render seam already used by Installation tests. No new dependency or framework. Adds eight cases alongside four retained owner-client cases.

Confirmed seam from task: actual frontend owner clients and existing component rendering. These are NOT browser event-handler/DOM interaction tests. No DOM test environment is installed in the existing suite; none added. This evidence narrows the frontend gap but does not claim reactive pending/error UI transitions or full criterion8/9 closure.

## Observations

- Full and Passthrough PUT promises remain unsettled while fetch replies are withheld. Each uses the verified local base plus one Storage prefix, exact filesystem target, transient filesystem bearer, requested mode and redirect:error. HTTP204 resolves void; there is no implicit GET or readiness result. Explicit subsequent GET returns only mode.
- For both modes, injected cleanup-pending HTTP409 propagates as owner error with no acknowledgement, automatic retry or setup-reset invocation.
- A composed client sequence acknowledges exact filesystem deselection and Full, then independently requests selection using the Management client and a distinct resource-scoped Storage token. Withheld selection reply remains pending; injected cleanup HTTP409 rejects without success or automatic retry. An explicit retry exchanges the new current actor and sends the fresh resource token, resolving only after injected HTTP204. Exact Device/Application/resource/kind and actual camelCase wire payload are checked. This does NOT demonstrate backend cleanup completion, transfer authorization or a real resource transfer; the server replies are controlled test fixtures.
- Actual SSR Residency rendering on desktop/web preserves Full content-availability and Passthrough reachable-peer limitations plus Storage cleanup-fence wording. No observed mode or mutation acknowledgement is rendered initially; empty-token Apply is disabled; web fieldset is disabled without native invocation.
- Actual SSR DevicePolicy rendering states independent owner authorization, no sign-in/join grant and no mutation-derived current-selection directory. Empty Device selection disables Select; database scope does not render filesystem Residency controls.

## Commands and exact results

Commands below run from of/.worktrees/bounded04-residency-ui/apps/app unless otherwise stated. Each Vitest invocation has a 90-second outer bound.

    node ../../node_modules/.pnpm/vitest@4.1.10_@types+node@26.1.2_@vitest+coverage-v8@4.1.10_vite@8.2.0_@types+node@26.1.2_jiti@2.7.0_yaml@2.9.0_/node_modules/vitest/vitest.mjs run --config vitest.auth.config.ts src/lib/common/state/ownerClients.test.ts

Final post-format run: exit0, one file, 12 passed, no failed/ignored; duration1.97s, tests1.733s. Previous green: 12/12, duration4.86s. Four old tests retained; eight new tests. No production RED-to-GREEN claim.

Earlier attempts, preserved here rather than called product regressions:

1. App and root .bin/vitest invocations each exit127 because no such shim exists. Used the already-installed literal Vitest module above instead; no install.
2. Initial execution: 12 failures, duration2.90s, missing packages/svelte-headless/.svelte-kit/tsconfig.json in fresh worktree. Added a test-only in-memory createStorage adapter mock. This excludes storage persistence/reactivity from evidence and avoids generating package outputs. Existing native/network/actor adapters were already mocked.
3. Next execution: 8 passed/4 failed, duration1.99s. Corrected fixture expectation from snake_case to the actual existing SelectionRequest camelCase contract; dynamic-imported Svelte render after vi.resetModules to share the component SSR runtime instead of retaining a stale static runtime.
4. Partial-line edit introduced two missing destructuring initializers: no tests, parse failure, duration0.202s. Corrected full import assignments.
5. Biome initially failed formatting only. Explicit scoped format corrected it; check then passes.

From worktree root, each autofixer bounded60s total:

    npx --yes @sveltejs/mcp svelte-autofixer apps/app/src/lib/common/components/ResourceResidency.svelte
    npx --yes @sveltejs/mcp svelte-autofixer apps/app/src/lib/common/components/DevicePolicy.svelte

Both: exit0, issues[], suggestions[], no further fix needed. Neither component changed. This is Svelte analysis, not whole-app svelte-check/typechecking or a frontend build.

From worktree root:

    ./node_modules/.bin/biome format --write apps/app/src/lib/common/state/ownerClients.test.ts
    ./node_modules/.bin/biome check apps/app/src/lib/common/state/ownerClients.test.ts
    git --no-pager diff --check

Final results: format/check exit0, one file; whitespace exit0. Reused existing root/app dependency directories via worktree-local node_modules symlinks; no dependency installation, package/client output generation or lockfile edit. Vitest created its ignored local app SvelteKit/cache support as part of the existing plugin; none staged. Missing package generated configuration was not repaired/generated.

## Limits and preservation

Mocked fetch/native URL/current actor/storage adapter plus actual frontend client serialization and SSR compilation are evidence only at those seams. Pending/error UI rendering after clicking, confirmation/cancel, double-submit protection, token clearing after component events, changing target during requests, and live transfer/retirement/cleanup-gated resource enabling remain unqualified. Tests do not invoke component event handlers. Mode acknowledgement or mode read is NOT content, peer, cleanup, selection, authorization or Node setup readiness. Successful mock selection retry is NOT proof that actual cleanup finished.

Native GUI approval remains deferred. No profile/provider/keyring/system mutation, native GUI, Rust build/test, Cargo Hack, CRAP or broad frontend build/check ran. No platform/power-loss certification, real-provider availability or actual authenticated join/offline reopen inferred. Ticket/map/status/criteria unchanged. Rust, generated package outputs, locks and root pre-existing storage-client dirt remain outside committed scope.

Commit only this evidence and the named frontend test. Merge integration tip INTO the own branch only; do not merge/advance the root integration branch. Integration tip observed before commit remains 04b84d0cc14f85d50cf5d0f81f0858807909b602; final merge/status result recorded below.

## Finish

Initial source/evidence commit: 3ba5254263840df6f3708717ee80f0e1efa87fb5. Hooks disabled to prevent cross-scope autofixes. Ran GIT_EDITOR=true git -c core.hooksPath=/dev/null merge offline-first-nodes-integration on the own branch: exit0, Already up to date. Integration still 04b84d0cc14f85d50cf5d0f81f0858807909b602; tracked worktree clean. This finish note is included by amending the qualification commit; the final commit ID is reported externally, not self-referenced here. No root merge.
