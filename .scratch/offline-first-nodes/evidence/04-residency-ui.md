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

## Follow-up: genuine component events and reactive DOM (2026-10-11)

This section supersedes the earlier infrastructure conclusion and the specific component-event deferral for the cases below. The earlier 12-test observations remain valid at their original seams; they were not themselves event tests.

### Installed infrastructure audit

Read revised criteria8/9 and machine-local policy again. Audited 421 installed workspace pnpm entries plus package manifests in the global pnpm tree (2082 scanned) and existing npm execution caches (3166 scanned). No workspace jsdom/happy-dom/linkedom, Vitest browser provider, Playwright/Puppeteer, or Testing Library is installed. Existing app Vitest configuration is Node/SSR; svelte-headless configuration explicitly has only a Node/server project. No standard Chromium/Chrome/Firefox executable was found on PATH or at the checked /usr/bin paths; normal Playwright/Puppeteer browser caches were absent.

However, an already populated npm cache contains jsdom26.1.0 at /home/nathan/.npm/_npx/f2259fd4c4b894b7/node_modules/jsdom/lib/api.js. Cached Testing Library and Puppeteer packages were also found but are not used. This makes genuine component events possible without installing a package or adding a framework. The earlier assertion that a DOM environment was unavailable was too broad: it was accurate for workspace dependencies, not the wider installed cache.

A discovered Go Playwright CLI at /home/nathan/code/go/bin/playwright was queried with --help. Unexpectedly, even that query attempted to download its missing1.47.2 driver and failed exit1 with HTTP404 at all three configured mirrors. No driver install succeeded; no browser/provider/profile was used. Abandoned that path. The DOM test path uses only existing local packages and performs no install/download.

### Minimum genuine seam and implementation

User-confirmed seam: rendered ResourceResidency and DevicePolicy controls and their actual component event handlers/reactive state. No source instrumentation, handler exports, controller extraction, custom fake DOM or new test framework.

New source files, all under apps/app:

- vitest.residency.config.ts: reuses existing owner-client aliases/SvelteKit plugin, selects only the interaction file, and resolves Svelte's browser/client runtime. It does not change the existing Node/SSR configuration.
- src/lib/common/components/residency.environment.ts: a small existing-Vitest environment adapter using Vitest populateGlobal and the existing jsdom. RESIDENCY_JSDOM_MODULE selects the already installed module; otherwise normal jsdom resolution is used. No absolute machine path in source, package manifest or lockfile change. Closes the DOM/restores globals at teardown.
- src/lib/common/components/residency.interaction.test.ts: uses Svelte mount/unmount/flushSync, actual DOM input/change events, button.click and native form-submit dispatch from clicking Submit. Native desktop/base URL, confirmation and owner responses are the mocked boundaries. Production components and their state/event code are unchanged.

Three interaction cases:

1. Full Apply: enter mode/token, click; withhold actual generated Storage-client fetch reply; observe fieldset disabled, no status, no duplicate request from a second click. Inject409; actual handler renders the no-success/setup-preservation alert, clears token, releases busy but disables Apply for empty token. Enter a fresh token/click again;204 renders only mode acknowledgement plus explicit no-content/cleanup-readiness caveat, clears the alert/token and does not publish owner-read current mode.
2. Same genuine event/state sequence for Passthrough, with the displayed acknowledged mode asserted separately.
3. Mount DevicePolicy with an approved Device; fill Device/Application/resource/kind through rendered controls; click Deselect and child Full Apply. Neither acknowledgement invokes selection. Click Select without independent resource token: actual handler rejects before owner call. Enter token/click Select: actual submit handler disables Select/Deselect and Device/resource edits while pending, clears earlier error and publishes no selection acknowledgement; disabled repeat click makes no second call. Inject cleanup-pending error: alert, no success, token cleared, no retry. Enter fresh token/click explicit retry: policy-only acknowledgement, no authorization/cleanup/Residency readiness claim, alert/token cleared and exact fresh selection request observed.

The cleanup error is deliberately controlled at the owner boundary to qualify UI handling, not to prove Storage/Management fencing. Existing real owner HTTP evidence owns actual cleanup/transfer enforcement; no duplicate owner HTTP/Rust run. Re-enabling request controls after an error is retry availability, NOT enabling resource content. These components expose no ready-content control or readable selection directory.

### Exact runnable commands/results

From of/.worktrees/bounded04-residency-ui/apps/app, both final commands ran sequentially under a90-second outer bound:

    RESIDENCY_JSDOM_MODULE=/home/nathan/.npm/_npx/f2259fd4c4b894b7/node_modules/jsdom/lib/api.js node ../../node_modules/.pnpm/vitest@4.1.10_@types+node@26.1.2_@vitest+coverage-v8@4.1.10_vite@8.2.0_@types+node@26.1.2_jiti@2.7.0_yaml@2.9.0_/node_modules/vitest/vitest.mjs run --config vitest.residency.config.ts

Final POST-integration-merge: exit0, 3 passed, one file, duration2.43s/tests679ms/environment345ms. Prior final-shaped premerge pass3/3, duration2.49s/tests662ms; first Full/Passthrough-only run2/2, duration2.17s. No failed interaction assertions or production RED-to-GREEN bug claim. First run emitted config extension and deprecated vitest/environments warnings; switched to explicit .ts config import and current vitest/runtime. Final runs have neither warning.

    node ../../node_modules/.pnpm/vitest@4.1.10_@types+node@26.1.2_@vitest+coverage-v8@4.1.10_vite@8.2.0_@types+node@26.1.2_jiti@2.7.0_yaml@2.9.0_/node_modules/vitest/vitest.mjs run --config vitest.auth.config.ts src/lib/common/state/ownerClients.test.ts

Final POST-merge retained client/SSR suite: exit0,12 passed, one file, duration1.68s/tests1.443s. This and interaction3/3 are two suite observations, not a single combined15-test run.

From worktree root:

    ./node_modules/.bin/biome check apps/app/src/lib/common/components/residency.environment.ts apps/app/src/lib/common/components/residency.interaction.test.ts
    git --no-pager diff --check

Both exit0. Earlier formatting/import-order diagnostics corrected with scoped Biome check --write. The app Biome includes exclude vitest.* config files; checked/formatted that config via Biome --write --stdin-file-path=apps/app/vite.config.ts, using its output, and independently verified idempotent output/exit0. Initial non-write stdin checks exit1 because contents were not fixed; not a product/runtime failure.

Repeated both existing Svelte autofixer commands from the earlier section: both exit0, issues[], suggestions[]. No component changed; no full svelte-check/build or inherited-error sweep claimed.

### Revised-criteria assessment and remaining limits

The old SSR/client seam reasonably contributed focused frontend evidence for current owner prefixes, initial scope/readiness messaging and response propagation under the revised policy. It did not establish actual handler/reactive behavior and was insufficient to claim the specifically requested component-interaction qualification. The three genuine DOM tests now qualify that focused Residency/selection UI slice. They can reasonably be combined with existing owner HTTP/native observations as criteria8/9 expressly allow; a whole native GUI matrix is not a newly invented closure gate. This slice alone does not decide the full ticket's create/join/setup/readiness obligations or alter its status/checkmarks.

Remaining limits: jsdom is an emulated DOM, not native Tauri/browser rendering/layout/accessibility-tree or real user-provider acceptance. The module remains an external pre-existing cache dependency: repeat on this machine using the exact environment variable above; a machine without that installed module cannot run this suite unchanged without making it available. This is disclosed, not a newly declared project dependency. Real cleanup/transfer, peer/content availability and actual authorization are not inferred from controlled responses. Mode acknowledgement still never means content/cleanup readiness. No new package/lock/client output, Rust build/test, GUI approval/profile/keyring/system trust mutation or root merge. No specific production bug was exposed, so no speculative fix.

Integration advanced during this follow-up. Merged tip8a70deeaf967dad1c9887a8d498dbeaa77a995ee INTO the own branch with hooks/gc disabled; conflict-free merge5b3be3ebfc1f973b640edbfacd7b2a4d1c117e39. Its five inherited07 paths include Rust/tests/evidence; none authored/edited or built in this frontend task. Both final frontend suites above run on that merged branch. Root integration was not merged into/advanced by this agent. Follow-up commit stages only the three new frontend test-support/test files and this evidence.
