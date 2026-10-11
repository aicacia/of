# Ticket 06 completion — 2026-10-11

Integration: `offline-first-nodes-integration`, validated source tip `3f7baed0d7b6e61a6ecfc27c5824e0596ed7f143`.

Ticket 06 is resolved within its API/client/artifact scope under the user's explicit instruction to finish it despite the formally incomplete 04 prerequisite. Dependency links remain unchanged; 04 GUI approval, joining-Node completion and two-profile offline restart are not accepted. Neither 07/08 nor the complete spec is accepted here.

## Acceptance evidence

| Criterion | Delivered evidence |
| --- | --- |
| Complete verified specifications and safe owner generation | [Live clients](06-clients.md): actual three public routers served by isolated UnifiedRuntime, HTTP200, IdP50/Management24/Storage14 operations. Existing temporary-output generator used for each distinct endpoint. Real unreachable-input generation failed with identical source digests for all services; staged checks also cover missing URL/incomplete operations/groups/files/formatter failure. |
| Current identity/Device/policy/resource contracts | Generated DeviceTransferRequest/transferDevice and current permission/restriction/selection/resource/Residency contracts. Obsolete setup API/model removed through generation. Native trusted-peer setup/readiness remains IPC/Iroh rather than invented HTTP routes. |
| Prefixes, audiences, probes and callers | [Caller evidence](06-callers.md): once-only public owner prefixes, direct IdP administration, distinct idp-management audience, listener/setup availability separate from persistent readiness. Active password-manager now uses explicit service bases, storage:filesystems exchange resource, operation-specific actions and flat socket request contract. Production SvelteKit alias selects current source; isolated normal package build and five unaliased tests separately qualify distribution exports. |
| Obsolete artifact/security/dependency audit | [Audit](06-audit.md), [prior deletion](06-obsolete-contracts.md): retired source/contracts/configs and generated setup artifacts removed; legitimate signer/CRDT/RBAC/negative-fixture names retained. No internal persistence consumer dependency, new compatibility route or alternate actor authorization. Read-only external findings reported to owners. |
| Least privilege and separated state | Existing ordinary service-client scopes/audiences, secure secret injection, canonical issuer and distinct context roots retained. No production authorization, issuer verification or TLS bypass added. |
| Stable documentation | System API/security/design/operations, IdP local-security, Storage API/security, public-persistence and glossary links corrected. Requirements distinguished from verified evidence; historical audit checkpoint findings retained unchanged. |
| Focused qualification | Exact integrated commands/results below; full package typechecks and scoped host fixture pass. Historical failed harness runs and dependency/output limitations explicitly retained. |

## Coordinator's integrated reruns

From `of`, after integrating all branches (source tip66ed7ca; cwd-only test fix3f7baed afterwards):

```sh
GENERATOR_TEST_BIOME=/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome node --test scripts/generate-openapi-client.test.mjs scripts/generated-clients.test.mjs
# 154 passed,0 failed/skipped,13.63s.

packages/idp-client/node_modules/.bin/tsc --project packages/idp-client/tsconfig.json --noEmit --incremental false
packages/management-client/node_modules/.bin/tsc --project packages/management-client/tsconfig.json --noEmit --incremental false
packages/idp-client/node_modules/.bin/tsc --project packages/storage-client/tsconfig.json --noEmit --incremental false
# All three exit0, no output emitted.

# cwd of/apps/app
../../packages/idp-client/node_modules/.bin/vitest run --config vitest.auth.config.ts
# 66 passed,6files,0 failed;1.79s.

# cwd of/packages/storage-client
../idp-client/node_modules/.bin/vitest run --no-cache src/index.test.ts src/residency.test.ts
# 18 passed,2files,0 failed;433ms.

# cwd of/packages/svelte-headless
../idp-client/node_modules/.bin/vitest run --no-cache src/lib/state/createReturnTo.test.ts
# 7 passed,0 failed;831ms.

# cwd of, after3f7baed
node --test apps/password-manager/svelte.config.test.mjs
# 2 passed,0 failed;685ms. Actual SvelteKit runtime alias inspected.

git --no-pager diff --check
# Passed.
```

The first coordinator alias-test root invocation failed because SvelteKit read cwd rather than the test's app; the test now establishes its own app cwd and restores it. Parent rerun2/2 passes; implementer additionally ran it from the app2/2. Production alias itself did not change. Parent-created root `.svelte-kit/env.d.ts` is removed, not retained as user state.

Live runtime/generation and real source-preservation negatives executed by the client implementer are recorded with exact resource-bounded commands in06-clients: fixture1/1,361.24s, runtime tasks/listener/store cleanup. Compilation initially timed out240s; cached bounded600s retry succeeded9m47s. No second coordinator live generation or production/GUI deployment run is claimed. Independent review inspected all branches and found no remaining source/contract blocker; its initial password-manager and package-resolution blockers were fixed before closure.

## Retained limitations, constraints and cleanup

- Ticket04 remains incomplete; setup availability, actual router generation and focused fixture restart are not native two-profile acceptance. Docker/lifecycle/deployment qualification remains07/08; no fullCargoHack/CRAP or GUI retry.
- Pre-existing IdP pagination drift remains: generated application/consent query handling requires separate contract correction. No topology/auth security bypass was used to mask it.
- Raw checkout public Storage esm/types are not rebuilt in the root. Password-manager uses the same owned source through a production framework alias; distributed consumers must explicitly build and ship COMPLETE package output including generated dependencies, as documented. Isolated build/unaliased5tests qualify that workflow; no partial artifact commit or claim of root rebuild.
- Historical supplemental worktree auth55passed/11failed from missing built native-fetch is retained in06-callers; current integrated app66passed supersedes only the current check result.
- Constraint deviation: an isolated `pnpm run build` unexpectedly ran automatic workspace dependency setup. It was not an explicit install command, but no-install compliance and absence of network/cache metadata effects are NOT claimed. Exact effects/cleanup are disclosed in06-callers; later checks used direct existing executables.
- Root's ten pre-existing Storage output/shim files retain exact bytes: dirty-diff SHA256 `667afe03e6a9a7e0e3a4b277b1e1f6ea08082e845cba9591bf7d8b3e03cefe9e`. Private profiles, existing worktrees and shared targets are preserved. Background rust-analyzer/flycheck changed ignored shared build artifacts during integration; no cleanup/restoration of those artifacts attempted.
- Only the three worktrees created for this ticket are removed after verifying all commits integrated and no tracked changes. Ignored dependency/Svelte artifacts created by this isolated work are disposable; no older/evidence-bearing worktree is removed. Shared Cargo target is not cleaned. No prune/gc, reset, stash or cross-workspace writes.
