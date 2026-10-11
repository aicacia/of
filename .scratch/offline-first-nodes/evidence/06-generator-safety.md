# Ticket 06 generator safety checkpoint — 2026-10-11

Integration branch: `offline-first-nodes-integration`.
Implementation: `bd5fec48a7995f426d57bdfd6a67c8f6e77edee6`, parent `e4eb566d47dd6261016c27be4c11074066bf292c`.

## Disposition

Partial ticket 06 progress under the user-directed deferral of prolonged ticket 04 verification. Ticket 04 remains incomplete; ticket 06 remains claimed, with no acceptance criteria promoted. No GUI retry, full Cargo hack or CRAP sweep.

Complexity: bounded inventory and staged validation in the existing generator. Risk: incomplete generated API publication and source loss. Priority: preserve sources before current-contract regeneration. No dependencies added.

## Delivered

- `scripts/generate-openapi-client.mjs` requires all current registered operations and API groups: IdP 51/5, Management 24/2, Storage 14/3. Includes `transferDevice`, absent from the stale generated IdP client.
- Required supporting files must exist and be nonempty. Existing package Biome configuration formats/parses temporary output before publication. Existing source backup/rollback behavior remains; Storage replaces only `src/generated`.
- `scripts/generate-openapi-client.test.mjs` covers missing inputs, failed/partial generation, absent groups/operations/files, staged formatting failure, source preservation, successful replacement and staging cleanup across all three services.
- Independent source review found no blockers for this bounded slice. Independently compared registered router operations and explicit OpenAPI paths, including API group assignment.

## Exact focused validation

Implementer ran in `of/.worktrees/api-generator-safety`:

```sh
node --test scripts/generate-openapi-client.test.mjs
# 146 passed; 3 optional real-Biome tests skipped.

GENERATOR_TEST_BIOME=/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome node --test scripts/generate-openapi-client.test.mjs
# 149 passed; none skipped.

/home/nathan/code/rust/aicacia/of/node_modules/.bin/biome check scripts/generate-openapi-client.mjs scripts/generate-openapi-client.test.mjs
# Passed after focused formatting.

git --no-pager diff --check
# Passed.
```

Coordinator independently reran the explicit `GENERATOR_TEST_BIOME` command: **149 passed, zero failed/skipped, 13.35 seconds**. Generation was fake; actual Biome processed synthetic output. Tests do not establish live endpoint availability or document correctness.

Work branch confirmed integration ancestry and merged its tip before reporting. Independent merger fast-forwarded integration with hooks disabled, verified dirty tracked bytes/status and retained untracked metadata unchanged. Integration `diff --check` passed. No stash/reset/clean or maintenance cleanup.

## Remaining limitations and next work

- No service-specific live endpoint verified; no clients regenerated. Current contracts, obsolete artifacts/configs and named documents still require ticket 06 work.
- The current inventory deliberately mirrors the current Rust router, including the obsolete denied `/setup/bootstrap` route. Remove its inventory entry and associated test expectations when removing the source route; do not retain it as compatibility.
- Structural inventory/file presence and Biome syntax checks do not prove model completeness, barrel exports or TypeScript type correctness.
- Default test invocation skips real-Biome cases; supply the explicit environment variable for that coverage.
- Two publication renames are not crash-atomic or safe against concurrent generators; caught rename failure rollback is inherited, not a newly proven interruption guarantee. No publication-failure injection test was added.
- Package post-generation hooks remain unchanged and can fail after publication for package-wide reasons.
- Test inventory comparison flattens groups and does not independently cover every explicit IdP/Management OpenAPI path; current grouping/path coverage was independently reviewed, not automatically future-proofed.
- Pre-existing storage-client outputs/shims, historical profiles, evidence-bearing worktrees, shared native target and recovery Git objects are preserved. Cleanup is limited to the clean, fully integrated generator worktree, which has no ignored artifacts or Cargo target.
