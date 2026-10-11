# 06 API clients and obsolete artifact removal

Status: resolved
Type: task
Work status: resolved
Blocked by: 03, 04, 05

## What to build

Update current contracts and safely regenerate clients for equal offline-first Nodes; remove stale centralized-role artifacts. Question: do all public callers use the current owner API without old join roles or live-central dependencies?

## Scope and acceptance criteria

- [x] Obtain complete current specifications from verified endpoints and use existing temporary-output generators. Missing URL, unreachable endpoint, incomplete operations or failed generation leave generated sources unchanged. No hand-editing generated code.
- [x] Include current identity/Device, permission, restriction, selection, transfer, trusted-peer setup and readiness contracts. Preserve IdP identity administration ownership and exact actor/action/target semantics; do not invent undocumented routes.
- [x] Service prefixes are joined exactly once; keep built-in Management Application URI `idp-management` distinct from transport prefixes. Update desktop probes/callers to distinguish setup from persistent local readiness.
- [x] Audit docs, sources, configs, specs and generated output in `of` for designated authority/replica roles, Storage-only joins, freshness gates, obsolete setup/signing routes, password-grant join, remote-only authorization, alternate actor headers, removed credentials and internal persistence dependencies. Delete obsolete contracts/configuration through the owning generation or source workflow; no compatibility wrappers.
- [x] Keep least-privilege ordinary local service-client scope/audience boundaries, explicit permissions, secure secret references and separate context state. Never widen access just to satisfy a new topology.
- [x] Update named system/context API/security/operations documents and glossary links as implementation becomes verified. Keep historical evidence explicitly historical, not silently rewritten into new acceptance.
- [x] Record generation success, negative-path source preservation and focused client/UI checks; separate pre-existing generated/dependency failures. Cross-workspace obsolete artifacts are reported to owners, not edited here.

## Verification and completion

Assess complexity/risk/priority. Use existing generators/checks and record exact commands/results. No unavailable endpoint or unrun check counts as success.

## Comments

2026-10-11 recovery: integration `e4eb566` verified. User-directed scoped progress proceeds while 04 remains incomplete; dependency and acceptance are not waived. First slice strengthens existing generator completeness and failure/source-preservation checks in an isolated worktree. Complexity: bounded generation/validation flow; risk: destructive publication of incomplete generated APIs; priority: prevent source loss before current-contract regeneration. No native GUI retry, full Cargo hack or CRAP sweep. Existing root storage-client artifacts/shims are preserved. Endpoint generation and broader artifact removal remain pending.

2026-10-11 partial slice integrated as `bd5fec48`: complete current operation/group inventory, supporting-file validation and staged Biome formatting before publication. Independent source review approved; coordinator rerun149 passed/0 skipped with actual Biome and fake generation. [Exact commands and limitations](../evidence/06-generator-safety.md). No endpoint/regeneration or full criterion acceptance; 06 remains claimed. Existing obsolete setup route remains in the current inventory until coordinated source removal. Pre-existing storage-client artifacts preserved; only clean integrated generator worktree eligible for cleanup.

2026-10-11 next partial slices integrated`6ddd54d`/`6c6b70f`: obsolete denied bootstrap route/unused setup contracts removed; current generator inventory aligned;3stale configs/ambiguous2launch recipes deleted. Independent source review approved; generator147/147 independently passed with real Biome. Changed Rust route regression1/1 passed under240s/resource-bounded cached build, superseding only its earlier build timeouts; CLI-enabled qualification remains unrun. just list/dry-run pass. [Exact evidence and remaining generated drift](../evidence/06-obsolete-contracts.md). No live endpoint/client regeneration or full criterion acceptance;04 incomplete/06 claimed, data/shared targets and pre-existing storage-client artifacts preserved.

Retains old 10 and artifact portions of 15/17/19. Generic APIs remain owned externally; this ticket only updates `of` contracts/callers. [Map](../map.md).

## Answer

Resolved on `offline-first-nodes-integration`, validated source tip `3f7baed`, under the user's explicit instruction to finish06 despite the formally incomplete04 prerequisite. Dependency links remain;04 is not accepted by this closure.

All seven scoped criteria are evidenced in [completion](../evidence/06-completion.md): actual live three-router generation50/24/14 operations, real unreachable-input source preservation, current generated owner contracts and obsolete setup removal, once-only prefixes and listener/readiness distinction, corrected active password-manager resource/socket caller and production source resolution, least-privilege/artifact audit and current stable docs. Independent review's active-caller/packaging blockers were fixed before closure.

Final integrated focused checks:154generator/generated-client tests,66app tests,18Storage tests,7headless tests,2production alias tests and all3client noEmit typechecks passed. Separate isolated host/generation fixture1/1 and normal built package/unaliased5tests passed; no production GUI/deployment/full-spec claim.

Preserve historical55pass/11fail worktree dependency qualification, pre-existing pagination drift, explicit complete distribution-build requirement, unexpected isolated pnpm dependency-setup deviation and exact original root artifact bytes.04/07/08 limits, shared target/profiles and older worktrees remain unchanged. No fullCargoHack/CRAP or native GUI retry. [Exact commands, limitations, review and cleanup](../evidence/06-completion.md).
