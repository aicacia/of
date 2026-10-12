# Finished-work consolidation and ticket08 handoff — 2026-10-12

User authorized collecting what is needed to finish the spec and cleaning/committing/merging everything else before fixing08. This is housekeeping plus the already-evidenced owner06 handoff, not ticket08 or full-spec acceptance. No code fixes, builds/tests, provider/profile/CA changes or pushes are part of this checkpoint.

## Finished delivery

- `of`: prior main `fc74d95` is an ancestor of finished integration `290738b`. Consolidate that history plus this documentation/recovery checkpoint by fast-forward to main.01–07 stay resolved within their recorded scopes.08 remains claimed; no failing08 source or timers merged.
- `ofdb`: consumer handoff06 resolved by docs-only `bfd21de` using accepted of02/of03 producer evidence, with commands/source ownership/failures/limits retained. Branch-retirement receipt `8a848b2` is current local main. Temporary owner diagnostics stay unmerged on `diagnostics/native-idp-stage-timing` at `b21c583`.
- `offs`: already-delivered source stays on main; branch-retirement receipt `de75aea` is current local main.
- `ofnet`: clean main `85632a9`, no outstanding finished history.

No new runtime acceptance is inferred. Preserved of03 completion/review READMEs are selectively committed as historical receipts; their then-current wording is not current ticket state. They support the now-closed ofdb06 handoff.

## Auxiliary worktree retirement

Five of worktrees were archived before removal: auth-unavailability, bounded04-partial-bootstrap, bounded04-residency-ui, peer-revocation and setup-early-reset. [Manifest](manifest.json) records exact tips, branches, tracked/untracked status, archive membership counts and SHA256/size for every bundle, tracked binary patch and filesystem tar.

- Each Git bundle was verified.
- Full filesystem snapshots include ignored build/dependency artifacts and untracked source/evidence. Tar did **not** dereference symlinks; archive regular-file content hashes and symlink targets were compared with the live worktrees before removal. `.git` pointer files were excluded; bundle history is the recovery mechanism.
- Snapshot tars total **4,240,066,560 bytes**. They are local/ignored, not committed. No private profile or external credential provider was inspected, reset or copied. Snapshot content is not certified public; do not publish archives indiscriminately.
- Archived dirty/ignored worktrees required explicit `git worktree remove --force`, only after verification. This retires filesystem checkouts, not qualification history.
- Residency, peer-revocation and early-reset refs were deleted with `git branch -d` after merged ancestry was checked. The latter two local drafts were archived, not merged over newer implementations.
- Auth `0716062` and partial-bootstrap `c4ef122` refs remain as inexpensive recovery pointers: unique/unqualified history is not accepted as finished. Their checkouts are gone. Existing merge-only recovery ref and all previous stashes remain.
- Current of worktrees are root and live `.worktrees/ticket08-full-nodes` only. Sibling `.worktrees/{ofdb,offs,ofnet}` symlinks and their targets are untouched.

Ofdb `storage-sync-integration` and offs `filesystem-sync-integration` were retired with `git branch -d` after ancestry checks; history remains in main and receipts record the original tips. Small linked owner scratch evidence/planning directories are deliberately retained, not shuffled into broken-link archives. `ofdb` storage-sync remains live for ticket16 diagnostics; unfinished KV-sharding is not discarded. Historical archives and cleanup receipts stay where their links resolve.

## Root user changes

The ten pre-existing Storage-client changes are partial generated distribution output and machine-path shims, not a complete qualified rebuild. They were **not committed as finished source**. The three profiling-only root lockfile edges were likewise not merged into finished main.

All11 root modifications are saved together in stash commit **`21edf8364e9eef1704f2c6a108ead6f08dfb79a2`**, message `cleanup-2026-10-12: preserve partial Storage distribution shims and profiling-only lock edges`. Additional local `preserved/root-user-work.patch` and verified complete-history `preserved/root-user-work.bundle` retain recovery independently of stash position.

Original Storage-only binary-diff SHA256 remains **`667afe03e6a9a7e0e3a4b277b1e1f6ea08082e845cba9591bf7d8b3e03cefe9e`**, verified from the stash against its parent. Root is clean after preservation; no blanket reset, clean, stash-drop or prune. The existing four older stashes are untouched. Apply only the desired paths when recovering partial output; the diagnostic lock edges belong with the diagnostic owner source, not finished owner main.

## Recovery

Preservation files are under `.scratch/worktree-cleanup/2026-10-12/preserved/`.

- For a retired branch, use its retained ref or verified bundle to create a new worktree at the manifest tip. To recover dirty/untracked/ignored files, extract its tar into that checkout **without overwriting `.git`**; patches separately identify tracked modifications. Inspect symlink destinations before use. Source remains unqualified.
- For root user changes, inspect the named stash commit or patch; do not rely on a numeric stash position. The bundle can recover the stash commit if refs later change.
- For08, use [remaining-work handoff](../../offline-first-nodes/remaining-work.md). Consumer `57426e3` and owner diagnostics `b21c583` stay separate from main; the owner root is now main and diagnostics must be deliberately reactivated before profiling.

## Validation and limits

Validated ancestry, worktree/branch inventories, tracked diffs, bundle integrity, archive byte hashes/symlink identity, preserved Storage diff hash and whitespace. Final fast-forward/status checks are recorded by the coordinator. No full Cargo Hack, CRAP, GUI retries or build sweeps. Prior OOM/timeouts remain failures; cleanup does not improve their acceptance status. Shared root targets, root dependency installs, native profiles/provider state and recovery refs were not pruned.
