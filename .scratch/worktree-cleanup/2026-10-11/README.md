# Workspace consolidation — 2026-10-11

User authorized removal of unused/finished worktrees and scratch clutter, and committing/merging delivered work into local `main` across all four repositories. This is repository housekeeping, not acceptance of unfinished tickets or permission to push.

## Delivered history

- `of`: delivered offline-first integration `29d6b3b` (103 commits above former main `5b22a32`), followed by this tracker/cleanup checkpoint. Tickets01/02/03/05/06 are resolved within recorded scopes;04 remains claimed/incomplete and07/08 open. The final main consolidation is a fast-forward, not a merge of unfinished auxiliary deltas.
- `ofdb`: local main fast-forwarded `3c4bf50` to `8b94799`,26existing commits. No new source commit or acceptance claim; integration retained.
- `offs`: local main fast-forwarded `7501cfe` to `dc91886`,9existing commits; lockfile-only commit `662f702` aligns the current committed public-persistence dependency graph. Integration ref also advanced to662f702.
- `ofnet`: already clean on main `85632a9`; nothing to merge or clean.

## Removed and archived

Registered worktrees across repositories:27before,8after (root4 plus4unfinished of auxiliaries). Removed17of,1ofdb and1offs auxiliary worktrees only after checking history, tracked deltas, ignored artifacts and process references.

- Of removed approximately21.768GiB of logical worktree file content. Unique review metadata/logs and duplicated native-reset generated outputs were copied/hash-verified before retirement; [worktree manifest](manifest.json) records exact paths and hashes. Added recovery ref `cleanup-review-completion-2026-10-11` for the merge-only detached review tip; no equivalent unique code was merged.
- Of removed the inactive historical `merge-review-cfe06833/target` cache,1.241GiB logical bytes; shared root target unchanged.
- Ofdb removed its6.0GiB allocated isolated Cargo cache and completed native-resource-retirement worktree; canonical evidence retained.
- Offs removed its completed managed-retirement worktree,1,841,147,224logical bytes; its26scratch files matched retained root copies.

Of root scratch folders consolidated14to3: `archive`, `offline-first-nodes`, `worktree-cleanup`. Twelve historical review/security directories and3metadata files moved into [the archive](../../archive/2026-10-11/README.md); all163moved files byte-identical. No current outside-archive Markdown hyperlink targeted a moved entry. Historical plain paths/commands and internal snapshot links remain historical; the index maps old to new locations. Archive data and private profiles are local/ignored, not indiscriminately staged.

Ofdb retains4small scratch folders (active storage-sync, unfinished KV-sharding, retirement evidence/review); offs retains3small referenced tracker/evidence folders. Ofnet has no scratch directory. Low-cost active or referenced evidence was not discarded just to reduce a count.

## Explicitly retained work

Four of worktrees and their branches remain:

- `auth-unavailability`: unique committed patch not integrated; preserve pending reconciliation rather than guessing it is equivalent to newer session handling.
- `bounded04-partial-bootstrap`: unique audit commit and2unfinished/unqualified Rust changes; historical stack-overflow/timeouts do not establish finished acceptance.
- `peer-revocation`:3modified tracked files and2newRust files; preserve all working code/lock changes.
- `setup-early-reset`: unique uncommitted regression test; preserve separately from current reset implementation.

Retain ongoing integration branches, the merge-only review recovery ref, existing stashes, native test profiles/keyrings/binaries, active04/07/08evidence, private/local environment files, sibling symlinks and all shared root targets. No secret/profile archive was staged. No reset/stash/prune/gc, broad gitclean, build, GUI or full validation sweep.

Of root ten existing Storage dirty files remain exact original bytes (4partial generated outputs,6machine-path shims), SHA256 of their combined diff `667afe03e6a9a7e0e3a4b277b1e1f6ea08082e845cba9591bf7d8b3e03cefe9e`. They are NOT a complete current distribution rebuild; no stale partial output or machine-specific shim was committed. Workspace source consumption remains qualified by ticket06; distribution requires the documented complete build.

## Validation

Checked Git ancestry, main/integration targets, scoped working-tree diffs, source preservation hashes, archive hashes, process references and whitespace. No new source test/build acceptance claimed.

Offs unfiltered offline locked metadata failed because cached `js-sys v0.3.106` was absent. The narrower `cargo metadata --offline --locked --filter-platform x86_64-unknown-linux-gnu --format-version 1` succeeded,121packages/resolved nodes; only this platform-scoped graph result qualifies lockfile coherence, not compilation or all-platform availability. The exact existing57-line lock delta was committed without regeneration or downloads.

Fully integrated short-lived branches may be deleted only after their worktrees are retired; unfinished checked-out branches and ongoing integration refs are excluded. Cleanup receipts and the current local tracker are committed selectively, not entire scratch trees or node_modules. Nothing is pushed to remotes.
