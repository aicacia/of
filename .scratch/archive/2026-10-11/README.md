# Cold evidence archive — 2026-10-11

This archive consolidates historical `of` merge-review and security evidence. Paths below are relative to the `of` repository root. Moved file bytes and preservation snapshots are unchanged; `manifest.json` records each file's before/after SHA-256 and the cleanup checks. The initial move stage staged nothing. Only this index and selected tracker/cleanup receipts are committed in the subsequent checkpoint; archive metadata, logs and snapshots remain local and ignored. Review them before selecting anything for publication.

## Original → archived paths

| Original path                                         | Archived entry                                                                           |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `.scratch/merge-review-a095bba5/`                     | [merge-review-a095bba5/](merge-review-a095bba5/)                                         |
| `.scratch/merge-review-api-b937/`                     | [merge-review-api-b937/](merge-review-api-b937/)                                         |
| `.scratch/merge-review-bc847f8d/`                     | [merge-review-bc847f8d/](merge-review-bc847f8d/)                                         |
| `.scratch/merge-review-c11feef/`                      | [merge-review-c11feef/](merge-review-c11feef/)                                           |
| `.scratch/merge-review-cfe06833/`                     | [merge-review-cfe06833/](merge-review-cfe06833/)                                         |
| `.scratch/merge-review-current-boundaries/`           | [merge-review-current-boundaries/](merge-review-current-boundaries/)                     |
| `.scratch/merge-review-d390c7b6/`                     | [merge-review-d390c7b6/](merge-review-d390c7b6/)                                         |
| `.scratch/merge-review-e7526fe/`                      | [merge-review-e7526fe/](merge-review-e7526fe/)                                           |
| `.scratch/merge-review-setup939/`                     | [merge-review-setup939/](merge-review-setup939/)                                         |
| `.scratch/security-candidates/`                       | [security-candidates/](security-candidates/)                                             |
| `.scratch/security-outbound/`                         | [security-outbound/](security-outbound/)                                                 |
| `.scratch/security-outbound-regression/`              | [security-outbound-regression/](security-outbound-regression/)                           |
| `.scratch/bootstrap-qualification-metadata.json`      | [bootstrap-qualification-metadata.json](bootstrap-qualification-metadata.json)           |
| `.scratch/security-outbound-metadata.json`            | [security-outbound-metadata.json](security-outbound-metadata.json)                       |
| `.scratch/security-outbound-regression-metadata.json` | [security-outbound-regression-metadata.json](security-outbound-regression-metadata.json) |

Every archived entry is under `.scratch/archive/2026-10-11/`.

## Historical paths and links

Commands, plain/backtick paths, test results, metadata contents, and links inside the moved evidence remain historical and were not rewritten. Historical relative links inside an archived entry may therefore require restoring that entry to its original path for exact resolution; do not interpret them as current executable instructions. Restore preserved evidence only, not the deleted compiled cache.

The cleanup scan found no Markdown hyperlink destinations outside the archive that pointed into these moved entries. No tracker or documentation link edits were necessary. Existing historical/plain-path mentions are intentionally unchanged.

## Removed cache and retained live state

Only `.scratch/merge-review-cfe06833/target/` was removed: 3,450 compiled-cache files, 1,332,971,803 logical bytes. Process cwd/executable/file-descriptor/path checks found no references before deletion; restricted process-inspection details are in the manifest. The repository's shared `target/` was not cleaned.

Active `.scratch/offline-first-nodes/` evidence, profiles and logs; `.scratch/worktree-cleanup/` preservation inventories; all four unfinished worktrees; sibling-repository symlinks and targets; and existing Git refs remain outside this archive and were not modified.
