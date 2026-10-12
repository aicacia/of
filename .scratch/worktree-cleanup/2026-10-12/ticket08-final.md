# Ticket08 final delivery cleanup — 2026-10-12

## Scope and merged sources

Authorized housekeeping **after** the qualified consumer and owner merges. No source edits, new runtime qualification, tests/builds, push, explicit prune, reset, cache cleanup, provider/profile/CA operation or shared-dependency deletion. Complexity is low; loss/disclosure risk is high, so verified local recovery preceded non-forced retirement.

- Consumer `of/main`, `offline-first-nodes-integration` and retired `offline-first-ticket08-full-nodes` all started clean at **`e2705f70a7606ef3e370e62b326d4038507109e4`**.
- Owner `ofdb/main` and retired `integration/native-catalog-reuse` both started clean at **`5b08d0ddc6e2c19a8be29af13fe5af6133b791a6`**; implementation source **`72aae34b75f0fd65f4feadfb49e13ae948b41f6c`**.
- Consumer runtime **`d9e40eb4e903f8e073e3a8c35fd879b6e1ad3806`**, cleanup **`ba7cfc2d6b75fbfe9f71b8cfc93137fd85345101`**, final assertion source **`6341cf1ec353dd4d73f93dd8879678f439af1978`** remain unchanged in history. [Remaining-work source/command receipts](../../offline-first-nodes/remaining-work.md#exact-qualifying-source-and-command-receipts) retain qualification and failure attribution.

Both retired branches were confirmed by `git branch --merged main` and `git merge-base --is-ancestor <branch> main` (exit 0). No diagnostic history was newly accepted by this cleanup.

## Exact recovery location and verification

Source filesystem: **`/home/nathan/code/rust/aicacia/of/.worktrees/ticket08-full-nodes`**.

Local recovery directory: **`/home/nathan/code/rust/aicacia/of/.scratch/worktree-cleanup/2026-10-12/preserved`** (ignored; not staged).

- [Full inventory/verification manifest](preserved/ticket08-final-manifest.json) records every path, regular-file SHA256/size/mode, symlink target/mode, directories, tracked/ignored/untracked classification, exact initial heads/refs/stashes/status/worktrees and protected-path metadata.
- Full filesystem tar: **986 regular files, 5 symlinks, 187 directories**, 1,178 archive members. All **867 tracked + 124 ignored** file/symlink entries are present; **0 nonignored untracked** entries. Git's ignored inventory includes evidence/argv/status/log artifacts and local generated/dependency artifacts.
- Only the root **`.git` pointer** was excluded. No symlink was dereferenced, no shared target or sibling dependency contents were copied, and no special filesystem entries were encountered.
- Complete-history Git bundle includes `refs/heads/main`, `refs/heads/offline-first-ticket08-full-nodes` and `refs/heads/offline-first-nodes-integration`, each at `e2705f70a7606ef3e370e62b326d4038507109e4`. `git bundle verify` passed twice; no prerequisite commits are required.
- Archive member set, regular-file SHA256/size/mode and symlink identity/mode were compared with source. Full source inventories before/after archive and immediately before removal matched. Final pre-removal archive hashes, Git state/stashes and protected metadata also matched.
- Raw `.json` argv/source metadata, `.status` and `.log` contents were preserved byte-for-byte, including historical failures. Their exact path-to-hash mapping is in the manifest; cleanup does not rewrite exits or certify prior runs.

### Archive files and SHA256

All filenames below are relative to `preserved/`.

| File                                |    Bytes | SHA256                                                             |
| ----------------------------------- | -------: | ------------------------------------------------------------------ |
| `ticket08-final.tar`                | 32040960 | `45014bafe27adefc327f9978fe3ac118b53d7c0ba01d1c99285b133f6152837c` |
| `ticket08-final.bundle`             |  3601669 | `5585e71006c29ef15c11b80431281a280a7a9880a99078f19238789bafb932d1` |
| `ticket08-final-status.txt`         |        0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `ticket08-final-status-ignored.txt` |     9694 | `1b3c7f925da3c7df7e2096ce9616b66219b6b79f22987fc6e7ca87c778ed6622` |
| `ticket08-final-untracked.nul`      |        0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `ticket08-final-ignored.nul`        |     9322 | `3e0bc0e5f2547d240bd71128e6cee3b4b5999add467de82bc5e2b26b4555e120` |
| `ticket08-final-tracked.nul`        |    40464 | `03c2bb4c56a5cebf1b952f4251ab4a313f9af898129a35840c128630b82bf8f6` |

Manifest SHA256: **`2f399466348782c59b79c4f7a88bc9ba38813967a8e99748f819566b1ac06a7e`**.

[Post-retirement, pre-documentation status receipt](preserved/ticket08-final-retirement.json) SHA256: **`8dca31c7dbd644da4602729eca82c1da4928c00d090337ce0e4089df5478c9eb`**. This immutable phase receipt distinguishes retirement state from the subsequent documentation commit. The local `ticket08-final-archive.py` is the stdlib preservation/verification helper, not delivered application source.

**Sensitive recovery only:** archives may contain secrets, fixture runtime data and historical diagnostic output. Owner-linked raw artifacts are not certified public either. No public-safe certification or permission to publish `preserved/` wholesale is implied. New preservation artifacts were created with owner-only permissions; prior archives were not rewritten.

## Retirement and final status

Executed successfully, without force:

```text
git worktree remove .worktrees/ticket08-full-nodes
git branch -d offline-first-ticket08-full-nodes
# In ofdb, after merged/ancestor checks:
git branch -d integration/native-catalog-reuse
```

No diagnostics worktree existed; none was removed. No owner-linked scratch tracker folders were deleted.

Post-retirement, before this docs-only commit:

| Root    | Main HEAD                                  | Porcelain status | Worktrees           |
| ------- | ------------------------------------------ | ---------------- | ------------------- |
| `of`    | `e2705f70a7606ef3e370e62b326d4038507109e4` | empty            | root on `main` only |
| `ofdb`  | `5b08d0ddc6e2c19a8be29af13fe5af6133b791a6` | empty            | root on `main` only |
| `offs`  | `de75aea778f892248d8ab3a4c6a01361999f8dd8` | empty            | root on `main` only |
| `ofnet` | `85632a965a07ab4f3ee1e7654cb762c061afe8d2` | empty            | root on `main` only |

For each root, exact `git status --porcelain=v1 --untracked-files=all` output was empty; SHA256 **`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`**. The documentation delivery advances only `of/main`; `offline-first-nodes-integration` is retained and fast-forwarded to that same cleanup commit. Identify its exact hash through `git log -1 --format=%H -- .scratch/worktree-cleanup/2026-10-12/ticket08-final.md`; the post-commit local `preserved/ticket08-final-delivery.json` records exact final heads/status hashes/worktrees and refs.

## Preserved recovery and shared state

- `of/cleanup-review-completion-2026-10-11`: **`162e76873845a16189ff9ca68b49216630107aa5`**.
- `of/offline-first-auth-unavailability`: **`0716062a8e7623659cc2996e195b6c278f964352`**.
- `of/offline-first-bounded04-partial-bootstrap`: **`c4ef122f67d1f00e020df858872b3b1850abf41e`**.
- `ofdb/diagnostics/native-idp-stage-timing`: **`3ec105590794331d62f67f33ccc4a7f56e623351`**, unchanged and retained. Contrary to the requested “not merged” description, observed Git ancestry places this tip in current main already (`merge-base --is-ancestor` exit 0, `main..diagnostics/native-idp-stage-timing` empty). This does not qualify obsolete instrumentation or authorize ref deletion.
- All old archive files and patches remain at their original locations. Their device/inode/mode/size/mtime signatures were unchanged after retirement. The shared `of/target` directory identity/metadata and `.worktrees/{ofdb,offs,ofnet}` symlink identities/targets were likewise unchanged. Removal was scoped to the archived ticket worktree; no external symlink destinations, root dependency installs, provider stores or private runtime state were deleted.
- All five `of` stash entries, in order, remain **`21edf8364e9eef1704f2c6a108ead6f08dfb79a2`**, **`dc4d1b4e72587a5b3a0bf63dd167d10bb85151e1`**, **`75f2975f57c77756532024cca71de33afdeda49e`**, **`23d034730a9ff0bd467092da1cc266eb3c758a2b`**, **`d9059db1b41fbdc7822ef7cfd5dad6084b84fca0`**. Stash messages and ordered commit IDs match the initial manifest.
- `offs` stash **`6bd5717e59c588b21b179b1bbc6122a91fad3633`** remains unchanged; `ofdb`/`ofnet` have no stashes. Remote refs remain unchanged.

## Recovery and limits

Use the bundle or surviving main history to create a checkout at the source tip, then inspect/extract the tar there without overwriting `.git`. Symlink targets may depend on a particular workspace layout; inspect before use. The manifest identifies every archived artifact without requiring a live retired checkout. Owner evidence under sibling `ofdb/.scratch/` remains at its existing location.

Only this receipt and the current [remaining-work pointer](../../offline-first-nodes/remaining-work.md) are committed. No raw archive, manifest, fixture, local helper or unqualified source is staged. Validation is limited to ancestry, exact archive/source verification, ref/stash/protected-path comparisons, branch/worktree inventories, clean statuses and documentation whitespace. No tests/builds, Cargo Hack/CRAP, push, explicit prune, reset or provider/cache operations were run.

Git unexpectedly announced automatic background packing during the initial documentation commit and integration fast-forward. No housekeeping/prune command was explicitly invoked; whether internal automatic GC performed pruning is not certified. Subsequent Git writes disable automatic housekeeping per invocation (`-c gc.auto=0`). Final delivery verification checks all preserved refs/stashes and archive hashes again; the packing message is not hidden as a clean no-housekeeping claim.
