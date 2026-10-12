# Independent completion review

Reviewed exact commits `9e0d7e52b04e0790db0945a16849e4ad7adebff6` (execution) and `f2f2b90c3698543c4807def9613dadc45d332151` (setup), each based on `8ddf6a307c116301099073f58f952acf3ab78020`. Read spec, both completion READMEs, actual 03/04 checkbox criteria, all commit diffs and relevant callers. Loaded global change-review and relevant Ponytail/Svelte skills. No subagent tool was available; review performed directly.

**Merge blocked by a reproduced setup reset recovery bug.** Integration remains `8ddf6a307c116301099073f58f952acf3ab78020`. Neither commit merged into integration. Isolated detached review worktree `.worktrees/review-completion` combined both commits with hooks disabled, final review HEAD `162e76873845a16189ff9ca68b49216630107aa5`. This is not integration HEAD.

## Blocker

`apps/app/src-tauri/src/app.rs:1194-1196` removes `node-setup.json` before `setup-ids.json` and `reset-pending`. Reset retry at lines 1109-1118 requires the issuer from `read_setup_intent` whenever setup IDs remain. A crash after the journal unlink, or failure on the subsequent ID unlink, leaves valid IDs and pending reset but no issuer; subsequent reset always fails with NotFound before reaching remaining cleanup. This is not user corruption: production reset generates the unrecoverable state itself. The initial setup also writes IDs before intent (lines 152-157, and join), so interruption there requires deliberate safe handling rather than treating every missing intent as irrecoverable corruption.

Reproduction: `review-reset.rs` extracts the exact `remove_local_reset_data` function from the combined production source. A filesystem shim injects failure at setup-ID removal, after issuer deletion. The retained IDs/pending marker assertions pass; the assertion that issuer survives for retry fails with NotFound. See `review-reset.log`: 0 passed, 1 failed. This is a deterministic production cleanup-order harness, not a real GUI/process-kill test or a full Tauri reset invocation.

Fix: retain a durable reset record containing all secret references and canonical issuer until secret deletion and data cleanup are durably complete; make post-secret-cleanup retry independent of files already removed. Merely swapping the two unlinks risks losing the secret references after crash/reordering and is not proof of durable reset. Add interruption coverage at every cleanup unlink, journal boundary and the IDs-before-intent boundary. Do not skip unknown secure-store deletion or infer namespaces from arbitrary live URLs.

## Execution and trust conclusions

- Socket access carries the verified subject/Application. The initial namespace is pinned and compared both before execution and before response handoff. The actual overlapping-resource-ID namespace regression passes. Existing socket cannot silently rebind; fresh authorization can open the new namespace. No new bypass found in this change.
- Filesystem `accept_stream` awaits the session in DATA's existing JoinSet child instead of spawning an escaped task. Actual production admitted-session parent cancellation releases the retained evaluator, preserves source content and denies later handle writes. Regression passes.
- Public-bootstrap driver checks durable IdP and Management imports, exact current local Device/member/public signer, active owner, exact local context grants and independent private signer. Completed offline retry/native reopen and learned local revocation are exercised. Receipt-only fixture still denies ordinary DATA and does not establish local signer trust. PublicReady is not Storage readiness, resource selection or a resource grant. Desktop completion subsequently requires composed local contexts and HTTPS checks; listener liveness is not selected-resource authorization.
- Relationship credential write/readback and private-signer readback fail closed; ineffective private deletion is rejected before losing key metadata. No plaintext fallback, raw bearer persistence or remote owner's private-key reset introduced.

## Independent focused validation

All Cargo test commands ran in `/home/nathan/code/rust/aicacia/of/.worktrees/review-completion`, offline and locked, using:

```sh
CARGO_TARGET_DIR=/home/nathan/code/rust/aicacia/of/.worktrees/review-completion/target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=1 RUST_MIN_STACK=67108864
```

Exact commands following that prefix:

```sh
cargo test -p unified-server -p storage-server --lib --no-default-features --features storage-server/network --offline --locked native_socket_response_binds_namespace_even_when_resource_id_exists_in_new_application -- --nocapture --test-threads=1
cargo test -p storage-server --lib --no-default-features --features network --offline --locked real_selected_filesystem_parent_cancellation_releases_admitted_session -- --nocapture --test-threads=1
cargo test -p unified-server --lib --no-default-features --offline --locked desktop_bootstrap_orchestration_completes_both_public_contexts_and_retries_offline -- --nocapture --test-threads=1
cargo test -p lidp --lib --offline --locked app::tests -- --nocapture --test-threads=1
cargo test -p lidp --lib --offline --locked service_secrets::tests -- --nocapture --test-threads=1
cargo test -p idp-server --lib --no-default-features --offline --locked node_provisioning_tests -- --nocapture --test-threads=1
```

| Focus | Result |
| --- | --- |
| Native socket namespace | 1 passed, 37.35s; storage package filter matched zero tests, not a storage-suite pass |
| Production filesystem parent cancellation | 1 passed, 60.17s |
| Both-context bootstrap/offline retry/native reopen/revocation | 1 passed, 208.74s |
| Desktop app setup/reset/status tests | 12 passed, 0.04s |
| Service credential tests | 6 passed, 1 real-OS test ignored |
| Native provisioning/readback/deletion tests | 2 passed, 1 real-OS test ignored, 16.39s |
| Added cleanup-order harness | Expected regression failure: 0 passed, 1 failed |

First cold socket and desktop compilations each exceeded 240s; resumed focused commands passed. Original cold logs remain in the isolated worktree (`review-socket.log`, `review-desktop.log`). No cold timeout is presented as a test pass. Real OS tests were reviewed from supplied evidence, not independently rerun; no GUI/process/platform acceptance was run.

Svelte autofixer ran on changed installation component and setup state via `node /home/nathan/.npm/_npx/0ff2b174d795ade9/node_modules/@sveltejs/mcp/dist/index.mjs svelte-autofixer <path>`: no issues/suggestions. `git diff 8ddf6a307c116301099073f58f952acf3ab78020 HEAD --check` passed. `python3 scripts/check_server_dependencies.py` passed. No full tests, cargo-hack, CRAP, owner sweeps, dependency installation or frontend full rerun.

## Closure and exact remaining work

**03 can be closed against its actual eight listed criteria after accepting/merging execution commit.** The supplied native SQL/KV gates, earlier KV commit observation, both independent identities/selections, current execution checks, admitted completion, reconnect and owner-hook evidence satisfy those criteria; independent socket/FS regressions reinforce the two new production fixes. No new execution blocker found. The additional deterministic same-issued-token expiry crossing remains unqualified (native verifier uses wall clock), but expiry interleaving is not an explicit 03 checkbox. Do not invent 08, ofdb06 or offs03 reverse blockers. This review does not edit or resolve the tracker, and current integration does not yet contain the fixes.

**04 cannot be closed.** Beyond the new reset blocker, the delivery has these concrete remaining items:

1. Expose pending authenticated PairingOffers and authorized equal-Node approval through the existing composed UnifiedRuntime/IdpRuntime/shared endpoint, and wire source desktop display/approval; present Device-only UI is insufficient. Do not open competing stores/endpoints or approve copied JSON.
2. Delegate live current joined readiness through the composed runtime; `get_setup_stage` currently uses runtime presence/base URL and completion markers, not dynamic local trust/grant checks. Keep status separate from Storage/resource authorization.
3. Qualify fresh driver pairing-send path and every owner/import/journal/secure-store interruption, including real process kill, partial rows/multiple batches and receiver mid-frame learned denial. Supplied driver fixture begins with a persisted receipt.
4. Fix inherited `idp-service/src/repo/private_key_keyring_repo.rs:89-95` initialization flag poisoning after first provider failure; only publish initialized state after successful setup and preserve retry/concurrency correctness, without fallback. No owner edit made here.
5. Provide explicit secure-reference recovery for genuine corrupt/missing journals and authenticated revocation propagation when possible after local reset; no persisted raw bearer substitute.
6. Finish direct-IdP frontend/client cutover for actual missing `grpcClient`/`lidpManagementClient.svelte` imports and stale identity-management calls (06); incorporate 05 transfer cleanup/reset gating and owner-backed selections/Full-Passthrough UI.
7. Then run genuine two-profile desktop create/join/denied-forged approval/pairing-isolation/cancel/retry/allowlist-update/disconnection/restart/reset/provider-failure/Residency acceptance. Existing real OS keyring evidence does not cover that GUI/process matrix or Windows/platform qualification.

## Safety and cleanup

No production source edits, owner writes, user-artifact deletions or shared tracker mutations. Only new review evidence/artifacts were written. Original root status remains its initial `?? .worktrees/`; both owner worktrees remain clean and their targets absent.

Before cleaning, Cargo metadata verified exact review target/build directory, non-symlink path and current-user executables/command lines. Initial /proc checks safely stopped on inaccessible user daemons; corrected check identified systemd/sd-pam/gpg-agent, none under target. `cargo clean --offline --target-dir /home/nathan/code/rust/aicacia/of/.worktrees/review-completion/target` removed 8179 files / 3.4 GiB; target verified absent. No shared/owner target cleaned. Detached review worktree and evidence retained; integration unchanged due to blocker.
