# Native recovery checkpoint — 2026-10-11

Branch: `offline-first-nodes-integration`, parent `c095f724783084b0ac87d6ad346f3d93108dffe3`.

User-directed disposition: stop prolonged native verification, record its limits, commit/clean up before starting subsequent issues. Ticket 04 remains claimed/incomplete; criteria 6–9 remain unchecked. Scoped subsequent work is authorized, not a claim that its unresolved dependency is accepted.

## Fixes in this checkpoint

- Native return targets use pathname/search/hash, not slicing an opaque `tauri://` origin; malformed/external persisted targets are discarded.
- Devices refreshes do not overlap; existing periodic refresh skips active Node actions.
- Prepared joins admit only purpose-specific pairing with the pinned approving peer and validated retained request, issuer, local endpoint and matching private/public signer. Bootstrap still requires matching verified approval. Ordinary protocols and unrelated peers gain no exception.
- Session clearing does not construct an OIDC client when an incomplete Node lacks an authority. Existing memory tokens/PKCE and native persistent caches are cleared, cached desktop client identity is invalidated, and real clearing/reset failures remain visible. Reset, sign-out and authentication denial use the shared lifecycle seam.
- Temporary Rust token/IPC diagnostic traces are removed.

Complexity: small redirect/session branches and a protocol-scoped admission change. Risk: security-sensitive redirects, session disposal and endpoint admission. Priority: observed native sign-in/reset/pairing blockers. Independent source reviews found no concrete blockers.

## Focused validation

Executed after final source review:

```sh
# of/apps/app
../../packages/idp-client/node_modules/.bin/vitest run --config vitest.auth.config.ts
# 45 passed

# of/packages/svelte-headless
pnpm exec vitest run src/lib/state/createReturnTo.test.ts
# 7 passed
```

Earlier in this recovery, explicitly executed real OS-keyring endpoint tests (not default ignored-test discovery):

```sh
RUST_MIN_STACK=134217728 CARGO_BUILD_JOBS=1 cargo test -p idp-server --lib node_join::transport::tests::prepared_join_can_send_pairing_without_global_pairing_or_peer_trust -- --ignored --exact --test-threads=1
# 1 passed
RUST_MIN_STACK=134217728 CARGO_BUILD_JOBS=1 cargo test -p idp-server --lib node_join::transport::tests:: -- --ignored --test-threads=1
# 3 passed
```

Svelte autofixer passed on modified components/modules. Bounded `pnpm build` passed. Final native A/B builds passed in 3m58/1m43 using `cargo build --offline --locked -p lidp --features tauri/custom-protocol`, one Cargo job, existing `target-native-acceptance`, incremental/debug information off and 128MiB Rust stack. B preserved identifier `com.aicacia.local.native-acceptance-b`. Builds used systemd memory6GiB/tasks512/CPU200% and unchanged240s timeout. Earlier A7 build timed out at240s; same-bound cached retry passed. No full Cargo hack, CRAP or cross-workspace validation.

## Real native results and deferred limitation

Observed: current live IdP wrong-password denial and actual-password HTTP200; repeated native administrator Dashboard; explicit isolated A/B UI RESET exit0; A enables joining; exact B join fields submit; A displays B's authenticated incoming offer and independent public signer.

**Not observed:** verified authorized GUI approval, B bootstrap/Device completion or the requested two-profile offline restart. Native confirmation handling failed. Temporary empty accessibility trees produced false approval-success labels, expressly invalidated in `run21-result.md`. B reported `closed by peer: endpoint is not allowlisted (code 256)`; without verified approval this cannot be classified as a post-approved regression. Historical user-not-found precise cause remains unproven; current live account lookup/issuance succeeds.

Interruption/provider-failure/Residency/platform matrices remain unqualified. Pairing/offer display is not approval, resource access or readiness. No acceptance checkbox is promoted by this checkpoint.

## Preservation and cleanup

All acceptance processes stopped. A's random password existed only in terminated harness memory; a future credentialed retry requires explicit isolated UI reset. B retains incomplete pinned state and must not be silently repointed. Profiles, keyrings and historical observations are preserved. Existing storage-client generated output/shim changes are excluded from this commit.

Cleanup removes only verified clean, fully integrated worktrees with no ignored artifacts. Dirty/unmerged worktrees, ignored evidence, profiles and the pre-existing shared native build target remain. No next-ticket implementation started.

Detailed local tracker/evidence remains under `.scratch/offline-first-nodes/`: issue04 Comments, map current checkpoint, `recovery-status.md`, `reset-diagnosis-20.md` and `run21-result.md`. This tracked checkpoint deliberately includes no passwords, bearers, private key material or profile contents.
