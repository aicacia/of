# 04 — Initial setup secret inventory

Date: 2026-10-10.
Branch: `offline-first-setup-secret-inventory`.
Base: integration `4a8ad6edd82ca61eed4d715fbfab5e00f28eeb1c`, not `01e96b5`.
Scope: review source findings 1–4; owner/service seams and their tests only. Desktop, reset journal, endpoint, and relationship-credential implementation were not edited.

## Delivery and risk

High-risk recovery/security change, high priority: a false never-started or complete-cleanup claim can discard the only reference to private material. Complexity is bounded to one preparation manifest plus the existing durable per-slot reference mechanism. No dependencies, migration, legacy adaptation, namespace guessing, or plaintext private-key fallback were added. Historical version-1 references are deliberately refused, not upgraded.

This delivers the owner boundary, **not a working desktop caller integration or full ticket-04 qualification**. The unchanged desktop must adopt the contract below. Merely merging these files does not make its existing setup flow safe/usable: absent inventory now denies setup and reset at the owner seam.

## Source changes

- `DbClientRepo::create_client_with_capture` commits the actual internally generated Client ID and local verifier, then asks `KeyService::create_initial_key_with_capture` to create initial key metadata and call the capture callback **before any initial master/derived private write**. A refused capture propagates without private writes. Ordinary Client creation reuses the same implementation through a direct returned future (no extra async forwarding layer).
- The key service reports the actual metadata path and its entire ancestry, including the root. `PrivateKeyRepo::ensure_derivation_path` can independently store every intermediate path; recording only the leaf would not be complete.
- `OwnerProvisioner` captures the actual internal ID and all paths in its existing atomic reference mechanism before acknowledging capture. Publication uses exclusive temporary files, file sync, rename, directory/ancestor sync, and validated readback. Files contain identities/paths only, never private material.
- Initial User signing has a retained slot too. Missing key metadata after captured production refuses replacement provisioning; reset still deletes all retained paths independently of surviving key rows.
- `pending` is an unknown history, not authorization to resolve from a surviving row or re-register when a row disappeared. Resolved IDs must still match current rows on ordinary retry. Missing, malformed, old-format, or conflicting references fail closed and are not reconstructed from empty database queries.
- An exact `preparing` manifest names the initial User and the complete ordered Client set before per-slot publication. Secret-producing setup entrypoints are barred until all slots are durable and the manifest is `ready`. Missing slots can be completed only while `preparing`; after `ready`, missing slots deny retry/reset. Reset completes verified partial preparation through the same slot API without ordinary provisioning or cancellation of a reset journal.
- Pending/unknown records and preparation evidence are retained on failure. Reset validates every slot before deleting any entity credentials. Existing verified deletion/readback APIs are reused.

## Exact handoff to the parent / desktop owner

The parent must provide positive fresh-intent authorization. **Absence of a manifest, reference, Client row, key row, or an empty/openable database is never that authorization.** Do not expose the fresh initializer as an ordinary retry/recovery operation.

For a positively verified fresh create/join attempt, with the original persisted setup IDs and before initial owner-local private work:

```rust
idp.prepare_fresh_setup_secret_inventory(
    ids.administrator_id,
    &setup_client_ids(&ids),
).await?;
idp.prepare_setup_client_slots(&setup_client_ids(&ids)).await?;
```

Use the actual initial User ID passed to `ensure_initial_user_signing_key`/reset if its local variable is named differently. Both the User and ordered five-Client list must match on retry/reset. The initializer publishes only `preparing`; the second call publishes/validates all Client and User slots and then `ready`.

On continuation/reopen, call **only** `prepare_setup_client_slots` with the same exact list. An intact `preparing` manifest can complete partial publication. An absent/corrupt manifest or lost slot after `ready` must remain recovery-required; never call the fresh initializer because a current row is absent. The parent must preserve its verified fresh disposition across owner opening in the same attempt, and must not recreate it after global attempted history. An interruption before the preparation manifest is durable remains fail-closed, not newly certified recoverable.

In `apps/app/src-tauri/src/app.rs`, both the create owner opening and join bootstrap owner opening currently go straight to `prepare_setup_client_slots`. They need the positively-fresh-only initializer above before that call; normal retries keep only the existing preparation call. Join must initialize/finish before `prepare_node_signer` or any local Client/private-key production. Existing imported public metadata is not proof of local freshness.

In `provision_service_client`, replace:

```rust
idp.begin_client_provisioning(&client_id.to_string()).await?;
// existing relationship-secret acquisition
idp.ensure_infrastructure_client(request).await?;
idp.ensure_client_signing_key(&client_id.to_string()).await?;
```

with the existing relationship-secret acquisition and:

```rust
idp.ensure_setup_infrastructure_client(request).await?;
```

The new method owns the pending transition, exact existing-registration validation, internal capture, and signing-key readback. Do not call `begin_client_provisioning` separately first: a second begin correctly rejects unresolved pending history. Keep the existing request construction and exact relationship IDs; relationship-secret storage itself remains outside this ownership. The older generic infrastructure-registration API is not a setup inventory API and must not be used for these initial Clients. The existing `ensure_desktop_client`, `ensure_initial_user_signing_key`, and `prepare_node_signer` now require the prepared inventory.

Preserve `services/idp/setup-secret-inventory.json` and `services/idp/local-client-key-references/` through secret cleanup failures (relative to the actual configured IdP owner directory). If reset recovery reconstructs owner references, it must retain/recover this exact manifest and version-2 User/Client inventory, not synthesize never-started records or translate legacy histories. Existing owner-directory deletion removes these files only after successful secret cleanup. No desktop/reset files were edited here.

## Regression evidence (red → green)

Before production edits, `RUST_MIN_STACK=16777216 cargo test -p idp-server --no-default-features --lib inventory_ --target-dir .../setup-secret-inventory/target-secret-inventory -j 2` ran four tests; **all four failed** at the asserted defect:

1. `inventory_captures_client_identity_and_paths_before_first_private_write`: first private-store refusal left `pending`, not a captured internal ID/path list.
2. `inventory_pending_unknown_retry_is_denied`: retry succeeded and registered a replacement instead of denying unknown pending history.
3. `inventory_user_cleanup_survives_lost_key_metadata`: cleanup succeeded while derived User credentials survived.
4. `inventory_partial_slot_preparation_can_reset`: reset failed on a missing slot after interrupted preparation.

Green fixtures explicitly invoke the new positively-fresh initializer. The tests additionally exercise missing references after ready, refusal to replace the manifest, native reopen denial, missing User metadata refusing new private paths, and native reopen/reset of partial preparation while Node/Client private work is barred.

`initial_capture_denial_prevents_all_private_writes` tests the actual Client-repository callback for public and confidential Clients: it observes the actual internal ID, leaf-to-root ancestry, and an empty private store at capture, refuses capture, and verifies no root/intermediate/leaf credential was written.

Focused validation:

- Server `node_provisioning_tests`: **10 passed, 1 ignored** (real OS provider qualification intentionally not run).
- Service `replica::client_repo::tests`: **5 passed**.
- `cargo check -p idp-service --no-default-features`: passed; existing unused-import warnings in `oauth2/authorization.rs` and `oauth2/scope.rs` were not edited.
- `cargo clippy -p idp-server --no-default-features --lib`: passed.
- Owned-file rustfmt and `git diff --check`: passed.

All cargo commands used only the branch-local `target-secret-inventory`, two jobs, and explicit bounded timeouts. Initial compilation needed repeated bounded runs (120s/600s limits). The initial default-stack test run aborted with stack overflow; subsequent runtime tests used a 16 MiB test-thread stack. A service compilation recursion-limit failure was traced to the added async forwarding layer and fixed by returning the existing future directly, with no recursion-limit attribute or unrelated test edits.

No CRAP, cargo-hack, desktop build, endpoint/reset suite, every-write process-kill matrix, real OS-provider, or power-loss qualification was run. These tests do not establish universal recovery of historical lost inventories, every subsequent runtime key, or unrelated endpoint/import histories.

## Finish

Integration is merged into the branch before handoff (integration remains the base at the time of validation). Only the owned source/test files and this evidence are committed, with Git hooks disabled. The exclusively used branch-local build target is verified and removed before handoff; shared/root targets are untouched.
