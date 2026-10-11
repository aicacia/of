# Ticket 07: same-Node recovery assessment and deployment availability

Date: 2026-10-11. Branch: `offline-first-node07-recovery`.
Worktree: `of/.worktrees/node07-recovery`.
Base: integration `80a050a96c4666166b4b1f2092e6af06a5d412e5`.
Disposition: **documentation/source assessment and read-only tool availability only; no actual recovery qualification. Ticket 07 remains incomplete.** No tracker/map changes.

## Scope and CRP

Read ticket 07, `docs/operations.md`, prior `07-deployment.md` and `evidence07-rotation.md`, shared glossary, current CLI/config/local provisioner/endpoint code, owner signer verification and private/raw keyring repositories. Read desktop `service_secrets.rs` only to identify its distinct protected-reference contract; no desktop Rust writes. Invoked `ponytail`. No code/test/script added, so no TDD cycle or behavioral red/green is claimed.

Complexity: low for these two documentation files; moderate for a future stopped-store restore test, high for consistent platform/provider-loss recovery. Risk: high (identity loss/cloning, protected references, stale authorization rollback and multi-context consistency). Priority: establish the smallest truthful recovery gate and its blockers before any deployment claim. No numerical CRAP/coverage claim or CRAP/full Cargo hack execution.

## Source findings, not executed recovery

- `cli.rs::run` calls public `LocalProvisioner::open_runtime` for ordinary serving. There are only provision/serve (plus optional completions) commands, not a backup/restore command.
- A present provisioning directory is authoritative. Completed `build_runtime` requires the configured roots, IdP/Management databases, protected endpoint key and Storage subroots; compares persisted endpoint/public signer; verifies each current infrastructure Client; then requires `node_public_ready`. Completed startup does not replay setup. A missing journal selects a different explicitly retained-host path, not permission to discard one during restore.
- `OwnerProvisioner::verify_node_signer` calls the existing local `KeyService::load_node_signer` path. Use this public trust/signing check, not private-key extraction, fresh signer production or prepared-signer inventory writes. Owner opening/runtime can write database state; existing-only means no identity/credential repair, not universal filesystem immutability.
- `PrivateKeyKeyringRepo` uses the Canonical Issuer as keyring service, plus configured key namespace and derivation path as entry name, with the IdP target modifier. Linux default uses D-Bus Secret Service; headless keyutils is not assumed persistent. The repository has load/store/delete, not a complete same-Node platform backup procedure. This audit does not establish that provider-loss recovery is impossible; it remains unqualified.
- The CLI requires the four named `UNIFIED_*_CLIENT_SECRET` environment injections. Desktop separately uses `local.unified-service-credentials`, Installation ID, Client ID and one of four relationship key names through `RawKeyringRepo`. Its missing-retained-secret path refuses unauthorized replacement. Preserve these bindings/provider entries; mounting a secret file does not implement CLI injection. The desktop OS-provider tests explicitly mutate/delete entries and were not run.
- `local_provisioning_creates_exact_host_and_reopens_offline` provisions isolated stores, exercises authenticated IdP/Management calls, reopens unchanged state and checks endpoint/provider/journal retention. It then checks missing endpoint denial. Rotation tests restore isolated endpoint bytes; lost-Storage control renames a retained tree back. None snapshots/restores all contexts, journal/references, endpoint and protected signing capability as one recovery gate. Their historical passes are not new recovery acceptance.

## Smallest safe candidate using existing APIs (not implemented or run)

Use a dedicated isolated current-format fixture and the public CLI startup decision. No backup product abstraction, new owner seam, dependency or production repair path is needed for this narrow candidate. Keep the same paths and one Node identity throughout; the journal embeds normalized absolute roots.

1. Explicitly provision the isolated Node once using existing public APIs. Establish current readiness and public endpoint/signer identity. Populate meaningful Storage SQL/KV/filesystem content through existing public APIs if claiming content recovery; an empty Storage tree proves at most startup structure. Retain all four relationship IDs/credentials and the same provider-held private material.
2. Shut down the runtime, join its serving task, drop every owner/database handle and provisioner guard before capture. Verify exclusion from any competing host. Universal detached-task shutdown remains a separate 07 gap; do not copy an actively held database or call a live file copy crash-consistent.
3. Capture a protected, stopped, same-format filesystem snapshot of the **whole** IdP, Management, Storage and endpoint roots and the endpoint-adjacent provisioning directory. Include `setup-secret-inventory.json`, `local-client-key-references`, owner lock files and every Storage subtree, not just database filenames or directory markers. Preserve configuration/root mapping, ownership, modes and public identity evidence. Snapshot storage must be outside managed roots, operator-only and local to this isolated Node. Never dump endpoint bytes, signer, credentials or bearer bodies into assertions/logs.
4. Retain the original provider and its exact protected references in place. Do not export/import/clone the private signer or mutate a real OS provider. Preserve the provisioning `operation.lock` inode in place: restoration must not replace/unlink it. Take no intervening domain/credential/revocation changes, so this test does not silently qualify stale-snapshot rollback.
5. In only the disposable filesystem fixture, displace the context/endpoint data to demonstrate missing-state existing-only denial with no newly generated identity/roots. Restore the captured trees to their exact original paths with protected permissions; retain the authoritative journal and lock. A second live Node or relocated roots are not equivalent. Preserve invalid material for diagnosis rather than manufacturing freshness.
6. Reopen through `LocalProvisioner::open_runtime`, compare public endpoint and trusted signer via `UnifiedEndpoint::persisted_endpoint_id`/`OwnerProvisioner::verify_node_signer`, and require current `node_public_ready`. Make real authenticated calls exercising IdP issuance, Management permission decisions and consuming Storage APIs/content. Verify retained trusted endpoint membership through the existing owner boundary. No central authorization/peer setup is involved; an actually network-isolated execution is a separate observation to record, not inferred from the word offline.
7. Shutdown/reopen once more; check journal, owner references/inventory and provider identity/material unchanged using secret-safe boolean comparisons, not operand-dumping assertions. Include a missing/corrupt endpoint or incomplete/invalid journal refusal control. No setup replay, reset, migration, permission widening or fresh fallback.

This would qualify **stopped filesystem restore with the original provider retained**, not backup/recovery of a lost provider, actual OS-process/unattended restart, Windows ACLs, crash/torn snapshots, stale authorization reconciliation or all desktop state. Full provider-loss recovery requires an approved same-Node platform procedure; do not assume copying the data parent includes it. This is a test design, not an operator-executable restore recipe.

## Concrete execution blockers / why no new fixture

No Rust build slot is authorized. The existing artifact tests do not contain a complete restore cycle, so re-running them cannot answer the recovery question. Implementing a new Rust fixture without compiling/executing it would not produce proven recovery work. A stdlib archive/copy fixture only qualifies file handling, not current owner trust or signer usability; no such surrogate script was added. No live profile or provider mutation is authorized, and no operator recovery profile was selected. Source traces show a viable narrow seam, not an API impossibility.

Next bounded prerequisite: coordinator authorizes a serial memory-limited Rust slot for a dedicated isolated recovery test and agrees whether acceptance is retained-provider filesystem recovery or actual provider-loss recovery. The latter also needs a reviewed platform-specific procedure and separate explicit authorization; this session did not query any actual credentials.

## Actual lightweight checks

Executed in the new worktree unless stated otherwise; commands bounded to 10 seconds, no build/pull/run.

- Root read-only status/log/worktree checks confirmed integration `80a050a` and the ten pre-existing Storage output/shim changes. Created this worktree/branch from that integration using `git -c core.hooksPath=/dev/null worktree add -b offline-first-node07-recovery .worktrees/node07-recovery offline-first-nodes-integration`. Root worktree and other worktrees were not edited.
- `command -v docker podman rustc cargo pkg-config dbus-send secret-tool openssl systemd-run` availability was checked with separate `command -v` invocations: all found except podman. Tool presence does not imply runtime qualification.
- `docker --version`: Docker 24.0.5, build ced0996. `docker info --format {{.ServerVersion}}`: 24.0.5, exit 0. This establishes current daemon access only; no image inventory/pull/build/run or registry tag check.
- `rustc --version`: `rustc 1.99.0 (b940084d7 2026-09-28)`; `python3 --version`: 3.12.3; `pkg-config --modversion dbus-1`: 1.14.10; `openssl version`: OpenSSL 3.0.13 (30 Jan 2024). Local Rust is not evidence that `rust:1.99-trixie` exists or that dependencies/linkage work.
- `df -h .`: 937G total, 493G used, 397G available. `free -m`: 31440 MiB total, 25878 used, 594 free, 5561 available; all 2047 MiB swap used. Point-in-time availability is not build permission. No disk/cache pruning or cleanup.
- Read-only session bus check below: address configured true, ListNames exit 0, Secret Service already registered true. Only the bus daemon was called; no provider activation, key lookup, collection inspection, unlock or mutation. Registered service presence does not establish authorized/unlocked/unattended access, persistence or post-logout/reboot recovery.
- `python3 -B scripts/test_container.py`: **exit 0, 3 tests passed, 0.013s**. Existing recipe/static-context checks only, no actual Docker filtering or built image execution.
- `git --no-pager diff --check`: exit 0 after operations edit. Final whitespace/scope/link checks and commit/integration disposition recorded below.

Exact read-only bus check (captured output is not printed; only booleans/status):

```python
import os
import subprocess
print("Session bus address configured:", bool(os.environ.get("DBUS_SESSION_BUS_ADDRESS")))
r = subprocess.run([
    "dbus-send", "--session", "--print-reply", "--reply-timeout=2000",
    "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus",
    "org.freedesktop.DBus.ListNames",
], capture_output=True, text=True, timeout=4)
print("Session bus ListNames exit:", r.returncode)
print("Secret Service already registered:", chr(34) + "org.freedesktop.secrets" + chr(34) in r.stdout)
```

No Rust build/test/Cargo metadata/Clippy/full hack/CRAP, Docker build/pull/run, GUI, TLS/proxy request, OS-provider mutation/profile reset, credential printing, sibling-repository write, push or root merge. No claim about Rust image tag availability, unattended providers or actual recovery passes. Tools required for a prospective local native/image attempt are present; deployment remains unqualified.

## Delivery

Only `docs/operations.md` and this dedicated evidence file are changed. Tracker/map, desktop/runtime Rust, scripts/tests, Cargo manifests/lockfiles and deployment recipe remain unchanged. Commit hooks are disabled to prevent implicit forbidden builds. The final branch tip, checks and merge of the then-current integration tip into this branch (not into root) are reported in the delivery response.

Final precommit checks: `python3 -B scripts/test_container.py` passed again (3 tests, 0.012s); Python stdlib checks confirmed the new operations recovery link resolves and the evidence explicitly labels no code/no recovery qualification/07 incomplete. `git --no-pager diff --cached --check` passed; staged name/scope check showed exactly the two allowed documentation paths. These are static/documentation checks, not recovery tests.
