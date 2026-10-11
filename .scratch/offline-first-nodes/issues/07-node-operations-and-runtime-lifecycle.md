# 07 Node operations, secure credentials, and runtime lifecycle

Status: ready-for-agent
Type: task
Work status: open
Blocked by: 01, 02, 04

## What to build

Verify full-Node deployment, desktop listener/endpoint lifecycle, client rotation/revocation and current-format local backup/recovery, then publish tested guidance in `docs/operations.md`. Question: does recovery restore usable local trust without central authority contact or copying a private signer to another Node?

## Scope and acceptance criteria

- [ ] One Node host composes one shared `iroh-chain` endpoint/router, persisted endpoint key/identity and local trusted membership, with identity/bootstrap and Storage protocol adapters. Reuse `ofnet` endpoint/mesh/pairing/allowlist/generic connection-routing mechanics; `of` supplies Installation/Device trust, local authorization and protocol-specific wiring. No injected context creates/closes a second endpoint; Storage denial does not erase separately permitted join/identity admission. Audit current router helpers before assuming arbitrary handler registration. Background work starts after local readiness; shutdown joins tasks and closes once.
- [ ] Load persisted locally trusted approved/non-revoked Device endpoint IDs into the shared allowlist before ordinary protocol use, restore them offline, and update them on learned membership changes. Missing/invalid trust denies; no central lookup or expiry lease. Handshake allowlisting is not resource authorization and pairing is not general access. Learned revocation must stop subsequent operations on existing connections through 03, not merely new handshakes. See [networking ownership/interfaces](../../../docs/design.md#networking-composition-and-trust).
- [ ] Desktop serves one HTTPS listener with prefixes once, stable port, explicit CA trust, certificate verification and secure key files. Occupied/invalid port, unsafe paths and TLS/secure-store failures stop startup clearly without fallback or new issuer/endpoint identity.
- [ ] Verify OS keyring and equivalent restrictive Windows ACLs as well as Unix protection. Installation-scoped names are independent of listener URLs; unattended secure-store access is tested rather than assumed.
- [ ] Configure every deployed Node with all contexts, separate roots, stable issuer/audiences, explicit permissions, and supported secure secret references. Retain least-privilege distinct local service clients where used; remove centralized deployment roles and remote readiness/freshness dependencies.
- [ ] Rotate/revoke clients with authorized local owner APIs, secure delivery and one-way verifiers. Prove old secrets/locally revoked credentials fail after learning the change, consumer restart/retry is safe, and propagation to peers is eventual. Do not claim instantaneous partitioned revocation or authority-only refresh consumption.
- [ ] Validate binaries/images with appropriate sibling dependency build context, TLS, persistence, offline restart and unattended credentials. Check disk capacity first; do not prune Docker or delete caches/data without approval.
- [ ] Test current-format backup/recovery of each local context, endpoint identity, local private signer and protected secrets on the same Node. Handle invalid state explicitly; no migrations, automatic reset, promotion, or cloning signers across Nodes. Recovery does not require a live central authorization server.
- [ ] Run real desktop lifecycle, restart, port conflict, TLS failure, allowlist restoration/update, pairing isolation, admission independence, existing-connection denial after learned revocation and exactly-once shutdown acceptance. Mesh messages and direct streams remain distinct; deployment guidance must not promise transparent multihop SQL/KV/filesystem sync. Replace historical operator commands only after current equivalents are verified; record gaps and evidence in named operations docs.

## Verification and completion

Assess complexity/risk/priority. Record exact deployment/lifecycle/rotation/backup commands and platform results. No historic build instructions or helper-level tests count as full recovery acceptance.

## Comments

Retains old 07, 16, 17 and operational parts of 04. [Current operations requirements](../../../docs/operations.md), [map](../map.md).


2026-10-10 — **Explicit local CLI provisioning prerequisite independently reviewed and integrated at `ec14858b30f7af7ddc2b33050e8753982bcf688c`; 07 remains open, formally blocked by04.** Delivery `397255681` consumes `99cc078f`/`2ba2a22`/`9c8d1e2`; [exact independent gate/root merge](../evidence/07-local-provisioning/merger-397255681-merged.md), [current frontier](../evidence/current-frontier.md). Supersedes historical owner-blocked/running/not-delivered and no-merge dispositions only for this prerequisite slice, not full operations acceptance.

Restricted explicit fresh provisioning and exact continuation use public owner capture/verification and protected input; ordinary serving is existing-only. Present journal evidence is authoritative, absent-journal startup checks approved retained signer/endpoint/contexts/current readiness. Reviewed retained0755 Storage support preserves existing permissions without chmod, journal synthesis or fresh fallback; endpoint protection remains. Lost attempted Management/initialized Storage refuses recreation. No peer-join, rotation, reset or backup command is inferred.

**Preserve timing risk:** initial and warm independent `99cc078f` evaluator requests failed with timeout. The unchanged independent `397255681` exact gate passes **3 passed/0 failed/67 filtered, exit0,224.66s overall/220.93s tests**, covering existing-host startup/reopen and missing attempted Management/initialized Storage denial with unchanged HTTP/test bounds. This is separate from implementer controls. Instrumented HTTP200 at10040ms after successful bearer/introspection supports timing-margin sensitivity; no proven historical cause/fix or zero-flake guarantee. No instrumentation, experimental runtime change, timer increase or authorization weakening was retained.

Frontend `a55ead270` and peer queue `a199c341`/`61d11e8e` are independently reviewed/integrated bounded prerequisites, not desktop lifecycle/rotation rollout acceptance. HTTPS queue native-owner reopen/retry is not OS-process/whole-Tauri restart. [Partial-bootstrap README](../evidence/04-partial-bootstrap/README.md) records only two uncommitted/unqualified test/helper files on its branch, no integrated completion, stack overflow/timeouts before observer; not recovery evidence for07.

All nine07 checkboxes remain unchecked. Real OS/unattended secret provider, Windows ACLs, binaries/images/deployment, TLS/port/lifecycle/shutdown matrix, authorized rotation rollout and same-Node current-format backup/recovery remain unqualified by this slice.04 criteria6–9,06/08 and external owner maps/dependencies are unchanged; no new API/ticket dependency or stable operations edit. Documentation-only reconciliation; no source/branch changes, tests/builds/provider operations or commits.
