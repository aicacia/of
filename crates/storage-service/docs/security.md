# Storage security and transport

[System ADR 0001](../../../docs/adr/0001-offline-storage-resources.md) records resource isolation; [system ADR 0002](../../../docs/adr/0002-service-authority-and-replica-boundaries.md) records owner-service authority and bounded synchronization. This document separates source-checked behavior from acceptance targets. No tests were rerun for this documentation audit.

## Authority

Storage API tokens authorize API actions, not mesh synchronization. Iroh endpoint keys identify transport peers, not Users or resource grants. No delegated Device keys, certificates, endpoint-signed grants, folder ACLs, or cross-user permissions are required.

IdP owns Device lifecycle. Management owns selection and admission policy. Storage uses live authenticated Management APIs, not a local replicated Management policy database. Unified hosting does not merge IdP and Management repositories.

Storage obtains selected-resource metadata and admission through Management's replication routes. Management resolves approved endpoint identities through IdP, checks matching owners, and checks allowance and whole-resource selection for both Devices. Selection claims in a peer handshake are not authoritative. Storage derives local identity from its injected endpoint and remote identity from `Connection::remote_id()`.

Selection starts empty. Concurrent deselection wins; a causally later selection may restore synchronization. Restriction denies admission even when selected. Resource ownership remains the User/Application namespace, not the Device key. A signed-in User lists only that namespace; background services retain selected-resource metadata, not a namespace-wide catalog.

Revocation stops future authorized work but cannot recall copied bytes. Desired transfer/reset and deselection cleanup rules are in the system plan; they are not established cleanup guarantees for all runtimes.

## Current checks and limits

SQL/KV transport checks policy before send and before/after receive. Filesystem transport checks before/after received frames and before outgoing enqueue, including response chunks, with a periodic background check. Both inbound and outbound paths use authorization checks.

These checks are not a guarantee of fresh authorization at each SQL apply transaction, filesystem metadata import/file operation, or queued filesystem socket write. Keep those gaps separate from the target requirement to check each bounded operation.

| Boundary                              | Current limit           |
| ------------------------------------- | ----------------------- |
| SQL encoded message / Iroh payload    | 1 MiB                   |
| Storage KV encoded frame              | 1 MiB                   |
| Filesystem metadata/session frame     | 1 MiB                   |
| Filesystem read request               | 1 MiB                   |
| Filesystem response data chunk        | 1 MiB minus 1,024 bytes |
| SQL default units per frame           | 64                      |
| SQL default session accounting budget | 64 MiB                  |
| SQL data apply batch                  | 1 MiB                   |
| Storage file stage                    | 64 MiB per stage        |
| Filesystem active requests            | 64                      |
| Filesystem response channel           | 1 entry                 |
| Filesystem transport queue            | 64 entries              |

Length-prefixed SQL and filesystem transports reject oversized payload lengths before allocating payload buffers. Storage's KV limit overrides the generic sibling KV default; do not treat generic defaults as deployed Storage limits.

Storage uses 5-second connection/handshake bounds, 10-second policy-check bounds, and a 30-second bound around the combined SQL/KV or filesystem synchronization operation. The 30-second wrapper is not a distinct timer for every batch or chunk. Frame limits and stage caps do not establish total memory, disk, or concurrent-work bounds.

## Ownership and validation

- `ofnet` owns authenticated transport and generic routing, not database/filesystem payload protocols.
- `ofdb` owns database/KV persistence and synchronization.
- `offs` owns filesystem persistence and synchronization.
- `of` owns resource catalogs, namespace isolation, service authorization, and runtime composition. It must reuse owning-crate protocols, not add a second framing or recovery layer.

Owning crates validate version, framing, and payload. Admission must precede synchronization, and the target requires renewed policy checks before each bounded operation. Do not use permissive adapters to hide missing checks.

The [implementation evidence](../../../.scratch/unified-server/evidence.md) preserves recorded test results; the [ticket index](../../../.scratch/unified-server/map.md) owns remaining acceptance work. Earlier policy-replica tests do not prove the deployed live-HTTP admission path. Full outage, cancellation, resource-bound, and topology acceptance must be established separately.

## Source

- `crates/storage-server/src/database_protocol.rs`, `storage_protocol.rs`, and `management_client.rs`.
- `crates/management-server/src/router/routes/replication.rs`.
- Sibling `ofdb`: `crates/sql-sync/src/session.rs` and `iroh_transport.rs`.
- Sibling `offs`: `crates/file-system/src/protocol.rs`, `file_service.rs`, `iroh_transport.rs`, and `sync.rs`.
