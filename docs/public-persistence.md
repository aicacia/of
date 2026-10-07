# Public persistence and protocol integration

This describes the implemented consumer boundary and its remaining gaps, not completed equal-Node acceptance. The original [of02 ticket](../.scratch/offline-first-nodes/issues/02-public-persistence-and-sync-integration.md) records commands, source revisions, and coordinated cutover evidence.

## Owner contracts

All Cargo dependency edges from `of` to `ofdb` target `ofdb-sql` or `ofdb-kv`, including development dependencies. Owner-internal dependencies transitively inside those facades are expected; they are not permission for `of` to import internal crates.

| Owner prerequisite | Public contract consumed | Owner qualification |
| --- | --- | --- |
| [ofdb01](../../ofdb/.scratch/storage-sync/issues/01-kv-facade-parity.md) | `ofdb_kv::Database::open_with_table(path, "kv")`, `client`, typed client transactions | Native named-table reopen, explicit incompatible-table rejection, commit/rollback, expiry, tombstones and facade-only exchange |
| [ofdb02](../../ofdb/.scratch/storage-sync/issues/02-native-sql-staging.md) | SQL `native-stage`; `Database::synchronize_with_stage_directory_checked` | Native stage creation/replay/drop/explicit cleanup, malformed and truncated records, facade composition |
| [ofdb03](../../ofdb/.scratch/storage-sync/issues/03-sql-pre-apply-authorization.md) | Async caller check before every SQL apply; `SyncError::PreApply` | Both roles, catalog/data/fallback/recovery checks, native cancellation and prompt cleanup with a pending Abort send |
| [ofdb04](../../ofdb/.scratch/storage-sync/issues/04-kv-pre-apply-authorization.md) | `Database::synchronize_checked(transport, role, config, check)`; public `SyncConfig`, `SyncRole`, `SyncError` | Both roles, batch denial and rollback, retained prior commits, cancellation, pending Abort and fresh-session retry |
| [ofdb05](../../ofdb/.scratch/storage-sync/issues/05-local-regression-qualification.md) | Separate durable SQL/KV resources and native checked staging | 581 feature combinations passed; complexity run completed but its coverage aggregation mismatch/high scores remain documented |
| [offs01](../../offs/.scratch/filesystem-sync/issues/01-remote-operation-admission.md) | `OperationControl`, `MetadataSync::with_operation_control` | Queued execution checks, admitted mutation completion, cancellation, per-destination outbound admission |
| [offs02](../../offs/.scratch/filesystem-sync/issues/02-staged-content-write-integrity.md) | Existing filesystem/session APIs, revision-bound reads and publication | Complete immutable content publication, error/drop cleanup, preserved prior content/revision; no cross-content/database crash-atomicity claim |

Owner reports remain the authority for generic integrity and cleanup guarantees. Consumer tests do not requalify their CRDT, replay, batching or content-publication implementations.

## Storage resources

`DatabaseRuntime` owns resource catalogs and namespace decisions, not backend construction. SQL resources use `ofdb_sql::Database`; KV sidecars use `ofdb_kv::Database::open_with_table(..., "kv")`. The established `kv` table remains explicit, rather than silently substituting the facade's default table. Query and transaction operations use each database's `Client`. SQL/KV handles are independent, and SQL success is not rolled back when a subsequent KV phase fails.

Native reopen tests cover durable resource identity, SQL and KV availability, subject/Application isolation, retained tombstones, and already-issued handle lifetime. Public owner APIs define supported formats; no conversion, migration, raw Redb sidecar construction or caller timestamp source remains in Storage.

## Direct protocol streams

`storage-server/src/data_protocol.rs` multiplexes database marker 1 and filesystem marker 2 on the existing `iroh-chain::DATA_ALPN` handler. The host supplies its `Server`; `Server::router` composes the existing mesh and one DATA handler, with the host's optional bootstrap handler where applicable. The new adapters do not bind endpoints, implement admission hooks, or own mesh/pairing/routing machinery. The existing standalone Storage endpoint is not duplicated by these adapters.

- `database_transport.rs` supplies length-prefixed byte exchange on existing streams through the public SQL `SyncTransport` seam. SQL and KV payload codecs remain in `ofdb`.
- `filesystem_transport.rs` owns the domain resource descriptor, handshake/envelope, authenticated connection peer, metadata/session multiplexing and concrete `FileHandle` implementation. Generic filesystem codecs and persistence remain in `offs`; no `file-system/iroh` dependency remains in `of`.
- The database handler supplies the authenticated resource check to native SQL checked sync and public KV checked sync. Owner `PreApply` denial becomes `io::ErrorKind::PermissionDenied`, distinguishable from integrity/transport/storage failure. The owner defines atomic apply units and staging lifetime; the former `of` stage implementation and its generic tests are deleted.
- The filesystem handler supplies the same authenticated resource binding through `offs::OperationControl` before executor operations. Cancellation requests stop unstarted work and permit an admitted owner operation to finish. Filesystem RPC requests additionally recheck local policy before transmission, including on established handles. There is no extracted periodic freshness poll or unauthenticated open path.

These are direct connections, not mesh Broadcast/Direct Message forwarding. No protocol added here uses forwarded source claims, and no transparent multihop database/filesystem synchronization is claimed.

The extracted transport tests exercise metadata plus remote read/write, denied established-handle writes without peer mutation, stream shutdown during multichunk reads, local usability after cancellation, and fresh-stream reconciliation of offline changes on the same authenticated connection. Existing Storage tests exercise both protocols through the shared DATA router, authenticated endpoint claims and descriptor denial. Their Management HTTP fixtures are not real local-domain authorization qualification; that remains of03.

## Security-record preflight and missing history exchange

`idp_server::validate_public_security_record` takes an actual Iroh `Connection`, local Installation identity, claimed member, public table, complete projected record and current time. It derives the remote endpoint from `Connection::remote_id`, consults the current local IdP membership/Device/signer repository, and applies the existing `PublicSecurityTable` column/type/public-JWK allowlist. Member/signer records must remain in the local Installation. Missing/invalid/revoked trust and forged member/Installation claims deny; a projection cannot contain credential/private-key/secret fields or an opaque history field.

This is **preflight validation**, not actor/action/target authorization, history reconciliation or an import API. Host adapters must supply the local Installation and current time from trusted configuration/state and check actual apply permissions. Native-store reopen and learned revocation on an existing authenticated connection are covered by a real local IdP/Device repository test.

The public SQL sync export is opaque whole-resource state. Mixed IdP rows and historical CRDT changes can contain excluded client verifiers, enrollment secrets or other credential material even if current projected columns look public. There is no verified public API to export/import an allowlisted, dependency-complete, conflict/tombstone-preserving security history. **IdP/Management domain history exchange is not enabled.** Do not call whole-engine export to bridge this gap, and do not replace reconciliation with unqualified last-writer-wins projected inserts. A safe owner contract and domain reconciliation semantics are needed first.

## Remaining migration and integration gaps

The SQL facade currently re-exports `Engine`, `Kernel`, codecs and backend types, but its `Database`/`Client` APIs do not expose the conflict inspection and resolution used by IdP/Management (`row_conflicts`, `resolve_row`, and transaction-local conflict checks). `of/crates/db/src/native.rs` still constructs an Engine with raw Redb through the facade re-export; native repository types still mention `RedbKernel`/`AutomergeRowCodec`. Removing this without an owner-supported conflict-aware public contract would discard security denial semantics or require a forbidden parallel facade. The all-native facade migration criterion therefore remains incomplete despite clean Cargo facade edges and the completed Storage migration.

Endpoint trust restoration/update and completed setup are host work in of04/of07. Detailed local policy and per-action execution checks, legacy timeout removal, in-flight completion and live learned-revocation qualification remain of03. These are not proven by a handler admitting a connection or by the isolated preflight test. Resource transfer/removal orchestration is of05; owner stage cleanup is not whole-resource removal evidence.

The adapter requires offs03's public `MAX_FILE_READ_LENGTH` export and adapter-free API. Validate against the integrated original sibling checkout before declaring that coordinated cutover complete. No absolute dependency paths, forwarding wrappers, compatibility implementation or owner-workspace edits are part of this change.
