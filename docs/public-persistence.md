# Public persistence and protocol integration

This describes the implemented consumer boundary and its remaining gaps, not completed equal-Node acceptance. The original [of02 ticket](../.scratch/offline-first-nodes/issues/02-public-persistence-and-sync-integration.md) records commands, source revisions, and coordinated cutover evidence.

## Owner contracts

All Cargo dependency edges from `of` to `ofdb` target `ofdb-sql` or `ofdb-kv`, including development dependencies. Owner-internal dependencies transitively inside those facades are expected; they are not permission for `of` to import internal crates.

| Owner prerequisite                                                                                       | Public contract consumed                                                                                      | Owner qualification                                                                                                                           |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| [ofdb01](../../ofdb/.scratch/storage-sync/issues/01-kv-facade-parity.md)                                 | `ofdb_kv::Database::open_with_table(path, "kv")`, `client`, typed client transactions                         | Native named-table reopen, explicit incompatible-table rejection, commit/rollback, expiry, tombstones and facade-only exchange                |
| [ofdb02](../../ofdb/.scratch/storage-sync/issues/02-native-sql-staging.md)                               | SQL `native-stage`; `Database::synchronize_with_stage_directory_checked`                                      | Native stage creation/replay/drop/explicit cleanup, malformed and truncated records, facade composition                                       |
| [ofdb03](../../ofdb/.scratch/storage-sync/issues/03-sql-pre-apply-authorization.md)                      | Async caller check before every SQL apply; `SyncError::PreApply`                                              | Both roles, catalog/data/fallback/recovery checks, native cancellation and prompt cleanup with a pending Abort send                           |
| [ofdb04](../../ofdb/.scratch/storage-sync/issues/04-kv-pre-apply-authorization.md)                       | `Database::synchronize_checked(transport, role, config, check)`; public `SyncConfig`, `SyncRole`, `SyncError` | Both roles, batch denial and rollback, retained prior commits, cancellation, pending Abort and fresh-session retry                            |
| [ofdb05](../../ofdb/.scratch/storage-sync/issues/05-local-regression-qualification.md)                   | Separate durable SQL/KV resources and native checked staging                                                  | 581 feature combinations passed at its recorded revision; complexity/coverage limitations remain documented                                   |
| ofdb public-conflicts follow-up `1f0fe5a` ([contract](../../ofdb/docs/storage-sync-public-conflicts.md)) | `Client::row_conflicts`, `row_conflict_values`, `resolve_row`; snapshot-local `Transaction` inspections       | Public native/reopen, memory, remote unsupported and transaction-local tests; incremental causal/delta repair integrated in `25b9251`         |
| [offs01](../../offs/.scratch/filesystem-sync/issues/01-remote-operation-admission.md)                    | `OperationControl`, `MetadataSync::with_operation_control`                                                    | Queued execution checks, admitted mutation completion, cancellation, per-destination outbound admission                                       |
| [offs02](../../offs/.scratch/filesystem-sync/issues/02-staged-content-write-integrity.md)                | Existing filesystem/session APIs, revision-bound reads and publication                                        | Complete immutable content publication, error/drop cleanup, preserved prior content/revision; no cross-content/database crash-atomicity claim |

Owner reports remain the authority for generic integrity and cleanup guarantees. Consumer tests do not requalify their CRDT, replay, batching or content-publication implementations.

## Storage resources

`DatabaseRuntime` owns resource catalogs and namespace decisions, not backend construction. SQL resources use `ofdb_sql::Database`; KV sidecars use `ofdb_kv::Database::open_with_table(..., "kv")`. The established `kv` table remains explicit, rather than silently substituting the facade's default table. Query and transaction operations use each database's `Client`. SQL/KV handles are independent, and SQL success is not rolled back when a subsequent KV phase fails.

Native reopen tests cover durable resource identity, SQL and KV availability, subject/Application isolation, retained tombstones, and already-issued handle lifetime. Public owner APIs define supported formats; no conversion, migration, raw Redb sidecar construction or caller timestamp source remains in Storage.

## Direct protocol streams

`storage-server/src/data_protocol.rs` multiplexes database marker 1, filesystem marker 2, and the Unified host's security marker 3 on the existing `iroh-chain::DATA_ALPN` handler. The host supplies its `Server`; `Server::router` composes the existing mesh and one DATA handler, with the host's optional bootstrap handler where applicable. The new adapters do not bind endpoints, implement admission hooks, or own mesh/pairing/routing machinery. The existing standalone Storage endpoint is not duplicated by these adapters.

- `database_transport.rs` supplies length-prefixed byte exchange on existing streams through the public SQL `SyncTransport` seam. SQL and KV payload codecs remain in `ofdb`.
- `filesystem_transport.rs` owns the domain resource descriptor, handshake/envelope, authenticated connection peer, metadata/session multiplexing and concrete `FileHandle` implementation. Generic filesystem codecs and persistence remain in `offs`; no `file-system/iroh` dependency remains in `of`.
- The database handler supplies the authenticated resource check to native SQL checked sync and public KV checked sync. Owner `PreApply` denial becomes `io::ErrorKind::PermissionDenied`, distinguishable from integrity/transport/storage failure. The owner defines atomic apply units and staging lifetime; the former `of` stage implementation and its generic tests are deleted.
- The filesystem handler supplies the same authenticated resource binding through `offs::OperationControl` before executor operations. Cancellation requests stop unstarted work and permit an admitted owner operation to finish. Filesystem RPC requests additionally recheck local policy before transmission, including on established handles. There is no extracted periodic freshness poll or unauthenticated open path.

These are direct connections, not mesh Broadcast/Direct Message forwarding. No protocol added here uses forwarded source claims, and no transparent multihop database/filesystem synchronization is claimed.

The extracted transport tests exercise metadata plus remote read/write, denied established-handle writes without peer mutation, stream shutdown during multichunk reads, local usability after cancellation, and fresh-stream reconciliation of offline changes on the same authenticated connection. RPC channel closure after delivered chunks without `ReadEnd` returns `BrokenPipe`, never successful partial data. Its deterministic regression uses an ordered response barrier and explicitly consumes the delivered chunk before permitting closure, without delivery sleeps. Existing Storage tests exercise both protocols through the shared DATA router, authenticated endpoint claims and descriptor denial. Their Management HTTP fixtures are not real local-domain authorization qualification; that remains of03.

## Authenticated scoped security-history exchange

**P1 fix implemented; of02 remains claimed pending review.** SQL schema/type-scoped history inspection alone cannot enforce confidentiality of Text-valued JWKs or grant hashes. Private JWK fields can survive in overwritten/deleted/losing-conflict assignments even when the visible row is public. The adapter now consumes original owner `1480a09` historical-value validation, and real marker3 regressions pass. Do not integrate or resolve before consumer review. Existing facade/extraction evidence remains valid; confidentiality is of02 work, not a deferred of03 permission test.

`idp_server::validate_public_security_record` takes an actual Iroh `Connection`, local Installation identity, claimed member, public table, complete projected record and current time. It derives the remote endpoint from `Connection::remote_id`, consults the current local IdP membership/Device/signer repository, and applies the existing `PublicSecurityTable` column/type/public-JWK allowlist. Member/signer records must remain in the local Installation. Missing/invalid/revoked trust and forged member/Installation claims deny; a projection cannot contain credential/private-key/secret fields or an opaque history field.

This is **preflight validation**, not actor/action/target authorization, history reconciliation or an import API. Host adapters must supply the local Installation and current time from trusted configuration/state and check actual apply permissions. Native-store reopen and learned revocation on an existing authenticated connection are covered by a real local IdP/Device repository test.

`unified-server/src/security_sync.rs` now performs actual bidirectional history exchange, not projected inserts. `SecurityProtocol::attach` adds security marker 3 to the existing DATA dispatcher; `compose_protocol_router` wires it alongside Storage and IdP bootstrap on the host's one persisted endpoint. `SecurityProtocol::synchronize` and `UnifiedRuntime::synchronize_security(connection, context)` are the outbound entry points on an existing authenticated connection. No new endpoint, reconnect timer, forwarding protocol, payload codec, stage or recovery layer is introduced. Connection/reconnect scheduling stays with the host caller.

A versioned, strictly decoded handshake binds the configured Installation/issuer, context, and member to `Connection::remote_id`. Before admission/export and every owner atomic incoming apply, both roles require current local member/signer/approved Device trust, configured local signer readiness, and a conflict-clear local User identified by the Device's persisted `owner_subject`. Both contexts verify their local table columns against reviewed domain allowlists through public SQL metadata before exporting history; widened local layouts reject even when using the standalone adapter. Owner scoped validation additionally rejects incompatible/hidden historical layouts. No actor comes from the wire or endpoint ID. Local Management evaluates the exact Installation permissions `idp.security.sync` / `management.security.sync` with matching `IdpSecurity` / `ManagementSecurity` resources. Missing local evidence denies. These explicit grants must be provisioned locally before reconciliation; pairing/discovery does not grant them. Admission and local owner `PreApply` denial are `PermissionDenied`; integrity/storage/transport failures remain separate.

These permissions authorize exchange of the full reviewed context scope, including public approvals/grants, not arbitrary per-row CRUD impersonation. Installation provenance is the authenticated session's currently approved member binding; scoped sessions do not run a whole projected-record validator over opaque history. Historical JWK/hash disclosure safety must instead use the generic owner per-table/column historical-value callback, with domain checks supplied by of. Foreign/unapproved bindings cannot authorize a session through the existing local trust repository. Fine-grained actor/issuer/in-flight authorization qualification remains of03; the historical JWK/hash confidentiality gate belongs of02. The current adapter additionally consumes same-transaction candidate evidence as described below; that is not correlated original historical mutation evidence. Whole-database export remains unsafe because excluded tables retain credential history. Never prune CRDT bytes or substitute projected last-writer-wins inserts.

### Local credential separation

The new schema removes secret/pending-workflow fields from otherwise syncable row documents:

| Public metadata                                                     | Local-only storage                                                                                               | Semantics                                                                                                                                                        |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clients` without `client_secret_hash`, with public `credential_id` | `local_client_credentials(client_id, credential_id, secret_hash)`                                                | Argon2 verifier; local creation/rotation/deletion with public metadata in one SQL Transaction                                                                    |
| `credentials` without `secret_hash`                                 | `local_credential_secrets(credential_id, secret_hash)`                                                           | Password Argon2 verifier; public active/revoked metadata governs use; password replacement atomically deactivates old metadata and creates new metadata/verifier |
| `devices` without enrollment/pending-pairing fields                 | `local_device_enrollments(device_id, enrollment_code_hash, enrollment_expires_at, pairing_accepting_public_key)` | Pending enrollment/pairing is local; approval/revocation deletes its local workflow row in the same Transaction as public state change                           |

These tables share the identity database to preserve owner transaction atomicity. They are **not keyring-encrypted**: protect the local database at rest. Raw passwords, client secrets and bearer grants are never stored. Private derived/master/signing keys remain in existing local secure `PrivateKeyRepo` implementations; no new keyring/SQL two-phase protocol or credential facade is introduced. Old/replaced verifiers can remain in local CRDT history and must never enter a scoped session.

Metadata arriving from a peer grants no credential capability. Missing local password verifier returns no password credential; missing local client verifier yields authentication denial, not an Argon2 parser/server error. Explicit local credential provisioning is required on each Node that authenticates a confidential client/User. Client verifiers are bound to a non-secret public `credential_id`: genuine secret rotation changes that revision atomically with the local verifier, while a metadata-only/no-secret-change update retains it. A learned revision mismatch disables an old local verifier until explicit local provisioning; concurrent conflicting revisions fail closed through existing client conflict checks. This preserves learned-rotation denial without sending the verifier. Public signing-key verification does not require those credentials. Test peer fixtures independently provision known secrets, rather than copy verifiers via public records; same-Node durability fixtures retain their own local tables.

Authorization-code/refresh-token rows retain SHA-256 lookup hashes, binding/expiry and consumed/revoked state, not raw grants. Their transaction-local redemption/replay semantics are unchanged; partitions still permit independent local winners, not global single use.

**Breaking storage change; no migration.** Initialize a fresh identity database. `replica::up` rejects existing public schemas containing the removed credential fields. Dropping columns externally does not sanitize old history and is unsupported; schema checks are not a sanitizer for arbitrary externally altered files.

### Scoped owner contract and historical-value handoff

Original owner `1480a09` delivers `synchronize_tables_validated_checked(transport, config, role, tables, validate, check)` and native `synchronize_tables_with_stage_directory_validated_checked(transport, config, role, directory, tables, validate, check)`. `validate` is a synchronous `Fn(&str, &str, &ofdb_sql::Value) -> Result<(), String> + Send + Sync`, separate from the existing zero-argument async current authorization check. Owner inspects every historical assignment/default, including overwritten/deleted/losing-conflict values, outgoing before disclosure and incoming before staging/apply, in state/incremental/recovery paths on both roles; actual later exports are revalidated after initial preflight. Rejection must not echo confidential values. No new trait, CRDT projection or consumer codec is needed. Exact owner/consumer coordination is in original of02 Comments.

`PublicSecurityTable::permits_historical_value` shares projection JWK/hash checks: closed public JWK fields, direct typed parsing of original text (including duplicate-key rejection), actual verifying-key point validation and 64-character ASCII-hex hashes. Null known-column history/default values carry no confidential content; this is not complete-row validity or permission. `permits_record` retains stricter complete-record requirements. Owner retains generic type/layout/history enforcement; of retains domain rules.

Original ofdb `2fbac37d26f8dc65b072481cd243a509c7460b43` provides:

- `Database::synchronize_tables_checked(transport, config, role, tables: &[&str], check)`
- `Database::synchronize_tables_with_stage_directory_checked(transport, config, role, directory, tables: &[&str], check)`

These older methods provide structural validation only and are NOT consumed by the production security adapter. The adapter consumes `synchronize_tables_with_stage_directory_candidate_validated_checked` from owner13 (`4dde323cf0d3082767fe829aeb5534e466fa77bf`), using existing `DatabaseTransport`, `SyncTransport`, `SessionConfig`, `SyncRole`, `SyncError` and owner stages. Its synchronous callback uses the matching IdP `PublicSecurityTable::permits_historical_value`, or Management's reviewed public table/column allowlist (owner retains SQL type/layout checks). Unknown table/column or invalid domain value returns only the constant `invalid public security historical value`, never the value. The zero-argument `FnMut() -> Future<Result<(), String>>` current-policy check remains separate and unchanged. IdP and Management databases and stage directories remain separate. See owner `docs/storage-sync-table-scope.md` for fixed-schema complete-history validation, exact scope agreement, rollback/recovery and cleanup evidence. No consumer export/apply or parallel staged transport exists.

Owner scope constrains outgoing manifests/incremental/full-state/recovery and incoming catalog/index/data/history on both roles. Full conflicts, tombstones, resolution deltas and causal dependencies remain intact; selected catalogs/indexes and data use existing atomic owner applies. Empty/invalid/duplicate scopes, schema widening, out-of-scope references, and unknown historical/deleted properties reject. Both peers must predeclare compatible fixed schemas. Unsupported history codecs reject rather than prune. DDL evolution/history sanitization is not supported. Checks precede incoming atomic applies, not every outgoing read or interruption of an already authorized operation. Earlier commits can remain after later failure; discard the stream after any failure.

Actual IdP scope is the eleven `public_security_tables()` tables, including credential metadata; Management scope is its six `PUBLIC_POLICY_TABLES` RBAC/selection tables. Email/phone/audit tables and all `local_*` tables are outside this initial scope. Public-record validators are not substitutes for this history contract. The adapter supplies current trust/Installation/actor/context checks; detailed downstream revocation/action qualification remains of03. Exact handoff and schema evidence are recorded in original of02 Comments.

### Current candidate semantics and readiness

The public native candidate-validated checked session supplies `SyncCandidateView` from the same outgoing export read transaction or incoming prospective apply transaction. Its complete selected-table rows, tombstones and named concurrent values allow domain correlation without database reentry, backend types, another stage or a new transport. The existing historical scalar callback still inspects every retained assignment/default, and now checks exact configured Installation/member issuer/signer issuer even when a foreign value was overwritten. Every current outbound send and incoming pre-apply authorization check remains independent and unchanged.

`unified-server/src/security_candidates.rs` validates IdP's reviewed eleven-table scope. Unambiguous signer JWK `kid` equals `key_id`; non-null `active_member_id` equals `member_id`. Membership endpoints are canonical Iroh endpoint IDs and match the related present Device public key. Membership SQL `id` is an independent row identity, **not** `member_id`. Device owner strings parse as non-nil User UUIDs. The two currently established session Device/member endpoints and owner IDs are pinned from local approved Device/conflict-clear User evidence; candidate rows cannot silently rebind them. Signer keys are not pinned, permitting legitimate key rotation and old revoked signer histories. Management retains its reviewed six-table/column scope and owner structural validation; this slice adds no cross-context RBAC provenance inference.

Missing/deleted related rows and conflicted correlated fields are pending evidence, not guessed historical tuples or fabricated references. Concurrent scalar values still require disclosure safety; unambiguous contradictory relations reject. Pending rows, revocations, tombstones and legitimate conflicts may persist, but an allowing callback never publishes trust or completion. Durable current repositories must subsequently establish conflict-clear Device/member/signer trust, active User owner, exact local context grants and independent signing capability. `trusted_signers` alone does not establish active User ownership or all-context readiness. The callback is synchronous/read-only/idempotent and performs no IO; errors contain constants, never values.

Incoming rejection rolls back the actual owner batch, not the session: earlier valid pending rows/catalog progress and independent local contenders remain. Outgoing fresh recovery is candidate-validated again. An unsolicited incoming recovery snapshot can be rejected by owner integrity **before** candidate validation; that negative result is not domain recovery-gate evidence. Current complete candidate observations do not correlate historical tuples or expose original mutation authorship. No authorship ledger/signature is introduced: current authenticated actor and exact context permission authorize the reviewed exchange scope, not impersonated per-row CRUD. Broader03 and purpose-bound04 acceptance remain open.

## IdP and Management facade consumers

IdP/Management open public SQL `Database` handles and obtain query/transaction handles with `client()`. `db/src/lib.rs` re-exports only public facade/query/value interfaces; the raw Redb constructor, backend aliases and backend repository generics are deleted. The client repository retains its private-key repository parameter: private signer material still belongs to the local key store, not SQL sync.

Conflict names, every concurrent value and explicit resolution use the owner Client APIs. Refresh-token and signer operations inspect conflicts on their existing public Transaction, preserving snapshot and local-write semantics. Administrator identity, monotonic revocation/consumption restrictions, restrictive Management convergence and resolution audit insertion remain unchanged domain logic. Unsupported inspection errors propagate; they are not clear-state results.

Repository history fixtures use public sync sessions over trusted test-only channels; the Unified security integration additionally uses real authenticated Iroh streams and the production shared DATA dispatcher. No production mixed-engine export is introduced. IdP tests retain fail-closed conflict decisions, administrator resolution/audit and revoked-grant non-resurrection. Public native tests retain code/refresh replay denial, offline signer issuance, key verification without private material, local permission restart and wrong-actor/action/namespace denial. Schema/projection tests use public SQL query metadata, not backend schema inspection. Their UUID literals now satisfy the owner's UUIDv7 contract; production deterministic IDs are unchanged.

## Joining from empty local owner stores

A purpose-specific equal-Node enrollment receipt binds the Installation, Device/member,
endpoint, independent public signer and approving User to a pinned approving peer.
`OwnerProvisioner::record_node_join_approval` persists that receipt, not public owner
state, context-export permission or local readiness. The independent private signer
remains in the local secure-store adapter. Replaying the receipt must not activate trust,
create grants or override a learned revocation.

The existing `SecurityProtocol::synchronize` is an **already-trusted peer** session, not
initial bootstrap. Before opening a history stream it requires local signer/member
trust; subsequent admission requires authenticated remote membership, its exact approved
Device, an active conflict-clear User owner, and the relevant locally evaluated
`IdpSecuritySync` or `ManagementSecuritySync` permission. A fresh joining database has
none of this public baseline. Enrollment on the approving Node does not establish it
on the joining Node. The registered bootstrap ALPN currently denies every request.

Consequently, initial authorized public bootstrap is not implemented. The native
`node_join_receipt_cannot_bootstrap_context_trust_even_after_native_reopen` regression
uses real User authentication/token exchange, authorized pairing, separate native
stores, independent local signer preparation and an authenticated DATA connection.
Even with explicit context grants at the source, both joining-side context attempts
fail at local signer/member trust before staging. No User, Device or policy rows are
imported. Offline native reopen retains the same receipt/request and local signer
material but remains incomplete. Its keyring is an injected test store, not an OS-keyring
or GUI/process-restart qualification.

### Concrete bootstrap handoff

- **Domain admission (of04 with of03):** provide explicit, purpose-bound authorization
  for initial IdP and Management public histories from the pinned, currently trusted
  approving endpoint to the exact enrolled joining endpoint/Device/member/signer.
  Evaluate current active owner and exact context grants at the source; enrollment
  approval alone is insufficient. The joining-side decision must verify these bindings
  without requiring the public baseline it is about to receive. Do not weaken ordinary
  marker-3 admission or treat pairing/receipt possession as general access.
- **Delivered owner/consumer seam (of03 handoff):** use the scoped native candidate-
  validated checked session above, historical scalar confidentiality/exact issuer
  checks and current per-send/pre-apply authorization. Owner13 supplies current
  candidate/related-row/conflict/tombstone evidence from the actual transaction;
  the ordinary marker3 adapter now consumes it. The prior scalar-only observation
  and missing-current-outbound statements are superseded. Bootstrap still needs its
  own purpose-bound pinned evidence and current source grants; ordinary session
  bindings must not be inferred from a receipt or empty joining stores. Incomplete
  candidates can persist without readiness. No new owner facade, trait or historical
  authorship ledger is demanded by this admission cycle.
- **Readiness (of04):** only after both contexts have durably imported validated full
  public histories and owner checks establish local trust, policy and independent
  signing capability may completion be persisted. Verify partial-apply failures,
  stable retries, learned revocation non-resurrection and offline issuance/reopen at
  this actual import seam. Current receipt/denial tests do not satisfy this acceptance.

### Receive-only bootstrap retry limitation

Owner13's candidate observation and ordinary marker-3 guards are delivered. A separate
one-way execution limitation remains: the current scoped session is bidirectional on
both `SyncRole`s. `Initiator`/`Responder` select turn ordering, not publication direction.
Before manifest comparison or outbound selection, it exports/preflights **all** retained
selected local rows. A joining-side candidate guard rejecting outgoing application rows
therefore permits the first import into empty tables but rejects a subsequent exact
retry once any imported application history is retained. This happens even when that
history already exists at the source and no reverse row transfer would be necessary.

The focused native `bootstrap_receive_only_guard_allows_empty_import_but_blocks_native_retry`
regression consumes `synchronize_tables_with_stage_directory_candidate_validated_checked`
with the same eleven public IdP tables and owner-native stages. Incoming application
candidates at the source and outgoing application candidates at the receiver reject;
catalog/control exchange remains permitted. The initial import succeeds with no receiver
application State/Changes frames. After native receiver reopen, exact retry rejects at
outgoing preflight, retaining both manifests. Adding another source User still cannot
resume: neither side publishes receiver application data, no additional User imports,
and prior receiver progress/source updates remain intact. This is an in-process transport
fixture testing the public persistence boundary, not authenticated domain bootstrap.

**Concrete owner follow-up:** provide a supported source-to-receiver scoped session
that excludes receiver application-history export/preflight/build/recovery publication
while retaining its real persisted progress for source inventory/delta/snapshot recovery.
The source must not apply receiver application rows, including on malicious or resumed
exchanges. Reuse the same candidate/historical validation, fixed schemas, native stages,
complete histories/conflicts/tombstones, atomic pre-apply checks and failure cleanup.
Qualify empty import, retained partial progress after cancellation/native reopen, exact
retry, fresh source updates, hostile reverse publication and learned local revocation
non-resurrection. No method signature or new consumer transport/persistence is prescribed.
This is a capability absent from the current public session, not a defect in owner13's
candidate evidence or a demand for an authorship ledger.

A rejecting candidate callback is not a filter: it aborts the session. Allowing retained
receiver rows during preflight could permit arbitrary receiver history publication;
the current row/conflict view does not establish that every historical assignment came
from the pinned source. Suppressing frames, pretending the receiver is empty, clearing
retained progress, or copying/projecting source state would violate the owner protocol
or retry/history requirements. Production purpose-bound bootstrap/readiness is not
implemented until this execution boundary can preserve progress without reverse publication.

Whole-database export, unchecked apply, source database copying, projected LWW baseline
inserts, receipt-derived grants and parallel staging are not bootstrap substitutes.
Private/local credential tables remain excluded; complete public history, tombstones
and conflicts stay owner-managed. Storage/resource access is a separate authorization
boundary, not granted by successful public context bootstrap.

## Remaining integration and qualification gaps

The previous incremental hash mismatch is repaired by original ofdb `25b9251`, which produces precise deltas and preserves causal order; see owner `docs/storage-sync-incremental-identity.md`. The unchanged active Management conflict/resolution/native-reopen regression passed five consecutive original-source runs after the repair. No integrity check was weakened and no fallback or ignored test concealed the finding.

Original ofdb `c368f16641d0039ac3d32edd1e271d997df3f5e9` repairs genuine unchanged UPDATE, including transaction no-rotation updates, without fabricated deltas/timestamps or weakened integrity. The formerly failing client no-rotation test remains active and now passes; current consumer qualification is recorded below.

Nine Management-service failures reproduce on committed baseline `5c4e1e2`: eight deterministic UUIDv5 resource-selection IDs rejected by the owner's UUIDv7 requirement, plus a configured-issuer mismatch in an actor-token fixture. Two Management-server denial fixtures return upstream-unavailable, and one IdP provisioning fixture lacks a local node signer; those also reproduce on that baseline. They are not repaired by this persistence migration.

Endpoint trust restoration/update and completed setup are host work in of04/of07. Detailed local policy and per-action execution checks, legacy timeout removal, in-flight completion and live learned-revocation qualification remain of03. These are not proven by a handler admitting a connection or by the isolated preflight test. Resource transfer/removal orchestration is of05; owner stage cleanup is not whole-resource removal evidence.

## Recorded consumer qualification

Focused owner-source runs passed: IdP-model 14, IdP-service with `replica` 40, and the no-default-features IdP-server/Storage-server/Storage-service run 9/50/13. Storage's 50 include all six filesystem transport tests and native resource/restart/namespace assertions. The all-targets unified-server build, boundary check and source/Cargo facade audit passed. Library Clippy passed with existing warnings; all-targets Clippy encountered existing unhandled IO-read counts in HTTP fixtures. Full powerset/CRAP success is not claimed. Commands and baseline investigation are recorded in the original ticket.

Current credential-separation checks use original sibling sources via existing symlinks, with **no Cargo source overrides**. At the credential-separation checkpoint, IdP-model passed 15/15 and IdP-service passed 43/44 with the owner no-op failure; that failure is repaired and superseded by the current scoped integration results below. New native password/client verifier separation, missing-verifier denial, enrollment workflow restart/cleanup and failed-local-write registration rollback tests pass. Independent-peer confidential-client token issuance first denies without a local verifier, then passes after explicit local provisioning. Management passed 28/37 with the same nine independently baseline-reproduced UUIDv5/issuer fixture failures; its previously intermittent sync regression passed five repeats. Unified-server all-targets build, library Clippy and boundary/diff checks pass. Final powerset timed out at 180 seconds; CRAP timed out at 120 seconds compiling coverage, with no analyzer result. These are not complete broad qualification. Current logs are retained under original `of/target/of02-credentials-*.log`.

Original offs `516b692` supplies the adapter-free API and public `MAX_FILE_READ_LENGTH`; all six extracted FS transport tests pass against those original sources, including deterministic missing-ReadEnd rejection. Original ofdb `25b9251` supplies the conflict API and incremental fix; `c368f166` repairs no-op updates and `2fbac37d` delivers scoped checked sessions. The coordinated extraction normal-source check is complete. No absolute dependency paths, forwarding wrappers, compatibility implementation or owner-workspace edits are part of this change.

### P1 follow-up status

The domain validator is implemented and tested: IdP service **45/45 passes**, including shared projection/history-value closed-JWK, point/duplicate/trailing-content and grant-hash cases. A native public-facade fixture proves a private JWK can be a losing conflict behind a public visible winner. The active tests previously reproduced RED outgoing disclosure, incoming import, unseen full-state import and malformed token_hash disclosure on original `2fbac37d`. With original `1480a09` and the production validated callback, **all eight history tests pass (seven-test suite plus separately added grant matrix)**, including 48 hostile JWK cases: current/overwritten/deleted/losing × both production roles × outgoing/incoming × retained incremental, unseen-row full state and late recovery. Outgoing uses deliberately unvalidated recipients and captured public owner frames to assert no State/Changes disclosure; incoming asserts protected key rows unchanged. Valid visible JWK rows with a private schema default reject on both outgoing roles. Public JWK rotations and 64-hex code/token hashes sync; a subsequent raw token_hash rejects without changing the recipient. Eight additional real marker3 cases reject overwritten raw code_hash/token_hash values behind valid visible hashes in both directions and roles, with the same outgoing no-disclosure/incoming unchanged-row/error-confidentiality assertions.

The recovery fixture manipulates only public `SyncMessage::RequestSnapshots` on the existing authenticated marker3 stream and introduces private history after clean preflight, before recovery selection; it adds no application CRDT codec/stage/transport. All four history variants run in both directions/roles. Local production initiators must return the exact domain rejection; remote production responder failure can surface as stream closure rather than delivered Abort, consistent with the owner contract. Every case checks no invalid row import; outgoing cases also check no history disclosure. Generic request validation, atomic rollback/history identity and recovery-stage cleanup remain qualified by owner follow-up11, not reimplemented here.

Original-source commands: `RUST_MIN_STACK=16777216 cargo test -p unified-server --lib security_history_tests -- --nocapture` **7 pass (258.97s)**; `cargo test -p unified-server --lib authenticated_equal_peers_exchange_scoped_history_without_local_verifiers -- --nocapture` **1 pass (122.25s)**; IdP replica library **45 pass**; Unified all-targets check and focused Unified/IdP library Clippy and Unified all-targets Clippy pass with existing warnings; boundary, touched Rust formatting and diff checks pass. The separately added overwritten-grant matrix passes (82.88s). Required root powerset completes all ten root-package combinations (zero tests/no-op disabled targets, not workspace-wide library qualification); CRAP times out at 120s compiling coverage (exit124, no analyzer result). No source override, owner edit, current-row workaround, ignored regression or absolute Cargo dependency path is used. **of02 remains claimed pending consumer review.** Logs: original `of/target/of02-p1-{marker3-final,recovery-green,equal-peer-green,grant-matrix-green,idp-final,check-final,clippy-final,clippy-tests,powerset-confirmed,crap-final}.log`.

### Historical scoped integration qualification on original sources (P1 acceptance withdrawn)

- `RUST_MIN_STACK=16777216 cargo test -p idp-model -p idp-service --features replica --lib --no-fail-fast`: **16 + 44 passed**. The unchanged no-rotation regression now passes on owner `c368f166`.
- `RUST_MIN_STACK=16777216 cargo test -p management-service --features replica --lib`: **29 passed / 9 unchanged baseline failures** (eight deterministic UUIDv5 selection IDs rejected as UUIDv7; one configured-issuer fixture mismatch). Public scoped-schema and conflict/reopen regressions pass. No of05 UUID semantics changed.
- `RUST_MIN_STACK=16777216 cargo test -p storage-server -p storage-service --features storage-server/network --lib`: **50 + 13 passed**, including all six extracted filesystem transport tests.
- `RUST_MIN_STACK=16777216 cargo test -p unified-server --lib authenticated_equal_peers`: final **2/2 repeated passes**, exercising the production shared DATA handler, actual authenticated Connection provenance, newly learned approved public Device/member/signer history, bidirectional public Users, independently retained local password/client/enrollment secrets, refresh consumption/replay denial, separate Management scope/root, concurrent owner conflicts/restrictive resolution deltas, role tombstones/repeated sync, native reopen, and forged Installation/member/version, missing signer/actor, learned permission denial and widened local-schema rejection. A test-only 240-second whole-fixture bound accommodates multiple native sessions; no production timer/quota was added.
- Combined Unified library run: **8 passed / 1 failure** in the existing host HTTP acceptance fixture (`temporarily_unavailable`, 503 vs 200); exact isolated `builds_three_prefixed_services` rerun **passed**, including the host's production router composition. Do not claim an all-green combined run.
- Unified all-targets build, focused library Clippy, boundary and source/Cargo facade audits pass. Clippy retains existing router-conversion/collapsible-if warnings.
- Exact required root `cargo hack test --feature-powerset --all-targets`: **10 root-package combinations completed**, compiling the host's CLI/configuration features; root binary tests contain zero tests, several disabled-target combinations are no-ops. This is **not** a workspace-wide library powerset pass. `just crap --summary` timed out after **120 seconds compiling coverage**; no CRAP result is claimed.

All commands use the worktree's existing sibling symlinks to original owner sources, without source overrides. Logs are retained under original `of/target/of02-security-*.log`. Generic integrity/history/stage rollback/recovery/cancellation evidence remains the owner's scoped-session qualification, not reimplemented consumer staging tests. The scoped SQL/no-op and historical-value callback owner blockers are delivered and consumed. Historical P1 acceptance remains withdrawn until consumer review passes; current GREEN evidence is recorded above. Host reconnect scheduling/full-platform acceptance and detailed of03 hostile-record, learned-revocation/in-flight qualification remain downstream; no automatic security-sync timer, global partition single-use or immediate unseen revocation guarantee is claimed.
