# Node security boundaries

[System design](design.md) states the equal offline-first requirements. This source audit records current boundaries without claiming full host/platform acceptance. Detailed contracts live in [IdP local security](../crates/idp-service/docs/local-security.md), [Storage security](../crates/storage-service/docs/security.md) and [public persistence](public-persistence.md).

## Identity is not interchangeable

A token subject identifies a User or Client Principal. A Node Signer identifies its issuer. An authenticated Iroh endpoint identifies the connection peer. None may substitute for another, and an endpoint ID or message-source claim is not a User actor or resource permission.

IdP administration uses validated bearer identity with exact audience, action and target. Management permission evaluation binds a User caller to the same requested User; only the separately registered least-privilege evaluator Client may assert a User under its explicit evaluator scope/audience. Alternate actor/subject headers grant no authority. Existing `x-actor-subject` impersonation-denial tests are intentional negative evidence, not obsolete authentication features. Selection supplies a kind-specific Storage token in the typed `storageAccessToken` body field, not an `X-Storage-Authorization` override.

`/replica-signers` is the current authorized public Node-signer API. Its historical name, `DbReplicaSignerRepo`, persisted membership table names, `replica` persistence features and CRDT source/receiver roles do not create a designated authority/privileged replica topology. Public signer approval is not private signing capability or blanket synchronization permission.

Storage transport bases are not token audiences. The password-manager caller delivery exchanges the current User token for `resource=storage:filesystems`, with exact typed Storage actions: read for listing, write for creation, read/write for the editable filesystem socket. Explicit IdP/Storage service bases replace the audience/origin fallback; no actor override or wider permission is introduced. [Current owner evidence](../.scratch/offline-first-nodes/evidence/06-audit.md#current-clientcaller-handoff--2026-10-11) qualifies these caller/package checks, not server authorization, GUI approval or deployment acceptance.

## Local trust and learned denial

Each Node checks persistent locally trusted IdP/Management owner state. Unified service relationships use the local contexts; unavailable or invalid local evidence denies. Loss of a remote peer alone is not authorization loss, and there is no 30-second trust freshness gate. Normal token expiry/renewal margins, purpose-specific pairing controls and bounded test waits are not trust leases.

Connection admission and approved endpoint allowlisting are not resource authorization. Pairing is purpose-bound approval exchange, not general access. Security-history exchange checks exact local context-sync permissions, authenticated membership and public-history integrity. Resource protocols independently check ownership, namespace, selection and restriction at actual apply/read/write boundaries, including existing connections. Learned denial blocks subsequent work; already-authorized work may finish. Partitioned Nodes may temporarily diverge, and OAuth consumption is atomic locally rather than globally single-use.

## Credentials and persistence

Keep independent private signers, raw passwords, raw secrets and confidential-client authentication material local in supported secure storage. Only reviewed public/domain projections and validated scoped history may synchronize. Removed mixed-row credential fields are rejected by current schema checks; externally dropping columns does not sanitize historical CRDT disclosure. Do not delete active local-only credential repositories, secret references, credentials metadata, or rejection fixtures merely because they mention a removed field.

`of` depends on public `ofdb-sql` and `ofdb-kv` facades. Owner-internal transitive dependencies, facade backend feature names and `.redb` data-file extensions are legitimate, not direct internal persistence dependencies. `offs` owns filesystem persistence, `ofnet` owns reusable endpoint/mesh/pairing/routing, and `of` owns domain authorization and protocol adapters. Preserve separate context roots and ordinary least-privilege local service-client scopes/audiences; no compatibility wrappers or central-role fallback are required.

## Qualification limits

Production setup/signer preparation, purpose-bound pairing/bootstrap and current owner-readiness seams are present. This does not establish authorized GUI approval, joining-Node completion or two-profile offline restart: ticket 04 remains incomplete under the [native checkpoint](../.scratch/offline-first-nodes/evidence/04-native-acceptance/checkpoint.md). Secure-store/provider/platform, deployment and broader lifecycle/integration qualification remain downstream. No historical passing test, receipt, generated route or listener probe waives those limits.

The [ticket-06 audit](../.scratch/offline-first-nodes/evidence/06-audit.md) records static findings, owner handoffs and commands. No credentials, raw tokens or private keys are included, and no Cargo/GUI/live-endpoint validation was run by this audit.
