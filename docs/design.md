# System design

This is the confirmed target architecture, not a claim that the implementation already satisfies it. [The glossary map](../GLOSSARY-MAP.md) links definitions and context contracts; [offline-first node work](../.scratch/offline-first-nodes/map.md) tracks implementation and acceptance gaps.

## Equal offline-first nodes

Every Node runs IdP, Management, and Storage. Nodes are equal peers: none is a designated writer, central authority, privileged replica, or promotion candidate. Any Node may mutate identity, policy, and resources when the actor's permissions checked against that Node's trusted local state permit it. An Installation shares a Canonical Issuer and approved public identities, not one live authorization server.

Trusted identity and policy state persists locally. Restart restores usable trusted state and local signing capability without requiring a reachable peer or revalidation against a central service. Missing, corrupt, untrusted, or locally revoked state must not grant access. A partition alone does not invalidate trusted state; there is no 30-second freshness rule or background freshness lease.

Revocations and restrictions take effect on a Node when learned. Temporarily divergent authorization decisions during partitions are accepted. Reconnection exchanges approved state and reconciles changes; no claim of instantaneous global revocation, remote erasure, or globally serialized administration is made.

## Service ownership

IdP owns Users, Applications, OAuth Clients and grants, signer metadata, and Device enrollment/approval/revocation. Management owns roles, permissions, assignments, restrictions, selections, and replication policy. Storage owns resource catalogs, namespace isolation, resource lifecycle, and authorization. These domain responsibilities exist on every Node; ownership names a context, not a privileged machine.

Users call the relevant authenticated owner API; Management is not an identity-administration proxy. Contexts retain separate repositories and data roots. A host composes services and coordinates owner-local setup without reading another context's repositories or bypassing permissions. Permission checks use local IdP and Management state through their owner boundaries, not a required remote control plane. Ordinary token issuance and validation need local identity/grant checks; administration additionally requires exact actor/action/target permissions.

`of` owns domain identity, policy, catalogs, Installation/Device trust decisions, local authorization, protocol-specific transport adapters wiring `ofdb`/`offs`, and runtime composition. `ofnet`/`iroh-chain` owns reusable Iroh endpoint, mesh, pairing mechanics, endpoint allowlist enforcement, and generic connection/routing machinery. `ofdb` owns SQL/KV persistence, CRDT synchronization, staging, batching, and cleanup. `of` uses only the public `ofdb-sql` and `ofdb-kv` facades, never backend or internal crates. `offs` owns filesystem persistence and synchronization, not transport. Generic tests live with these owners; `of` supplies domain and authorization integration tests. Generic hooks must not contain IdP, Management, or Storage policy.

## Identity and grants

Each Node has an independent private signer kept in its local secure store. Approved public signer data and other explicitly approved identity/policy data may synchronize; private keys, raw passwords, and raw client secrets must not. Define record allowlists and provenance checks rather than copying mixed engines. Signer identity, token Principal, and authenticated Device transport identity remain distinct.

All Nodes may perform locally authorized OAuth/OIDC issuance, code creation/redemption, and refresh rotation/revocation. Validate signature, configured issuer, audience, token use, lifetime, client, scope, Principal, and signer against locally known state. Grant consumption is durable and atomic locally, including after restart. Local atomicity does not guarantee global single use across partitioned Nodes; partitioned concurrent consumption is an accepted limitation, not a reason to introduce a designated consumer or global coordination dependency.

## Installation and lifecycle

Create a new Installation through restricted owner-local setup, with stable retry IDs, explicit initial administrator grants, secure secrets, and no unauthenticated HTTP setup mutation or password-grant join. Join an existing Installation through a trusted reachable peer using authenticated, purpose-specific approval, Installation/endpoint/signer binding, and approved state exchange. Every joined Node hosts all three contexts; Storage-only and privileged-authority/replica join roles are retired. Join readiness establishes local trust and signing capability, not an expiring peer lease.

After completed setup, persist trust, identity, policy, endpoint identity, and local completion state for offline restart. Partial setup remains incomplete and retryable. Secure-store or TLS failures do not permit plaintext fallback; malformed state is preserved for explicit recovery/reset. Local reset affects only that Node and may proceed offline; authorized revocation is propagated when possible.

A Node host composes one shared `iroh-chain` endpoint/router with persisted endpoint identity and trusted membership, shared by its protocol handlers. Transport trust is not resource permission. Desktop serves one HTTPS listener with prefixes mounted once, persistent port, explicit CA trust, certificate verification, readiness verification before background work, and one shutdown. Context isolation remains even when services share a host.

## Networking composition and trust

Reuse [ofnet's Endpoint Mesh vocabulary](../../ofnet/GLOSSARY.md) without equating its Endpoint with an Installation Node or its Peer with an approved Device. `of` binds an authenticated endpoint to an Installation Device through local IdP owner state; `ofnet` has no Installation, User, selection, or resource policy.

At startup, `of` loads persisted, locally trusted approved/non-revoked membership into the shared endpoint allowlist and updates it as approval/revocation is learned. The endpoint key and domain membership are persisted by the host/owner integration; `iroh-chain`'s `EndpointIdStore` is an in-memory shared set, not a durable trust database. A completed Node restores this state offline without central contact or a trust-expiry lease. Missing/invalid local trust fails closed.

Endpoint allowlist hooks enforce connection/handshake admission, not resource authorization. Pairing mechanics provide purpose-specific offer/reply exchange, not approval authority or general access: `of` authorizes the approver, validates Installation/Device/endpoint/signer binding, and persists approved membership before granting ordinary participation. Pairing or protocol-specific bootstrap admission must not grant arbitrary data access. Existing optional timed pairing/ALPN helpers do not prescribe an expiring Installation trust lease or new custom timers.

Mesh Broadcast and Direct Message are message-routing facilities, including forwarding through peers. Direct Iroh connections/byte streams are distinct interfaces. Their existence does not provide transparent multihop SQL/KV/filesystem stream synchronization. `of` adapters wire direct protocol streams to public persistence/sync APIs; any mesh-message use needs explicit protocol semantics and provenance/authorization checks, not an assumption that a forwarded message's source is the authenticated connection peer.

Read-only interface anchors:

- [`Server`](../../ofnet/crates/iroh-chain/src/server.rs): `bind_with_secret_key`, `endpoint`, `peers`, `allowlist_hook`, `router`/`router_with_protocol`, pairing controls/offers, `broadcast`/`send`/`subscribe_messages`, and `connect_direct_with_alpn`/`open_stream`.
- [`EndpointIdStore`](../../ofnet/crates/iroh-chain/src/store.rs): `replace`/`add`/`remove` update the shared in-memory endpoint set.
- [`AllowlistHook`](../../ofnet/crates/iroh-chain/src/hooks.rs): `before_connect`/`after_handshake`; these hooks do not reauthorize operations on an existing connection.
- [`PairingOffer`](../../ofnet/crates/iroh-chain/src/pairing.rs): authenticated `remote_id`, payload, and `reply`; [`mesh`](../../ofnet/crates/iroh-chain/src/mesh.rs) implements message exchange/forwarding.

These are existing source interfaces, not proof of delivered multi-protocol Node integration. Audit router composition during implementation: current helpers accept a data handler and optionally one additional protocol; do not invent an already-available arbitrary registration API. Reuse the existing machinery first. Move genuinely generic missing connection/routing pieces to `ofnet` only on demonstrated need; domain trust and protocol integration stay in `of`. Coordinated filesystem adapter extraction in of 02/offs 03 does not authorize a blanket `ofnet` rewrite, a new networking framework, or a new mandatory tracker/dependency gate.

## Authorization and synchronization

Both peers use locally known trusted Device ownership, permissions, selections, restrictions, and resource catalog data. Derive peer identity from the authenticated Iroh connection, not handshake owner/endpoint claims. Missing local authorization evidence or a failed local evaluation denies the operation; loss of a remote peer is not loss of local authorization.

Check authorization before each apply operation through a generic execution hook supplied by the owning persistence/sync API. This requirement does not prescribe a new trait. Transport admission or receiving/enqueueing bytes is not permission to apply them later. Also authorize resource reads, outbound writes, and API mutations at their actual execution boundaries. An already-authorized in-flight operation may finish; a newly learned revocation or restriction blocks subsequent operations, including on already-open connections. Removing an endpoint from the allowlist or waiting for another handshake is not a substitute for these execution checks. No custom quotas, timers, deadlines, or periodic freshness checks are required.

Integrity, atomicity, cancellation cleanup, and valid progress remain required. Receive/stage required records before opening write transactions; network waits must not block unrelated writers. Validate and commit the complete SQL catalog and derived indexes atomically before dependent data. Apply dependency-ready complete rows with their index updates in owner-defined batches, rolling back failed batches while retaining earlier valid commits. Transport frames are not commit units; source multi-row atomicity is not promised without protocol-defined boundaries. Preserve recovery completeness, Tombstones, reconnect, and source/local data on rejection. Cancelled or failed work releases streams, tasks, handles, and staging artifacts without damaging unrelated resources.

Generic staging/batching/cleanup implementation and acceptance belong to [ofdb storage-sync](../../ofdb/.scratch/storage-sync/map.md); filesystem persistence/sync and cleanup belong to [offs filesystem-sync](../../offs/.scratch/filesystem-sync/map.md). These are cross-workspace handoff targets, not work completed by this documentation migration. `of` must not retain parallel persistence/staging or duplicate reusable networking implementations to bridge old behavior; its domain/protocol adapters remain necessary integration.
