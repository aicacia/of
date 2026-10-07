# System design

Use authenticated owner-service HTTP APIs in separate and unified deployments, with Management as the single RBAC authority and IdP as the identity owner. Unified Hosts share one Iroh endpoint, not service repositories or authorization bypasses; first Installation uses local owner operations rather than unauthenticated HTTP setup.

This document describes design requirements, not proof of implementation. Shared definitions live in [the glossary](../GLOSSARY.md); [the glossary map](../GLOSSARY-MAP.md) links context-specific design and contracts.

## Service ownership

IdP owns Users, Applications, OAuth Clients and grants, signing-key metadata, Device enrollment/approval/revocation, and replica membership. Management owns roles, permissions, assignments, restrictions, selections, and replication policy. Storage owns resource catalogs, content, and synchronization.

Users call the identity owner directly; Management is not an identity-administration proxy. Management references canonical IdP IDs and calls authenticated owner APIs without accessing IdP repositories. Ordinary token issuance and validation do not depend on Management; identity administration requires its RBAC decision. Unified hosting preserves separate state ownership and data roots.

Resource isolation and selection requirements are defined in [Storage design](../crates/storage-service/docs/design.md). OAuth/OIDC and key identity are defined in [IdP design](../crates/idp-service/docs/design.md).

## Replica authority

IdP replicas keep independent private signing keys and share a canonical issuer and approved public-signer registry. Copying signing secrets is rejected because Device revocation cannot invalidate copied secrets; database-only bootstrap is insufficient because it does not establish signing capability.

One Designated IdP Authority handles identity mutations, authorization-code creation/redemption, and refresh rotation. Replicas may validate and issue client-credentials tokens only while authoritative security state is at most 30 seconds old. This avoids treating eventual database synchronization as single-use grant coordination; automatic authority promotion and broader replica user-token issuance are outside scope.

## Installation and synchronization

First Installation grants explicit Application/Installation RBAC permissions and provisions distinct service relationships, including IdP→Management permission evaluation.

Storage checks policy before each bounded synchronization operation; completed valid batches may remain after later failure. For SQL synchronization, the complete incoming catalog is one atomic batch and must validate before dependent data is applied. Dependency-ready complete row records may commit in byte-bounded transactions with their index updates; a failed batch rolls back, while earlier valid batches remain committed. Transport frames are not commit units. Bounded retention and ordered apply are required, but no public rewind API is required. Receive records before opening the corresponding write transaction so network waits do not block unrelated writers. Row-batch atomicity does not preserve source multi-row transaction boundaries unless the protocol identifies them. Clean Installation is required, without migrations or compatibility paths.

The [unified service spec](../.scratch/unified-server/spec.md) contains setup lifecycle and acceptance requirements; [tickets](../.scratch/unified-server/map.md) track remaining work and [implementation evidence](../.scratch/unified-server/evidence.md) records results.
