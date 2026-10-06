# Glossary Map

## Shared domain

- [Shared terms](GLOSSARY.md): Installation, User, Application, Principal, Device, and setup lifecycle.
- [System-wide decisions](docs/adr/).
- [Unified service spec](.scratch/unified-server/spec.md), [tickets](.scratch/unified-server/map.md), and [implementation evidence](.scratch/unified-server/evidence.md).

## Contexts

| Context    | Glossary                                            | Decisions and contracts                                                                        |
| ---------- | --------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| IdP        | [Identity Provider](crates/idp-service/GLOSSARY.md) | [OIDC and key identity](crates/idp-service/docs/adr/0001-oidc-and-key-identity.md)             |
| Management | [Management](crates/management-service/GLOSSARY.md) | [Owner-service authority](docs/adr/0002-service-authority-and-replica-boundaries.md)           |
| Storage    | [Storage](crates/storage-service/GLOSSARY.md)       | [API](crates/storage-service/docs/api.md), [security](crates/storage-service/docs/security.md) |

Each context covers its related model, service, server, and client packages.
Context-specific contracts belong in `crates/<context>-service/docs/`; context-specific ADRs belong in its `adr/` directory. Create them only when needed. System-wide decisions stay in `docs/adr/`.

## Relationships

- IdP owns identity, OAuth, Device enrollment, and replica membership. Identity administration uses Management RBAC; ordinary token issuance and validation do not depend on Management.
- Management owns roles, permissions, restrictions, selections, and replication policy. It refers to canonical IdP identities and calls authenticated owner APIs, not IdP repositories or identity-administration proxies.
- Storage owns resources and synchronization. It uses IdP identity and Management policy.
- A Unified Host coordinates owner-local setup and service lifecycle without merging authority or state ownership.

Read shared docs and every context relevant to the work. State conflicts with existing ADRs rather than silently overriding them.
