# Glossary Map

## Shared domain

- [Shared terms](GLOSSARY.md): Installation, User, Application, Principal, Device, and setup lifecycle.
- [System design](docs/design.md): service authority, replica boundaries, Installation, and synchronization requirements.
- [Unified service spec](.scratch/unified-server/spec.md), [tickets](.scratch/unified-server/map.md), and [implementation evidence](.scratch/unified-server/evidence.md).

## Contexts

| Context    | Glossary                                            | Design and contracts                                                                                                                                            |
| ---------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IdP        | [Identity Provider](crates/idp-service/GLOSSARY.md) | [Design](crates/idp-service/docs/design.md): OAuth/OIDC and key identity                                                                                        |
| Management | [Management](crates/management-service/GLOSSARY.md) | [Service authority](docs/design.md#service-ownership), [selection and admission](crates/storage-service/docs/design.md#device-ownership-and-resource-selection) |
| Storage    | [Storage](crates/storage-service/GLOSSARY.md)       | [Design](crates/storage-service/docs/design.md), [API](crates/storage-service/docs/api.md), [security](crates/storage-service/docs/security.md)                 |

Each context covers its related model, service, server, and client packages.
Definitions belong in the relevant `GLOSSARY.md`. Current design, contracts, and operational guidance belong in stable topic files such as `docs/design.md`, `docs/api.md`, `docs/security.md`, or `docs/operations.md`, not numbered decision records. System-wide topics live in `docs/`; context-specific topics live in `crates/<context>-service/docs/`. Create topic files only when needed, update them in place, and link them here.

## Relationships

- IdP owns identity, OAuth, Device enrollment, and replica membership. Identity administration uses Management RBAC; ordinary token issuance and validation do not depend on Management.
- Management owns roles, permissions, restrictions, selections, and replication policy. It refers to canonical IdP identities and calls authenticated owner APIs, not IdP repositories or identity-administration proxies.
- Storage owns resources and synchronization. It uses IdP identity and Management policy.
- A Unified Host coordinates owner-local setup and service lifecycle without merging authority or state ownership.

Read shared docs and every context relevant to the work. State conflicts with existing definitions and design contracts rather than silently overriding them.
