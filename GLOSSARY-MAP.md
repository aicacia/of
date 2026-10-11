# Glossary Map

## Shared domain

- [Public persistence and protocol integration](docs/public-persistence.md): owner facade contracts, shared-router adapters, authenticated scoped security history, local credential separation, and qualification boundaries.

- [Shared terms](GLOSSARY.md): Installation, User, Application, Principal, Device, and setup lifecycle.
- [System design](docs/design.md): equal offline-first Nodes, local authorization, ownership boundaries, and synchronization requirements.
- [System API contracts](docs/api.md): owner routes, prefix composition, setup/readiness, and safe client generation.
- [System security](docs/security.md): actor/subject/signer/endpoint distinctions, local trust, secret separation, and acceptance limits.
- [Networking composition](docs/design.md#networking-composition-and-trust): `ofnet`/`iroh-chain` reuse, local membership, and source interfaces; [ofnet Endpoint Mesh glossary](../ofnet/GLOSSARY.md) defines Endpoint, Peer, Mesh, Broadcast, Direct Message, and Byte Stream.
- [Offline-first Nodes spec](.scratch/offline-first-nodes/spec.md), [tickets and migration coverage](.scratch/offline-first-nodes/map.md), and [Node operations](docs/operations.md).

## Contexts

| Context    | Glossary                                            | Design and contracts                                                                                                                                                                                      |
| ---------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IdP        | [Identity Provider](crates/idp-service/GLOSSARY.md) | [Design](crates/idp-service/docs/design.md), [local security](crates/idp-service/docs/local-security.md), [owner API](docs/api.md#owner-contracts)                                                        |
| Management | [Management](crates/management-service/GLOSSARY.md) | [Service ownership](docs/design.md#service-ownership), [owner API](docs/api.md#owner-contracts), [selection and admission](crates/storage-service/docs/design.md#device-ownership-and-resource-selection) |
| Storage    | [Storage](crates/storage-service/GLOSSARY.md)       | [Design](crates/storage-service/docs/design.md), [API](crates/storage-service/docs/api.md), [security](crates/storage-service/docs/security.md)                                                           |

Each context covers its related model, service, server, and client packages.
Definitions belong in the relevant `GLOSSARY.md`. Current design, contracts, and operational guidance belong in stable topic files such as `docs/design.md`, `docs/api.md`, `docs/security.md`, or `docs/operations.md`, not numbered decision records. System-wide topics live in `docs/`; context-specific topics live in `crates/<context>-service/docs/`. Create topic files only when needed, update them in place, and link them here.

## Relationships

- Each equal Node hosts IdP, Management, and Storage, with persistent local trusted state and locally checked actor permissions. No live central authority or privileged replica role is required.
- IdP owns identity, OAuth, Device lifecycle, and public signer trust. Private signers remain local; locally atomic grant consumption does not promise global single use during partitions.
- Management owns roles, permissions, restrictions, selections, and replication policy. It refers to IdP identities through owner boundaries, not identity repositories or administration proxies.
- Storage owns domain catalogs, namespaces, resource lifecycle, and authorization. `ofdb` owns SQL/KV persistence/sync/staging/batching/cleanup through public `ofdb-sql`/`ofdb-kv`; `offs` owns filesystem persistence/sync, not transport. `ofnet`/`iroh-chain` owns reusable endpoint/mesh/pairing mechanics, allowlist enforcement, and generic connections/routing. `of` owns Installation/Device endpoint trust binding, local authorization, and protocol-specific adapters wiring `ofdb`/`offs`.
- A Unified Host coordinates owner-local setup and service lifecycle without merging context state ownership. Joining uses a trusted reachable peer; completed Nodes work offline and after restart. Revocation takes effect when learned, including before subsequent operations on existing connections. Endpoint allowlisting is not resource authorization, pairing is not general access, and mesh messages do not imply transparent multihop database/filesystem streams.

Read shared docs and every context relevant to the work. State conflicts with existing definitions and design contracts rather than silently overriding them.
