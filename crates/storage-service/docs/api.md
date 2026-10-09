# Storage API

Route tables below preserve the API description audited on 2026-10-06, not runtime acceptance or verification of the new architecture. The target is a full offline-first Node: authenticated operations use persistent locally trusted IdP/Management state, not mandatory remote introspection. See [security](security.md), the [offline-first Nodes spec](../../../.scratch/offline-first-nodes/spec.md), and [active tickets](../../../.scratch/offline-first-nodes/map.md).

## Identity and ownership

The namespace is `(subject, application_id)`. Derive both from validated IdP identity; callers cannot choose their namespace. Multiple OAuth Clients of one Application share that User's resources. Other subjects and Applications cannot discover or open them.

Each database or filesystem has its own stable, kind-specific ID and an optional, non-unique display name. A Filesystem ID is not a Database ID. There are no file permission bits, groups, cross-user grants, or per-folder ACLs.

Use IdP-issued Storage-audience access tokens from sign-in or exchange. Check the namespace and required `read` or `write` action on each request. These tokens do not authorize mesh synchronization.

## Storage routes

Routes below show the unified `/storage` prefix; standalone prefixes are configurable.

| Operation         | Route                                         | Action  | Success |
| ----------------- | --------------------------------------------- | ------- | ------- |
| Create database   | `POST /storage/databases`                     | `write` | `201`   |
| List databases    | `GET /storage/databases`                      | `read`  | `200`   |
| Get database      | `GET /storage/databases/{database_id}`        | `read`  | `200`   |
| Delete database   | `DELETE /storage/databases/{database_id}`     | `write` | `204`   |
| Create filesystem | `POST /storage/filesystems`                   | `write` | `201`   |
| List filesystems  | `GET /storage/filesystems`                    | `read`  | `200`   |
| Get filesystem    | `GET /storage/filesystems/{filesystem_id}`    | `read`  | `200`   |
| Delete filesystem | `DELETE /storage/filesystems/{filesystem_id}` | `write` | `204`   |

Create accepts an optional `name`. List returns only the caller's namespace. Unknown, deleted, wrong-kind, and wrong-namespace resources do not grant access; a delete that finds no matching resource returns `404`.

Deletion tombstones the catalog and removes cached runtime references. It does not invalidate existing in-process handles or guarantee immediate removal of all physical or offline copies. Deselection is a separate policy operation. Passthrough filesystems retain metadata without local file content and do not permit writes.

## Management selection API

IdP owns Device enrollment, approval, and revocation. Management owns resource selections, restrictions, and replication admission. Services use authenticated owner APIs and separate repositories, including in unified hosting.

Routes below show the unified `/management` prefix. The historical implementation uses IdP introspection, requires a User principal with the Management audience, and checks Application-scoped `devices.select`. The target validates against the Node's local trusted IdP state and local Management permissions; no reachable remote IdP is required.

| Operation         | Route                                                                                    | Current behavior                                                                 |
| ----------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Select resource   | `PUT /management/devices/{device_id}/selection`                                          | Validates Device and resource, stores selection, returns `204`                   |
| Deselect resource | `DELETE /management/devices/{device_id}/selection/{application_id}/{kind}/{resource_id}` | Checks current local IdP owner and permission; returns `204` or denial/not found |
| Deselect all      | `DELETE /management/devices/{device_id}/selection`                                       | Mounted but denies; use the resource-specific route                              |

Selection JSON contains `applicationId`, `kind` (`database` or `filesystem`), `id`, and `storageAccessToken`. The token is not supplied through an `X-Storage-Authorization` header. The Management token's Application must match `applicationId`.

Validate the supplied Storage token's signature, configured issuer, audience/resource, use, lifetime, subject, Storage scope, and `read` action. Bind Device ownership to locally trusted IdP records and check the kind-specific resource through the Node's Storage owner API. Unknown locally unverifiable resources and identity mismatch deny selection; offline locally verified resources remain usable. Deselect does not need content availability. Historical remote lookup/introspection behavior is a cutover gap, not a target remote dependency.

Selection starts empty and covers whole resources. Both selection and resource-specific deselection resolve current Device identity through locally hosted IdP `GET /devices/identities/{device_id}` with the service-only `idp.device.lookup` permission. IdP checks conflict-clear approved Device, canonical endpoint, signer-backed Installation membership and active owner. A stored policy owner is not identity evidence; deselection does not need content availability or a Storage read token.

`GET /management/devices/{device_id}/restriction` returns `{ "adminAllowed": bool }`; `PUT` accepts exactly that typed body and returns `204`. They require separate Installation-scoped `management.device_restrictions.read` / `.update` grants with the exact Device target, and current IdP binding. An Application grant cannot escalate; an administrator need not own the Device. Unknown/mismatched targets, malformed bodies and denied updates do not lift prior restrictions.

A learned owner mismatch records a durable local cleanup gate and clears old selections. It does not grant the new owner use/sync or pretend transfer completion. Storage public retirement APIs deny new runtime opens and retained scoped-session operations and report incomplete owner cleanup, not physical-removal success. They preserve catalog discovery, unrelated copies and Tombstones. See the [public owner cleanup handoff](../../../docs/public-persistence.md#managed-copy-retirement-public-owner-handoff): original ofdb lacks whole-resource removal/handle invalidation; offs projected eviction is insufficient. Authorized transfer initiation/completion and complete runtime/reset orchestration remain open. Revocations/restrictions take effect once learned locally; previously authorized in-flight work may finish. No global offline blocking or remote erasure is promised.

`ScopedFileSystemRuntime::set_resource_residency` persists a whole-resource Full/Passthrough choice locally. Passthrough service operations cannot write/delete/rename; unavailable content fails rather than becoming a local write. Authorized reachable-Full-peer read routing and durable path-specific choices remain unqualified; raw owner objects are not a substitute for this domain API.

## Source

- Storage handlers: `crates/storage-server/src/router/resources.rs`.
- Storage authorization: `crates/storage-server/src/router/storage_authorization.rs`.
- Selection handlers: `crates/management-server/src/router/routes/device_selection.rs`.
- Owner API checks: `crates/management-service/src/hosted_control_plane.rs`.
