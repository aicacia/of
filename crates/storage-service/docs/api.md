# Storage API

This is a source-checked API description, not a runtime acceptance result. See [security](security.md) for peer authorization, the [unified service spec](../../../.scratch/unified-server/spec.md) for targets, and the [ticket index](../../../.scratch/unified-server/map.md) for open work.

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

Routes below show the unified `/management` prefix. Management bearer validation uses IdP introspection, requires a User principal with the Management audience, and checks the Application-scoped `devices.select` permission.

| Operation         | Route                                                                                    | Current behavior                                                         |
| ----------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Select resource   | `PUT /management/devices/{device_id}/selection`                                          | Validates Device and resource, stores selection, returns `204`           |
| Deselect resource | `DELETE /management/devices/{device_id}/selection/{application_id}/{kind}/{resource_id}` | Checks selection-policy owner and permission; returns `204` or not found |
| Deselect all      | `DELETE /management/devices/{device_id}/selection`                                       | Mounted but denies; use the resource-specific route                      |

Selection JSON contains `applicationId`, `kind` (`database` or `filesystem`), `id`, and `storageAccessToken`. The token is not supplied through an `X-Storage-Authorization` header. The Management token's Application must match `applicationId`.

Management checks the supplied Storage token's signature, configured issuer, audience/resource, use, lifetime, subject, Storage scope, and `read` action. It uses authenticated IdP Device lookup and the kind-specific Storage GET route, checking returned identity and Application. Unknown resources, identity mismatch, and unavailable owner APIs deny selection. Deselect does not need Storage, but bearer validation still depends on IdP.

Selection starts empty and covers whole resources. Administrator allowance is enforced in stored policy, but no public `/devices/{device_id}/restriction` route is currently mounted. No ownership-transfer implementation is established by this contract. Local-copy cleanup and stronger Device-owner binding remain open work in the system plan.

## Source

- Storage handlers: `crates/storage-server/src/router/resources.rs`.
- Storage authorization: `crates/storage-server/src/router/storage_authorization.rs`.
- Selection handlers: `crates/management-server/src/router/routes/device_selection.rs`.
- Owner API checks: `crates/management-service/src/hosted_control_plane.rs`.
