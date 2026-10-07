# Storage

The resource-management and database/filesystem synchronization context. Shared terms are defined in [the root glossary](../../GLOSSARY.md). Resource isolation and synchronization policy are described in [Storage design](docs/design.md).

## Language

**Storage Resource**:
A database or filesystem in one User's Application namespace, with a distinct stable identity and a potentially non-unique display name. Multiple OAuth Clients of that Application share the namespace, while other subjects cannot open it.

**Resource Catalog**:
The synchronized record of Storage Resource identity, ownership, display names, and deletion status. Discovery does not imply local possession of content or permission to access it.

**Storage-Audience Access Token**:
A standard IdP access token for the Storage API, obtained through sign-in or exchange from an Application client's user token. It binds subject, Application, and API action limits, not mesh synchronization; it is neither a separate token type nor a single-use storage session.
_Avoid_: Storage Session, storage client token

**Resource Ownership**:
The exclusive User/Application namespace boundary for a database or filesystem and every file in it. Other subjects and Applications cannot access or select it; there are no file permission bits, groups, or cross-user grants.
_Avoid_: Device grant, endpoint grant

**Filesystem ID**:
The stable identity of one filesystem instance, independent of its local root path. It scopes filesystem authorization and synchronization.
_Avoid_: Vault ID

**Database ID**:
The stable identity of one Application database, separate from the IdP/Management control-plane database and every Filesystem ID.

**Residency**:
A Device-local choice per filesystem path: Full stores metadata and content locally, while Passthrough stores metadata and reads content from an available Full peer but cannot write. Residency is not synchronized.

**File System**:
A local-first replicated storage engine for paths, metadata, and file content, separate from Application databases and IdP/Management records. It has no file permission bits, groups, or cross-user grants.

**File Entry**:
Metadata for one filesystem path, with a stable file identity, content revision, and provider information. Deleted entries are represented by synchronized Tombstones.

**Tombstone**:
A synchronized deletion record that prevents a deleted File Entry or Storage Resource from returning when an offline Device reconnects.
