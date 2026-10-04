# Domain Context

This describes the target domain. Implementation gaps are tracked in [the unified-server plan](docs/unified-server-plan.md). See [the glossary](GLOSSARY.md) for installation authority terms.

## Identity Provider (IdP)

The IdP is the OAuth 2.0 and OpenID Connect authority. It authenticates users, registers and validates OAuth clients, obtains consent, issues and verifies tokens, exposes OIDC metadata and JWKS, and manages signing-key metadata.

The IdP owns device enrollment, approval/revocation, endpoint ownership, and IdP-replica enrollment. Management owns resource restrictions and replication policy; Storage owns resource management and database/filesystem synchronization. Identity administration is authorized through Management RBAC, while ordinary token issuance and validation do not depend on Management.

## Management Service

The Management Service is the single RBAC and resource-policy authority for an installation. It owns roles, permissions, assignments, resource restrictions, selections, and replication policy. Applications and device identities belong to IdP.

Management stores canonical IdP IDs and calls normal authenticated owner APIs. It neither accesses IdP repositories nor proxies identity administration.

## Bootstrap Service

The Bootstrap Service establishes the idempotent system baseline for a new installation. It creates or updates the built-in IdP and management applications and clients, the initial administrator and signing key, management permissions and roles, and an optional bootstrap device.

A local installation coordinator invokes separate owner-local IdP and Management operations; it does not compose their repositories. Initial permissions are explicit, not future-capability wildcards. Partial installation is not ready; retries preserve canonical IDs and do not duplicate users, clients, or keys.

## User

A User is the authenticated human subject. Its stable public identifier is the OAuth/OIDC `sub` claim. Profile, email, phone, password-verifier, and key records are stored separately from the core user record.

Raw passwords are never persisted or synchronized.

## Application

An Application is a logical product or resource identified by a stable URI. It groups one or more OAuth Clients and scopes storage resources owned by a user.

An application is not an OAuth client.

## OAuth Client

An OAuth Client is a concrete web, native, or machine integration for an Application. It has a `client_id`, redirect URIs, grant and response types, allowed scopes, and client authentication configuration. Multiple clients may access that application's resources when authorized by the same user.

## OAuth Consent

OAuth Consent records a User's approval for a client, redirect URI, and scope set. It allows the authorization flow to determine whether interaction is required before issuing an authorization code.

## Authorization Code

An Authorization Code is a short-lived OAuth credential bound to its client, redirect URI, scopes, signing key, optional resource, PKCE challenge, and optional OIDC nonce. It is single-use: redeeming it durably marks it consumed so only one redemption succeeds.

## Access, ID, and Refresh Tokens

An Access Token authorizes an API request. An ID Token conveys authenticated OIDC identity claims to a client. A Refresh Token obtains replacement tokens under its original grant constraints. Tokens are signed by a Key and are validated against the configured issuer, audience, use, lifetime, and signature.

## Key

A Key is signing-key metadata: its entity owner, derivation relationship and path, name, state, and validity period. Its public JWK may be published through JWKS.

Private or derived key material is local secret state. It must not enter filesystem synchronization.

## Principal

A Principal is the User or OAuth Client represented by a token's subject. A Replica Signer identifies the authorized IdP member that signed it, not the subject. Device endpoint identity authenticates transport; it does not represent a user or grant access to resources.

## Role and Permission

A Permission is a named action with Application or Installation scope. A Role groups explicit permissions; assignments grant their authority to a User. Application authority does not imply installation-wide authority.

The built-in management application URI is `idp-management`.

## Device

A Device is one installation's persistent transport endpoint identity, represented by its locally supplied name, public key, and reachable address. A device is pending, approved, or revoked. A user who introduces a device owns it; device identity links transports, not user identity or resource permission.

A pairing request creates a pending device. An approved device signs the pairing approval payload. Revocation removes future trust but cannot erase data already copied to the revoked device.

## Reset Device

Reset Device removes one runtime's local setup state, local synchronized data, and device identity, returning it to Installation Setup. It attempts to revoke its approved device record remotely but proceeds when offline. It does not remove data from other devices.

## Installation Setup

Installation Setup establishes a new installation through local owner operations or joins an existing installation in an explicit role. A Storage-only Node receives no IdP database copy. An IdP Replica requires privileged enrollment, defined IdP state synchronization, an approved independent signer, and approval of its own endpoint before it is ready. All IdP members share the installation's canonical issuer; private signer keys remain local.
_Avoid_: Master setup, primary-node setup

## Device Setup

Device Setup configures and later edits the data an installation member stores locally after Installation Setup completes. Its completion is recorded in local device state.
_Avoid_: Setup Mode, device initialization

## Initial Administrator

The Initial Administrator is the username/password user whose supplied credentials establish administrative access when a new installation is created.
_Avoid_: Default admin, bootstrap admin

## Trusted Device

A Trusted Device is an approved, non-revoked Device eligible to participate in the mesh. Approval is transport trust, not user authorization.

## Hosted Control Plane

A Hosted Control Plane is the configured HTTP(S) authority a local runtime trusts for access-token verification and trusted-device discovery. Its issuer is configured locally, never derived from untrusted claims.

## Storage Resource

A Storage Resource is a database or filesystem in one User's Application namespace, identified by `(subject, application_id)`. Each has a distinct stable ID and may have a non-unique display name; multiple OAuth clients of that Application share the namespace, while other subjects cannot open it.

## Resource Catalog

The Resource Catalog is the synchronized record of storage resource identity, ownership, display names, and deletion status. Discovery does not imply local possession of resource content or user permission to access it.

## Storage-Audience Access Token

A Storage-Audience Access Token is a standard IdP access token for the Storage API, obtained through sign-in or exchange from an application client's user token. It binds subject, Application and API action limits, not mesh synchronization. It is not a separate token type or a single-use storage session.
_Avoid_: Storage Session, storage client token

## Resource Ownership

Resource Ownership is the exclusive `(subject, application_id)` boundary for a database or filesystem. Every file belongs to the namespace subject; other subjects and applications cannot access or select the resource. There are no file permission bits, groups, or cross-user grants.
_Avoid_: Device grant, endpoint grant

## Filesystem ID

A Filesystem ID is the stable identity of one filesystem instance, independent of its local root path. It scopes filesystem authorization and synchronization.
_Avoid_: Vault ID

## Database ID

A Database ID is the stable identity of one application database, separate from the IdP/management control-plane database and every Filesystem ID.

## Resource Selection

Resource Selection is a whole-resource choice of what a device retains and synchronizes, independent of ongoing user sessions. Its owner may select resources in their own subject/application namespaces, subject to administrator storage limits, and may deselect them. Deselecting removes only the local copy, not the resource itself.

## Residency

Residency is a device-local choice per filesystem path: Full or Passthrough. Full stores metadata and content locally; Passthrough stores metadata and reads content from an available Full peer but cannot write. Residency is not synchronized.

## File System

The File System is a local-first replicated storage engine for paths, metadata, and file content. It has no file permission bits, groups, or cross-user grants and is separate from application databases and IdP/management records.

## File Entry

A File Entry is metadata for one filesystem path, with a stable file ID, content revision, and provider information. Deletions are represented by synchronized metadata tombstones.

## Tombstone

A Tombstone is a synchronized deletion record that prevents a deleted file entry or storage resource from returning when an offline device reconnects.

## Repository Backend

A Repository Backend persists a service trait through the native replicated `ofdb` engine. CLI and desktop runtimes compose the native DB repositories directly.
