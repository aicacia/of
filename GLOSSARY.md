# Shared domain

Terms shared by IdP, Management, and Storage. See [the glossary map](GLOSSARY-MAP.md) for context terms and architecture decisions.

## Language

**Installation**:
A group of services and devices with one canonical identity issuer and one authoritative Management policy domain.

**Unified Host**:
A host that runs IdP, Management, and Storage together while retaining their separate authority and state ownership.

**Storage-only Node**:
An Installation member that stores selected resources and uses remote identity and policy authorities without hosting an IdP replica.

**User**:
An authenticated human subject with a stable public identity.

**Application**:
A logical product or resource identified by a stable URI. It groups OAuth Clients and scopes storage resources owned by a User; it is not an OAuth Client.

**Principal**:
The User or OAuth Client represented by a token's subject. A Replica Signer identifies the issuing IdP member, while Device endpoint identity authenticates transport; neither is the token's subject.

**Device**:
An Installation's persistent transport endpoint identity with a locally supplied name, public key, and reachable address. It is pending, approved, or revoked and belongs to the User who introduces it; Device identity is not resource permission.

**Trusted Device**:
An approved, non-revoked Device eligible to participate in the mesh. Approval is transport trust, not user authorization.

**Bootstrap Service**:
The coordinator that establishes the repeatable system baseline for a new Installation through separate IdP and Management owner operations.

**Installation Setup**:
The process that establishes a new Installation or joins an existing Installation in an explicit role.
_Avoid_: Master setup, primary-node setup

**Device Setup**:
The process that configures and later edits the data an Installation member stores locally after Installation Setup completes.
_Avoid_: Setup Mode, device initialization

**Reset Device**:
The operation that removes one runtime's local setup state, synchronized data, and Device identity, returning it to Installation Setup. It does not remove data from other Devices.

**Initial Administrator**:
The username/password User whose supplied credentials establish administrative access and whose explicit initial permissions are granted when a new Installation is established.
_Avoid_: Default admin, bootstrap admin

**Hosted Control Plane**:
The configured HTTP(S) authority a local runtime trusts for access-token verification and Trusted Device discovery.
