# Shared domain

Terms shared by IdP, Management, and Storage. See [the glossary map](GLOSSARY-MAP.md) for context terms, design, and contracts.

## Language

**Installation**:
A group of equal Nodes sharing a canonical identity issuer and trusted identity, policy, and resource data.

**Node**:
An independently usable Installation member hosting IdP, Management, and Storage, with its own local trusted state and private signer.
_Avoid_: Authority node, privileged replica, Storage-only Node

**Unified Host**:
The host composing a Node's IdP, Management, and Storage contexts while retaining separate domain and state ownership.

**User**:
An authenticated human subject with a stable public identity.

**Application**:
A logical product or resource identified by a stable URI. It groups OAuth Clients and scopes storage resources owned by a User; it is not an OAuth Client.

**Principal**:
The User or OAuth Client represented by a token's subject. A Node Signer identifies the issuing Node, while Device endpoint identity authenticates transport; neither is the token's subject.

**Device**:
An Installation member's persistent domain identity bound to a transport endpoint, with a locally supplied name, public key, and reachable address. It is pending, approved, or revoked and belongs to the User who introduces it; an endpoint alone is not an Installation Device or resource permission.

**Trusted Device**:
An approved, non-revoked Device eligible to participate in the mesh. Approval is transport trust, not user or resource authorization.

**Bootstrap Service**:
The coordinator that establishes the repeatable system baseline for a new Installation through separate IdP and Management owner operations.

**Installation Setup**:
The process that establishes a new Installation or joins it as an equal Node through a trusted peer.
_Avoid_: Master setup, primary-node setup

**Device Setup**:
The process that configures and later edits the data an Installation member stores locally after Installation Setup completes.
_Avoid_: Setup Mode, device initialization

**Reset Device**:
The operation that removes one runtime's local setup state, synchronized data, and Device identity, returning it to Installation Setup. It does not remove data from other Devices.

**Initial Administrator**:
The username/password User whose supplied credentials establish administrative access and whose explicit initial permissions are granted when a new Installation is established.
_Avoid_: Default admin, bootstrap admin

**Trusted Peer**:
An approved Node whose authenticated identity and permitted shared data are trusted within an Installation; it has no privileged writer role and is not merely a known mesh Peer.

**Device Pairing**:
A purpose-specific exchange used to establish approved Installation Device membership. Pairing is not a general resource-access grant.

Endpoint, Peer, Mesh, Broadcast, Direct Message, and Byte Stream retain their [ofnet definitions](../ofnet/GLOSSARY.md); they do not imply Installation membership or resource authorization.
