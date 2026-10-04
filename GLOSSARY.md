# Installation authority

Terms for independent services, unified hosting, and joining installations. See `CONTEXT.md` for the wider domain model.

## Language

**Installation**:
A group of services and devices with one canonical identity issuer and one authoritative Management policy domain.

**Designated IdP Authority**:
The IdP member responsible for identity administration, signer approval, and single-use user-grant lifecycle within an Installation.

**IdP Replica**:
An authorized Installation member with replicated IdP state and its own approved signer. Replica membership is distinct from ordinary Device approval.

**Storage-only Node**:
An Installation member that stores selected resources and uses remote identity and policy authorities without hosting an IdP replica.

**Unified Host**:
A host that runs IdP, Management, and Storage together while retaining their separate authority and state ownership.

**Replica Signer**:
An approved signing identity held by an IdP member. It identifies the issuer member, not the User or service Principal represented by a token.

**Canonical Issuer**:
The stable identity of an Installation's token authority, shared by its IdP members and independent of their listener addresses.

**Application-scoped Permission**:
Authority for a named action within one Application; it grants no installation-wide authority.

**Installation-scoped Permission**:
Authority for a named action across an Installation, including administration of its infrastructure identities.

**Initial Administrator**:
The User granted explicit initial installation permissions when a new Installation is established.
