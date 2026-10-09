# Identity Provider (IdP)

The identity and OAuth/OIDC context hosted by each Node of an Installation. Shared terms are defined in [the root glossary](../../GLOSSARY.md). OAuth/OIDC and key identity are described in [IdP design](docs/design.md).

## Language

**Identity Provider (IdP)**:
The OAuth 2.0 and OpenID Connect context for Users, Applications, clients, grants, signing-key metadata, and Device enrollment.

**Node Signer**:
An approved signing identity held independently by one Node. It identifies the issuing Node, not the User or service Principal represented by a token.
_Avoid_: Replica Signer

**Canonical Issuer**:
The stable issuer identity shared by an Installation's Nodes, independent of their listener addresses.

**OAuth Client**:
A concrete web, native, or machine integration for an Application, with a client identity, redirect URIs, grant and response types, allowed scopes, and authentication configuration. Multiple clients may access the Application's resources when authorized by the same User.

**OAuth Consent**:
A User's approval for a client, redirect URI, and scope set. It determines whether authorization requires further user interaction.

**Authorization Code**:
A short-lived OAuth credential consumed atomically once within a Node, without a global single-use guarantee during partitions, bound to its client, redirect URI, scopes, signing key, optional resource, PKCE challenge, and optional OIDC nonce.

**Access Token**:
A signed credential that authorizes an API request within its grant constraints.

**ID Token**:
A signed credential that conveys authenticated OIDC identity claims to a client.

**Refresh Token**:
A signed credential for obtaining replacement tokens under its original grant constraints.

**Key**:
Signing-key metadata describing its entity owner, derivation relationship and path, name, state, and validity period. Its public JWK may be published through JWKS.
