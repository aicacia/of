# Identity Provider (IdP)

The identity and OAuth/OIDC authority for an Installation. Shared terms are defined in [the root glossary](../../GLOSSARY.md).

## Language

**Identity Provider (IdP)**:
The OAuth 2.0 and OpenID Connect authority for users, applications, clients, grants, signing-key metadata, Device enrollment, and IdP replica membership.

**Designated IdP Authority**:
The IdP member responsible for identity administration, signer approval, and single-use user-grant lifecycle within an Installation.

**IdP Replica**:
An authorized Installation member with replicated IdP state and its own approved signer. Replica membership is distinct from ordinary Device approval.

**Replica Signer**:
An approved signing identity held by an IdP member. It identifies the issuer member, not the User or service Principal represented by a token.

**Canonical Issuer**:
The stable identity of an Installation's token authority, shared by its IdP members and independent of their listener addresses.

**OAuth Client**:
A concrete web, native, or machine integration for an Application, with a client identity, redirect URIs, grant and response types, allowed scopes, and authentication configuration. Multiple clients may access the Application's resources when authorized by the same User.

**OAuth Consent**:
A User's approval for a client, redirect URI, and scope set. It determines whether authorization requires further user interaction.

**Authorization Code**:
A short-lived, single-use OAuth credential bound to its client, redirect URI, scopes, signing key, optional resource, PKCE challenge, and optional OIDC nonce.

**Access Token**:
A signed credential that authorizes an API request within its grant constraints.

**ID Token**:
A signed credential that conveys authenticated OIDC identity claims to a client.

**Refresh Token**:
A signed credential for obtaining replacement tokens under its original grant constraints.

**Key**:
Signing-key metadata describing its entity owner, derivation relationship and path, name, state, and validity period. Its public JWK may be published through JWKS.
