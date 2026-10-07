# IdP design

The IdP supports standard OAuth 2.0 and OpenID Connect clients alongside key-based identity and key rotation. Key identity remains separate from the IdP signer and the token subject. Definitions live in [the IdP glossary](../GLOSSARY.md); Installation and replica authority are defined by [system design](../../../docs/design.md).

## OAuth and OpenID Connect

Use conventional OIDC, not self-issued OIDC. The IdP signs access and ID tokens with its approved signing keys. Self-issued OIDC requires a different relying-party trust model.

Use standard authorization, token, userinfo, discovery, JWKS, PKCE, and refresh-token surfaces. Key-based authentication is not a replacement for the OAuth/OIDC protocol, and password authentication is not excluded.

## Identity and keys

Retain BIP32-style entity master keys and derived keys. Keep master keys private; do not expose them to relying parties. Per-client key choices must not replace the canonical User identity.

Tokens identify the Principal by its stable entity ID, not a raw public key or user-selected per-client key. Key rotation need not change the Principal's identity. A stable entity subject does not promise pairwise unlinkability across clients.

Keep private key material local. Public-key metadata alone is not signing capability. JWKS publishes approved IdP signing material, not user authentication keys. Private signing-key compromise affects issuer trust; Replica Signer approval and revocation remain separate from User identity. Replicas use independent private signers, not one shared private signer, as required by [system design](../../../docs/design.md#replica-authority).

## Implementation and acceptance

These are design requirements, not proof of implementation. For setup lifecycle, authority, and synchronization requirements, use the [unified service spec](../../../.scratch/unified-server/spec.md). Remaining work is in the [ticket index](../../../.scratch/unified-server/map.md); recorded results are in [implementation evidence](../../../.scratch/unified-server/evidence.md).
