# OIDC and key-based identity

## Status

Accepted. Consolidates the retained protocol and key decisions from the earlier IdP ADR. Installation and replica authority are defined by [system ADR 0002](../../../../docs/adr/0002-service-authority-and-replica-boundaries.md).

## Context

The IdP must support standard OAuth 2.0 and OpenID Connect clients while supporting key-based identity and key rotation. Key identity must remain separate from the IdP signer and the token subject.

## Decision

- Use conventional OIDC, not self-issued OIDC. The IdP signs access and ID tokens with its approved signing keys.
- Retain BIP32-style entity master keys and derived keys. Keep master keys private; do not expose them to relying parties. Per-client key choices must not replace the canonical User identity.
- Tokens identify the Principal by its stable entity ID. The earlier proposal to use user-selected per-client keys as pairwise subjects is not the current subject model.
- Use standard authorization, token, userinfo, discovery, JWKS, PKCE, and refresh-token surfaces. Key-based authentication is not a replacement for the OAuth/OIDC protocol, and password authentication is not excluded.
- Keep private key material local. Public-key metadata alone is not signing capability. JWKS publishes approved IdP signing material, not user authentication keys.

## Consequences

Key rotation need not change the Principal's identity. A stable entity subject does not promise pairwise unlinkability across clients. Private signing-key compromise affects issuer trust; replica signer approval and revocation remain separate from User identity.

## Alternatives

- Self-issued OIDC: rejected because it requires a different relying-party trust model.
- Raw public keys as subjects: rejected because key rotation would change identity.
- One shared private signer for replicas: rejected by system ADR 0002.

For setup lifecycle, authority, and synchronization requirements, use the [unified service spec](../../../../.scratch/unified-server/spec.md). Remaining work is in the [ticket index](../../../../.scratch/unified-server/map.md); recorded results are in [implementation evidence](../../../../.scratch/unified-server/evidence.md).
