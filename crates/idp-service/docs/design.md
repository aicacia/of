# IdP design

The IdP supports standard OAuth 2.0 and OpenID Connect clients alongside key-based identity and key rotation. Key identity remains separate from the IdP signer and the token subject. Definitions live in [the IdP glossary](../GLOSSARY.md); Installation and equal-Node ownership are defined by [system design](../../../docs/design.md).

## OAuth and OpenID Connect

Use conventional OIDC, not self-issued OIDC. The IdP signs access and ID tokens with its approved signing keys. Self-issued OIDC requires a different relying-party trust model.

Use standard authorization, token, userinfo, discovery, JWKS, PKCE, and refresh-token surfaces. Key-based authentication is not a replacement for the OAuth/OIDC protocol, and password authentication is not excluded.

## Identity and keys

Retain BIP32-style entity master keys and derived keys. Keep master keys private; do not expose them to relying parties. Per-client key choices must not replace the canonical User identity.

Tokens identify the Principal by its stable entity ID, not a raw public key or user-selected per-client key. Key rotation need not change the Principal's identity. A stable entity subject does not promise pairwise unlinkability across clients.

Keep private key material local. Public-key metadata alone is not signing capability. JWKS publishes approved IdP signing material, not user authentication keys. Private signing-key compromise affects issuer trust; Node Signer approval and revocation remain separate from User identity. Every Node uses an independent local private signer, not one shared private signer, as required by [system design](../../../docs/design.md#identity-and-grants). Approved public signer data can synchronize; revocation takes effect on each Node when learned.

## Local trust and grant lifecycle

Every Node may administer identity and perform OAuth/OIDC issuance and grant lifecycle operations after local actor/permission checks. Persist trusted identity, policy, approved signer state, and grant consumption so completed Nodes can operate and restart offline. There is no designated authority, privileged replica, promotion, or 30-second freshness requirement. Missing, invalid, or locally revoked trust denies; a partition by itself does not.

Consume authorization codes and rotate refresh tokens atomically and durably on the executing Node. Concurrent local requests have one winner, including after reopen. Partitioned Nodes do not have a global single-use guarantee. Reconcile approved grant state on reconnect without claiming that eventual convergence prevented earlier duplicate consumption. Define synchronized records explicitly; raw secrets and private signing material are never shared.

Check issuer, audience, use, lifetime, signature, approved signer, Principal, client, scope, and exact requested permission against trusted local state. An actor's identity is not the transport signer or a supplied header. Administration permission evaluation uses the Node's local Management context without a required remote service or recursive administration calls.

## Device membership and pairing

IdP owns Installation Device lifecycle and trusted endpoint binding; `of` authorizes approval and persists locally trusted approved/non-revoked membership. On startup it restores that membership into the Node's one shared `iroh-chain` endpoint allowlist and updates the set as changes are learned. Restart does not require a reachable peer or expiring trust lease.

Reuse `ofnet`/`iroh-chain` endpoint, pairing offer/reply, allowlist and routing mechanics rather than recreating them in IdP. Generic pairing admission is purpose-specific exchange, not Installation approval or general data/resource access. Check approver actor/action/target and Installation/Device/endpoint/independent signer binding before persisting membership. Endpoint admission is not token/Principal or resource authorization; learned revocation prevents subsequent operations even on existing connections through `of`'s execution checks. See [networking ownership, ofnet vocabulary and source interfaces](../../../docs/design.md#networking-composition-and-trust).

## Implementation and acceptance

These are target requirements, not proof of implementation. [The offline-first Nodes spec](../../../.scratch/offline-first-nodes/spec.md) and [ticket index](../../../.scratch/offline-first-nodes/map.md) track cutover, conflict handling, trusted peer synchronization, local grant atomicity, and partition acceptance. Superseded authority/replica test results are not acceptance of this design.
