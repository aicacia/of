# Local identity, policy, signing, and grants

Every Node executes OAuth and identity operations against its own persistent trusted IdP state. There is no authority designation, promotion, freshness lease, or remote permission evaluator. OAuth configuration rejects the retired `role` field. Missing, corrupt, conflicted, unapproved, or locally revoked evidence still denies.

## Owner boundaries and administration

Authenticated IdP HTTP administration binds the verified User subject to the exact service audience, action, and target. Application-scoped requests must also match the actor's locally known client Application. `LocalPermissions` evaluates Management's own persistent store; IdP never reads Management repositories. Unified composition shares this evaluator with the local Management context. Standalone IdP can use a separate `management_data_dir`. Missing policy/grants or evaluation errors deny before owner mutations. The in-process owner service and repository APIs are trusted composition seams, not alternative unauthenticated administration endpoints.

Management's IdP HTTP relationship in unified composition points at the local IdP listener, not a remote authority. If that local context is unavailable, authentication still fails closed. Removing remote authority dependence does not mean operating without a functional local identity/policy context.

## Independent local signers

`NodeSignerBinding` identifies the local membership, signer key, and endpoint. `prepare_node_signer` persists independent private material in the local private-key repository and returns only a public JWK; it does not approve membership. Issuance requires an exact matching public approval and an active, approved Device bound to that endpoint. Native runtime construction rejects a signer bound to another injected endpoint.

Each operation rechecks persistent membership, Device, signer, conflict, issuer, approval, and expiry state. Loading private material derives the public point and compares it with the approved JWK. A missing local secret never triggers implicit replacement during issuance. JWKS publishes approved Node signers only, not User/Client authentication keys. JWT signature algorithm and key metadata are ES256K/secp256k1, not EdDSA. Signed access/refresh tokens also carry a required `principal_key_id` binding, independent of the Node signer ID, so locally learned authentication-root rotation/revocation rejects tokens bound to an old root. Tokens without the current binding are rejected; there is no legacy-token fallback. The token subject is independently resolved to a locally active User/Client and authentication root; a transport endpoint or signer key is not the Principal. Client, scope, use, issuer, audience, and lifetime checks remain mandatory.

Completed-node setup must persist the `local_signer` binding together with endpoint identity and local secure key storage. A Node without this configuration/trust cannot issue. Provisioning the binding in setup/join and real host restart qualification are downstream integration work; public metadata alone is never sufficient.

## Public security exchange contract

`PublicSecurityTable::columns` is an explicit **projection** contract. It does not authorize exporting opaque whole-table/whole-row CRDT documents that may contain excluded fields or history. `permits_record` rejects unknown fields, private JWK parameters (including private scalars embedded in JSON text), and raw code/token values masquerading as hashes. SQL schema/integrity/dependency checks and domain permission checks are additional requirements, not established by this projection predicate.

Allowlisted IdP data includes public Users, Applications, client registrations without secrets/verifiers, public authentication-key metadata, approved Device/membership/signer trust, consent metadata/revocation, and hashed authorization-code/refresh-grant lifecycle state. Credentials, password verifiers, client secret verifiers, enrollment secrets, private signers/master keys, raw passwords, raw codes, and raw tokens are excluded. Receiving public client data does not provide confidential-client authentication capability; required local credential material must be provisioned locally. Management separately allowlists roles, permissions, role-permission links, and User-role assignments in its own store.

`DbReplicaSignerRepo::is_trusted_peer` checks the caller-supplied **authenticated connection endpoint** against current local Installation/Device/signer trust. It is not authentication of a string received in a message, an actor claim, or a resource-access grant. The transport adapter must supply independently authenticated connection identity and repeat local admission/permission checks before actual application, including on already open connections. Configuration, convergence, pairing, and supplied JWKs do not establish provenance. Tickets 02/03 wire and qualify these contracts through public persistence/transport seams.

## Local consumption and reconnect

Authorization codes and refresh grants contain hashes, never raw grant credentials. Conditional local consumption/rotation has one concurrent local winner and persists across database reopen. Wrong client, redirect/PKCE, scope, Principal, signer, or signature evidence denies; authorization-code redemption checks local signing capability and issuance inputs before consumption.

Two disconnected Nodes with the same locally trusted grant may each consume it. Their independent successful decisions are accepted; neither a designated consumer nor a global lock is introduced. Different locally signed replacement tokens do not imply global single use. Reconnect cannot undo tokens already issued during a partition.

Unresolved security-row conflicts deny authentication/authorization/issuance. Authorized owner-local conflict resolution is audited and cannot resolve consumption or revocation back to null; conflicting lifecycle fields require a retained integer timestamp. Learned revocation or consumption prevents later local work. Other security conflicts require explicit authorized resolution, not silently trusting last-writer-wins ordering. The authenticated record import/reconciliation adapter and live reconnect/revocation integration remain downstream qualification, not guarantees inferred from CRDT convergence.

## Evidence boundaries

Domain tests use real owner repositories and services, separate local stores, and native database reopen. Local private-key persistence tests retain a test private-key store across reopen; they do not prove OS keyring behavior across process restart. Partition tests deliberately demonstrate two local refresh winners and subsequent local replay denial. The HTTP administration test retains actor/action/target/audience/impersonation denials while proving IdP administration continues after the Management HTTP listener stops, because local policy remains available. Full authenticated transport, completed-host setup/restart, and live partition/reconnect acceptance belong to the original offline-first Nodes tracker.
