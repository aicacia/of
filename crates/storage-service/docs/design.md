# Storage design

Storage provides offline-first database and filesystem resources. Definitions live in [the Storage glossary](../GLOSSARY.md); service ownership and bounded synchronization requirements live in [system design](../../../docs/design.md). These are design requirements; [security and transport](security.md) distinguishes source-checked behavior from acceptance targets.

## Resource isolation

The Storage API owns multiple databases and filesystems per `(user subject, application_id)` namespace; OAuth Clients of the same Application share it. No other subject or Application may access or select those resources. Every file belongs to the namespace subject.

There are no cross-user grants, Unix permission bits, or Device-key delegation: they would add an authorization layer without another Principal who can use it. IdP-issued tokens bind subject, Application, audience, and API action limits such as read/write; these limits authorize API calls, not mesh synchronization. Iroh endpoints establish only transport identity. Services synchronize independently of user sign-in.

## Device ownership and resource selection

The introducing User owns a Device. An approved Device may store their namespace by default unless an administrator restricts it, but selection starts empty. The owner may choose which of their namespace's whole resources it stores, subject to administrator storage limits; they may always deselect. A `read`-only Storage token cannot enroll, select, deselect, or revoke.

IdP owns Device enrollment, approval, and revocation. Management owns administrator storage limits and resource selection/deselection. A regular User needs a distinct Management API permission and a matching Device-owner subject to change selection; administrator authority is separate.

Before selection, Management checks kind/ID/namespace through the existing Storage API GET route with a Storage read token bound to the Management actor's subject and Application. Unknown or unavailable resources fail closed, including while offline; the owner may still deselect. Management does not open filesystem catalogs. Selections are recorded as synchronized control-plane state. Concurrent selection and deselection resolve to deselection; a causally later selection may restore synchronization.

## Synchronization admission

Both peers must select the resource. Storage uses live authenticated Management APIs for admission, not a local replicated Management policy database. Management resolves approved endpoint identities through IdP and checks matching owners, storage limits, whole-resource selection, resource kind/ID, and namespace against the authenticated Device IDs. Peer handshake selection claims are not authoritative.

Global catalog metadata is not exposed to all mesh Devices; a signed-in owner lists only resources in their subject/Application namespace, and background services retain only selected-resource metadata. Administrative records remain separate.

## Cleanup and persistence

Revocation stops future authorized synchronization but cannot erase bytes already copied. Ownership transfer must clear selections and local copies before the new owner can select resources; offline Devices must not resume synchronization until reset. These are lifecycle requirements, not established cleanup guarantees for all runtimes.

A filesystem's Full/Passthrough residency is a separate local per-path choice. Resource deletion replicates a Tombstone; deselection only removes a local copy. Incompatible persisted formats fail without migration or automatic deletion.
