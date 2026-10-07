# Management

The resource-policy and role-based access-control authority for an Installation. Shared terms are defined in [the root glossary](../../GLOSSARY.md). Service authority is described in [system design](../../docs/design.md); resource selection and admission are described in [Storage design](../storage-service/docs/design.md).

## Language

**Management Service**:
The single authority for an Installation's roles, permissions, assignments, resource restrictions, selections, and replication policy. Applications and Device identities belong to IdP.

**Permission**:
A named action with Application or Installation scope.

**Role**:
A group of explicit permissions whose assignments grant authority to a User.

**Application-scoped Permission**:
Authority for a named action within one Application; it grants no installation-wide authority.

**Installation-scoped Permission**:
Authority for a named action across an Installation, including administration of its infrastructure identities.

**Resource Selection**:
A whole-resource choice of what a Device retains and synchronizes, independent of ongoing user sessions. Its owner may select resources in their own subject/Application namespaces within administrator storage limits; deselection removes only the local copy, not the resource itself.
