# Owner-service authority and independent IdP replica signers

Use normal authenticated owner-service HTTP APIs in separate and unified deployments, with Management as the single RBAC authority and IdP as the identity owner. Unified hosts share one Iroh endpoint, not service repositories or authorization bypasses; first installation uses local owner operations rather than unauthenticated HTTP setup.

IdP replicas keep independent private signing keys and share a canonical issuer and approved public-signer registry. Copying signing secrets is rejected because device revocation cannot invalidate copied secrets; database-only bootstrap is insufficient because it does not establish signing capability.

One designated IdP authority handles identity mutations, authorization-code creation/redemption, and refresh rotation. Replicas may validate and issue client-credentials tokens only while authoritative security state is at most 30 seconds old. This avoids treating eventual database synchronization as single-use grant coordination; automatic authority promotion and broader replica user-token issuance are outside scope.

First installation grants explicit application/installation RBAC permissions and provisions distinct service relationships, including IdP→Management permission evaluation. Storage checks policy before each bounded synchronization operation; completed valid batches may remain after later failure. Clean installation is required, without migrations or compatibility paths.
