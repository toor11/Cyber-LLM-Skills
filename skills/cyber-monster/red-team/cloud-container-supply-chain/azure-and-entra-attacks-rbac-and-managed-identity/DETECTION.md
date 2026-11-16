# Detection Signals and Blue-Team Handoff

> Sub-skill: [`azure-and-entra-attacks-rbac-and-managed-identity`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Azure Activity log: `Microsoft.Authorization/roleAssignments/write` with a `properties.roleDefinitionId` in the privileged set.
- Entra sign-in log: a token issued to a managed identity's client id from an IP outside the resource's expected range.
- AKS audit log: a `patch` or `create` on `serviceaccounts` that adds the `azure.workload.identity/client-id` annotation.
- Key Vault diagnostic event: `SecretGet` by a managed identity that has never read that secret before.
- Azure Activity log: `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write`, which changes who can assume the identity.
- Defender for Cloud finding: an identity with owner-level permissions at subscription scope.
- Configuration drift: a role assignment created outside the pipeline's service principal.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
