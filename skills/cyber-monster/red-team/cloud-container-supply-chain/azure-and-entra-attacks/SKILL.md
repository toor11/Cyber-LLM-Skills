---
name: azure-and-entra-attacks
description: "Assesses and exploits Azure and Entra ID: token acquisition and refresh, service principal and managed identity abuse, RBAC weaknesses and storage exposure. Use when the target runs on Azure."
family: cloud-container-supply-chain
tier: core
triggers: ["azure attack", "entra id attack", "azure pentest", "managed identity", "service principal abuse"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [azure-and-entra-attacks-token-and-consent-abuse, azure-and-entra-attacks-rbac-and-managed-identity, cloud-recon-and-enumeration, aws-attacks]
---

# Azure and Entra Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`saas-workspace-and-entra-unified-audit-forensics`](../../../blue-team/digital-forensics/saas-workspace-and-entra-unified-audit-forensics/SKILL.md)

## Mechanism and Preconditions

Entra ID review is the study of what a token proves and what it does not. An access token carries a `tid` (tenant), an `oid` (object id), an `appid`, roles or scopes, and a lifetime; it does not carry the policy under which it was issued, so a token stolen after a Conditional Access check remains valid until it expires or until something revokes it. That gap is what continuous access evaluation closes: CAE-aware clients subscribe to critical events — user disabled, password reset, MFA enabled, refresh tokens explicitly revoked, high user risk — and re-evaluate within minutes rather than at the next refresh. The other half of the review is the consent and permission model: an application's `requiredResourceAccess` in the manifest is a request, a `servicePrincipal` `appRoleAssignment` is a grant, and an `oauth2PermissionGrant` is a delegated grant that survives the user who consented — the `OAuth2PermissionGrant` object with `consentType: AllPrincipals` is the tenant-wide version that shows up in every over-consent review. Token Protection, a Conditional Access session control that requires device-bound primary refresh tokens, is the current answer to token replay on supported platforms.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the finding is an over-privileged application **THEN** distinguish the manifest request from the actual grant; the `appRoleAssignment` and the `oauth2PermissionGrant` are the grants and the manifest is not.
2. **IF** a grant has `consentType: AllPrincipals` **THEN** every user in the tenant is affected, which is the tenant-wide over-consent finding.
3. **IF** the question is token replay **THEN** check whether Token Protection is enforced on the app and whether the client uses a device-bound primary refresh token.
4. **IF** the question is revocation latency **THEN** check whether CAE is in use for the resource; a non-CAE client keeps its token for its full lifetime regardless of policy.
5. **IF** the identity is a managed identity or a service principal **THEN** switch to [`azure-and-entra-attacks-rbac-and-managed-identity`](../azure-and-entra-attacks-rbac-and-managed-identity/SKILL.md).
6. **IF** the mechanism is consent phishing or an illicit consent grant **THEN** switch to [`azure-and-entra-attacks-token-and-consent-abuse`](../azure-and-entra-attacks-token-and-consent-abuse/SKILL.md).
7. **IF** the tenant has no CAE-capable client for a sensitive resource **THEN** the finding is the revocation gap, and the proof is a token that survives a disable.
8. **IF** every grant is a specific principal with a scope the application needs **THEN** record `Verified Safe` with the grant list.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `azure-and-entra-attacks-token-and-consent-abuse` | [`azure-and-entra-attacks-token-and-consent-abuse`](../azure-and-entra-attacks-token-and-consent-abuse/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `azure-and-entra-attacks-rbac-and-managed-identity` | [`azure-and-entra-attacks-rbac-and-managed-identity`](../azure-and-entra-attacks-rbac-and-managed-identity/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Decide whether you are reviewing a token, a grant, or a policy.** A token review asks what it carries; a grant review asks who consented to what; a policy review asks what would have blocked it. Mixing them produces findings that no one can action.
2. **Enumerate the grants, not the requests.** `servicePrincipal.appRoleAssignments` for application permissions, `oauth2PermissionGrants` for delegated ones, and `appRoleAssignedTo` for the reverse direction. The manifest's `requiredResourceAccess` is a wish list.
3. **Choose the branch.** Tenant-wide delegated grant, high-privilege application role, missing CAE for a sensitive resource, or missing Token Protection for a replayable client.
4. **Define the baseline-vs-probe differential.** Baseline: a token issued to a compliant client for the resource, with the grant list recorded. Probe: the same token used after the user is disabled or the password reset, against a CAE-aware and a non-CAE resource. The differential is whether the probe is rejected and how long it takes.
5. **Name the stop condition.** Stop at the first grant that exceeds the stated need, or the first token that remains usable after a revocation event. Do not replay a token against production data.
6. **State the proof.** Report the object id, the grant type, the scope or role, the affected principal count, and the control that is missing (CAE, Token Protection, an access review). If every grant is scoped and every client is CAE-aware, record the negative with the evidence.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `oauth2PermissionGrant` with `consentType: AllPrincipals` and `Mail.Read` | Tenant-wide delegated read of every mailbox, granted once and surviving the consenting user | Microsoft Graph, Exchange Online |
| `appRoleAssignment` for `Directory.ReadWrite.All` on a service principal | Application-level directory write without a signed-in user, which is a persistence path | Entra app registrations |
| A `requiredResourceAccess` entry with no matching assignment | The manifest asks for more than was granted, which is a review flag but not the grant | App manifest review |
| Token Protection enforced with a device-bound PRT | Replay from another device is blocked, which is the control for stolen tokens | Conditional Access session controls |
| A CAE-aware client on a resource with critical-event evaluation | Revocation takes effect in minutes instead of at token expiry | Exchange Online, SharePoint Online, Teams, Graph |
| A token with a 28-hour lifetime in a CAE session | Long lifetime is safe only because CAE drives revocation; without CAE it is a finding | CAE-negotiated sessions |

## Worked Contrast

**Vulnerable: tenant-wide delegated grant plus a non-CAE resource on a sensitive app**

```powershell
# Every user in the tenant can read every mailbox, granted once, and the token that
# carries it stays valid until expiry because the resource is not CAE-aware.
New-MgOauth2PermissionGrant -BodyParameter @{
  clientId    = $appObjectId
  consentType = "AllPrincipals"
  resourceId  = $graphServicePrincipalId
  scope       = "Mail.Read User.Read.All"
}
```

**Hardened: per-principal delegated grant scoped to what the app needs, with CAE and Token Protection**

```powershell
# The grant names one principal and one scope, and the Conditional Access policy
# enforces Token Protection so a stolen token cannot be replayed elsewhere.
New-MgOauth2PermissionGrant -BodyParameter @{
  clientId    = $appObjectId
  consentType = "Principal"
  principalId = $pilotGroupId
  resourceId  = $graphServicePrincipalId
  scope       = "Mail.Read"
}

New-MgIdentityConditionalAccessPolicy -BodyParameter @{
  displayName = "Require token protection for mail"
  state       = "enabled"
  conditions  = @{ applications = @{ includeApplications = @("00000002-0000-0ff1-ce00-000000000000") } }
  grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
  sessionControls = @{ signInFrequency = @{ isEnabled = $true; value = 1; type = "hours" } }
}
```

**Why this matters:** The left grant is tenant-wide and permanent: every mailbox is readable by the application on behalf of every user, and a stolen token works because nothing revokes it early. The right grant limits consent to one group and one scope, and the session control bounds the window in which a stolen token is useful.

## When It Is NOT This Issue

- **An `AllPrincipals` grant for `User.Read` or `openid`.** These are baseline scopes that every sign-in needs; tenant-wide consent for them is not the finding.
- **A manifest requesting high privileges with a matching assignment to a single group.** The grant is scoped even though the request is broad; report the request as a review note.
- **A token that survives a password reset on a resource that is not CAE-aware, when the resource is not in the sensitive tier.** The behaviour is documented; the finding needs sensitivity.
- **A long token lifetime in a CAE session.** CAE is precisely what makes the long lifetime safe.
- **An application permission granted to a first-party Microsoft service principal.** Microsoft's own permissions are not a customer over-grant.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `azure-and-entra-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `azure-and-entra-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: azure-and-entra-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`saas-workspace-and-entra-unified-audit-forensics`](../../../blue-team/digital-forensics/saas-workspace-and-entra-unified-audit-forensics/SKILL.md) - Blue Detection/Defense Counterpart
- [`azure-and-entra-attacks-token-and-consent-abuse`](../azure-and-entra-attacks-token-and-consent-abuse/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`azure-and-entra-attacks-rbac-and-managed-identity`](../azure-and-entra-attacks-rbac-and-managed-identity/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `azure-and-entra-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 10 |
| Top sources | CYBER_CPT/gh_advisories (2), cyber-security/security-code (1), OffsecCyber (1), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
