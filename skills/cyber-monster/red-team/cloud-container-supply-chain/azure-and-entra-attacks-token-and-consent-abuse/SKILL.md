---
name: azure-and-entra-attacks-token-and-consent-abuse
description: Entra token acquisition and consent abuse. Covers illicit consent grants, token theft and refresh, device code flow abuse and primary refresh token handling. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["entra consent phishing", "illicit consent", "primary refresh token", "device code azure"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [azure-and-entra-attacks, azure-and-entra-attacks-rbac-and-managed-identity, cloud-recon-and-enumeration, aws-attacks]
parent: azure-and-entra-attacks
---

# Azure and Entra Attacks Token and Consent Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`saas-workspace-and-entra-unified-audit-forensics`](../../../blue-team/digital-forensics/saas-workspace-and-entra-unified-audit-forensics/SKILL.md)

## Mechanism and Preconditions

Consent abuse is the Entra-specific version of phishing, and it works because the consent is legitimate: a user grants a real application real delegated permissions, and from then on the attacker holds a refresh token that yields access tokens without any further authentication. The mechanism has three parts. The registration: an application in a tenant the attacker controls, or a multi-tenant application, with a `requiredResourceAccess` list that includes offline access plus a valuable scope (`Mail.Read`, `Files.ReadWrite.All`, `Contacts.Read`). The consent: an admin or user clicking through a real Microsoft consent screen, often via `adminconsent` for the tenant-wide variant. The token: the resulting refresh token, which the attacker's application can redeem indefinitely until the grant is revoked or a Conditional Access policy blocks the client. The related token-abuse forms are refresh-token theft from an endpoint that stores it, and primary-refresh-token theft from a device, which is what Token Protection is designed to defeat. The precondition for all of them is a user interaction plus the absence of a control that limits which applications can be consented to.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the finding involves an application consenting on a user's behalf **THEN** this is the skill; the grant object is the artefact, not the application.
2. **IF** the grant is `AllPrincipals` **THEN** the tenant-wide variant applies and the affected population is every user.
3. **IF** the scope includes `offline_access` **THEN** the attacker holds a refresh token, so revocation is the only remedy; say so explicitly.
4. **IF** the question is which control would have prevented it **THEN** check the user-consent policy and the admin-consent workflow setting, in that order.
5. **IF** the stolen artefact is a primary refresh token from a device **THEN** Token Protection is the control, and its absence is the finding.
6. **IF** the review is about application permissions rather than delegated ones **THEN** start at [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md); no user consent is involved.
7. **IF** the tenant restricts user consent to verified publishers with low-risk scopes **THEN** record the policy as the control with its exact scope list.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify which artefact the attacker holds.** A delegated grant, a refresh token, or a primary refresh token. Each has a different revocation path and a different detection signal.
2. **Trace the consent path.** Who consented, to which application, with which scopes, and whether an admin-consent workflow was involved. The audit record names all of it.
3. **Choose the branch.** Illicit consent grant, tenant-wide grant, refresh-token theft from an endpoint, or PRT theft from a device.
4. **Define the baseline-vs-probe differential.** Baseline: the grant list before the incident, or the tenant's consent policy settings. Probe: the grant that exists now, with its scope and consent type. The differential is the new grant plus the policy that would have blocked it.
5. **Name the stop condition.** Stop when the grant object is identified with its scope, principal, and consent type. Do not exercise the refresh token.
6. **State the proof.** Report the grant's `clientId`, `resourceId`, `scope`, `consentType`, the consenting principal, the timestamp, and the control that was absent. The remediation is revoke the grant, disable the application's service principal, and tighten the consent policy.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `Consent to application` audit event with `ConsentContext.IsAdminConsent: true` and `offline_access` | An admin granted a persistent delegated capability, which yields refresh tokens | Entra audit log |
| An `oauth2PermissionGrant` whose `clientId` belongs to a multi-tenant app outside the tenant | Illicit consent: the application is not one the tenant registered | Graph `oauth2PermissionGrants` |
| User consent policy set to `AllowUserConsentForAllApps` | Any application can be consented to by any user, which is the enabling setting | Entra authorisation policy |
| Admin-consent workflow configured with reviewers | The control that turns a consent attempt into a request | Entra admin consent workflow |
| Token Protection enforced on the device-bound PRT | Replay of a stolen PRT fails, which closes the device-theft branch | Conditional Access session control |
| A refresh token redeemed from an ASN the user never used | Token replay rather than consent abuse, but the same artefact class | Sign-in log `tokenIssuerType` and IP fields |

## Worked Contrast

**Vulnerable: tenant-wide admin consent to an unverified multi-tenant app, user consent unrestricted**

```text
# The authorisation policy allows any user to consent to any application, and an
# admin has granted tenant-wide delegated mail access to an app the tenant does not own.
GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy
{
  "defaultUserRolePermissions": { "permissionGrantPoliciesAssigned": [] },
  "allowInvitesFrom": "everyone"
}

GET https://graph.microsoft.com/v1.0/oauth2PermissionGrants
{
  "clientId": "9f1c...external-app", "consentType": "AllPrincipals",
  "scope": "openid offline_access Mail.Read"
}
```

**Hardened: user consent disabled, admin-consent workflow with reviewers, per-principal grant only**

```text
# Users cannot consent; requests go to a reviewer queue, and the only grant is
# scoped to a pilot group with the single scope the integration needs.
PATCH https://graph.microsoft.com/v1.0/policies/authorizationPolicy
{
  "defaultUserRolePermissions": {
    "permissionGrantPoliciesAssigned": ["managePermissionGrantsForSelf.microsoft-user-default-low"]
  }
}

GET https://graph.microsoft.com/v1.0/oauth2PermissionGrants
{
  "clientId": "9f1c...external-app", "consentType": "Principal",
  "principalId": "pilot-group-id", "scope": "Mail.Read"
}
```

**Why this matters:** The left state lets any user hand an external application persistent mailbox access, and the tenant-wide grant means one admin click covers every mailbox in the tenant. The right state removes the user's ability to consent, routes requests through reviewers, and limits the surviving grant to one group and one scope, so the same attack needs an approval rather than a click.

## When It Is NOT This Issue

- **A consent grant to a first-party Microsoft application or an approved internal one.** The grant exists by design; the finding would be an unexpected scope.
- **An `AllPrincipals` grant for `openid profile offline_access` with no data scope.** No data access, so the grant is a sign-in baseline.
- **A refresh token redeemed from the user's usual ASN and device.** Normal behaviour, not replay.
- **A user consent policy allowing low-risk scopes for verified publishers.** That is a deliberate, bounded setting.
- **An admin-consent workflow request that a reviewer denied.** The control worked; there is nothing to report.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `azure-and-entra-attacks-token-and-consent-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `azure-and-entra-attacks-token-and-consent-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: azure-and-entra-attacks-token-and-consent-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`saas-workspace-and-entra-unified-audit-forensics`](../../../blue-team/digital-forensics/saas-workspace-and-entra-unified-audit-forensics/SKILL.md) - Blue Detection/Defense Counterpart
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`azure-and-entra-attacks-rbac-and-managed-identity`](../azure-and-entra-attacks-rbac-and-managed-identity/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `azure-and-entra-attacks-token-and-consent-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/hacktricks_cloud (2), CYBER_CPT/blackhills (1), CYBER_CPT/wiz_research (1), CYBER_CPT/infocon (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
