---
name: entra-id-and-hybrid-identity
description: "Attacks Microsoft Entra ID and hybrid identity: token theft, consent phishing, service principal abuse, password spray against cloud identities, and hybrid sync path abuse. Use when the identity provider is cloud-backed."
family: network-ad-and-endpoint
tier: core
triggers: ["entra id attack", "azure ad attack", "hybrid identity", "token theft", "consent phishing", "service principal"]
cwe: [CWE-287]
owasp: []
attack: [T1528]
capec: [CAPEC-560]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Entra Id and Hybrid Identity - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Hybrid identity joins an on-premises directory to a cloud tenant, and the join is a bridge with credentials on both sides: Entra Connect holds a synchronisation account with directory rights, the tenant trusts device certificates for hybrid join, and the authentication methods (password hash, pass-through, federation) each create a distinct path. Since 2025 the tradecraft has shifted from exporting the sync account's credentials — now certificate-based — to adding credentials to the sync application, and to device-code flows that produce a refresh token and then a Primary Refresh Token.

- **CWE-287 (Improper Authentication):** When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is on-premises to cloud **THEN** the sync account or the sync application registration is the bridge; read its credential and role state
2. **IF** the question is cloud to on-premises **THEN** a device certificate or a Primary Refresh Token is usually the pivot, because it satisfies device-based conditional access
3. **IF** the authentication method is federation **THEN** the token-signing certificate is the trust anchor; check its custody
4. **IF** the token comes from a device-code flow **THEN** the refresh token and the broker client id are the artefacts, and the device registration is the follow-on
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `entra-id-and-hybrid-identity` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The on-premises directory is the target | [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) | Directory objects and ACLs |
| The certificate authority is the trust anchor | [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) | Certificate issuance and templates |
| A captured token must be used | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | Reuse rather than acquisition |
| The entry point was a user | [`initial-access-via-phishing`](../initial-access-via-phishing/SKILL.md) | How the token was obtained |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the authentication method in force.** Password hash sync, pass-through authentication, or federation. Each has a different trust anchor, and the method determines which bridge object matters. This is readable from the tenant's domain configuration.
2. **Read the sync identity's credential and role state.** Whether the sync agent uses a user account or an app registration, which certificate is bound to it, and which directory role it holds. An application with `Application Administrator` reach is a broader path than the legacy sync account was.
3. **Establish the device-trust state.** Hybrid-joined devices carry a certificate on the computer object's `userCertificate` attribute, which the sync account can write. That write capability is the device-impersonation path, and it is readable from the attribute's ACL.
4. **Name the stop condition.** Stop at the first bridge object whose credential or role state permits a tenant-wide effect. Enumerating every hybrid object produces a large report without a clearer finding.
5. **State the proof.** Proof is the sync principal, its credential type and age, its role assignment, and — for the device path — the write ACL on `userCertificate` plus the resulting device registration. A token's existence is not proof of the path that produced it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Sync app registration with a certificate credential | Proves the modern bridge, where adding a credential rather than resetting a password is the abuse path; Entra ID with cloud sync or Connect sync. |
| `userCertificate` write on computer objects | Proves device-identity impersonation, which satisfies device-based conditional access; Entra ID hybrid join. |
| Federation token-signing certificate custody | Proves the trust anchor for federated domains, where a forged token needs no password; Entra ID with AD FS. |
| Refresh token issued to the broker client id | Proves a device-code flow that leads to a Primary Refresh Token and device registration; Entra ID. |
| Conditional access policy with a device filter | Proves the policy depends on device identity, which is exactly what the certificate path satisfies; Entra ID. |

## Worked Contrast

**Weak configuration — sync application holds a directory role with tenant-wide reach and its certificate is unmonitored:**

```powershell
Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Entra Connect Sync'" |
    Select-Object Id,AppId
# the app holds Application Administrator, and its certificate credential was added
# outside the installer, with no alert on credential addition
```

**Hardened configuration — least-privilege role for the sync app and alerts on credential addition:**

```powershell
# replace the broad directory role with the documented sync permissions
# and alert on Add servicePrincipal/certificates
Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Entra Connect Sync'" |
    Select-Object -ExpandProperty KeyCredentials
# verification: the role assignment is the narrow sync set and a test credential addition raises an alert
```

**Why this matters:** the bridge's reach is its role assignment and its credential custody, so the controls are role minimisation and alerting on credential changes, verified by an alert on a test addition.

## When It Is NOT This Issue

- **A sync account that exists with no directory role beyond sync.** The account is required; only excess role reach is a finding.
- **A device certificate present on a hybrid-joined computer.** That is the mechanism working as designed; the finding is who can write the attribute.
- **A refresh token in a legitimate device flow.** Interactive device-code sign-in is a supported flow; the finding is an anomalous client id or a token used from an unexpected location.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `entra-id-and-hybrid-identity` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `entra-id-and-hybrid-identity` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: entra-id-and-hybrid-identity
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287 | Mapping: T1528]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `entra-id-and-hybrid-identity` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, T1528`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 29 |
| Distinct dataset sources | 12 |
| Top sources | OffsecCyber (10), CYBER_CPT/hacktricks_cloud (5), cyber-security/security-code (2), bugbounty-hunter-v1 (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
