---
name: active-directory-certificate-services-esc5-through-esc8
description: ADCS ESC5 to ESC8 CA and relay abuse. Covers CA-level permission flaws, EDITF_ATTRIBUTESUBJECTALTNAME2, NTLM relay to HTTP enrollment and certificate-based persistence. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["esc5 esc6 esc7 esc8", "adcs relay", "certificate persistence"]
cwe: [CWE-269]
owasp: []
attack: [T1649]
capec: [CAPEC-122]
related: [active-directory-certificate-services, active-directory-certificate-services-esc1-through-esc4, network-recon-and-port-scanning, service-enumeration]
parent: active-directory-certificate-services
---

# Active Directory Certificate Services Esc5 Through Esc8 - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md)

## Mechanism and Preconditions

The later ESC classes move the weakness off the template and onto the CA infrastructure. ESC5 is write access to the CA's AD objects, which lets a trustee control the CA itself. ESC6 is the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on the CA, which makes every template behave as though it allows a supplied subject. ESC7 is a CA role permission that lets a principal manage requests or certificates. ESC8 is the relay case: the HTTP enrollment endpoint accepts NTLM, so a coerced authentication can be relayed into a certificate request without any template misconfiguration.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the CA object or its container is writable by a non-tier-0 principal **THEN** ESC5; the trustee can change CA behaviour, so rank it as CA compromise
3. **IF** `EDITF_ATTRIBUTESUBJECTALTNAME2` is set on the CA **THEN** ESC6; every published template becomes ESC1-shaped, including ones that look safe
4. **IF** a principal holds `ManageCA` or `ManageCertificates` **THEN** ESC7; request approval and certificate management become available to that principal
5. **IF** an HTTP enrollment endpoint accepts NTLM **THEN** ESC8; the vehicle is relay, so pair with the coercion and relay skills
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-certificate-services-esc5-through-esc8` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The template itself supplies the subject | [`active-directory-certificate-services-esc1-through-esc4`](../active-directory-certificate-services-esc1-through-esc4/SKILL.md) | Template-level conditions |
| The CA needs checking for newer classes | [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) | ESC15, ESC16 and ESC17 |
| The relay is the mechanism | [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) | Relay target selection and signing state |
| A coerced authentication must be produced | [`ntlm-relay-and-coercion-coercion-primitives`](../ntlm-relay-and-coercion-coercion-primitives/SKILL.md) | Coercion primitives and preconditions |
| Need the class-level branch table first | [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the CA flags and the CA object's DACL together.** `certutil -getreg policy` shows the subject-name flag and the disable list; the DACL on the `pKIEnrollmentService` and certification-authority objects shows who can change them. ESC5 and ESC6 are both CA-level, so they are read from the same place.
2. **Enumerate the enrollment endpoints and their authentication.** HTTP enrollment (`/certsrv`), the certificate enrollment web service, and the NDES SCEP endpoint each have their own authentication. An endpoint accepting NTLM without Extended Protection is the ESC8 precondition.
3. **Check the CA role assignments.** `ManageCA` and `ManageCertificates` are CA security roles, not AD groups. A principal holding either can approve requests (ESC7), so read the CA's security descriptors rather than only AD group membership.
4. **Baseline against a hardened CA.** EPA enforced on all enrollment endpoints, `EDITF_ATTRIBUTESUBJECTALTNAME2` unset, CA objects writable only by tier-0, and no NTLM on HTTP enrollment. Each deviation maps to one ESC class.
5. **State the proof.** Proof is the CA registry flag, the CA object ACE, the endpoint's authentication configuration, or the CA role assignment — read from the live system, not inferred from a scan summary. For ESC8, the proof also needs the coerced authentication reaching the endpoint.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `EDITF_ATTRIBUTESUBJECTALTNAME2` in `certutil -getreg policy` | Proves ESC6: every template on that CA accepts a requester-supplied subject, regardless of its own flags; Windows Server CA. |
| `ManageCA` or `ManageCertificates` role assignment | Proves ESC7: the holder can approve pending requests or issue/revoke certificates; Windows Server CA. |
| Write ACE on the `pKIEnrollmentService` object | Proves ESC5: the trustee can change which templates the CA publishes; AD CS. |
| NTLM accepted by the `/certsrv` endpoint | Proves ESC8: a coerced authentication can be relayed into a certificate request; AD CS with the web enrollment role. |
| EPA (`Extended Protection for Authentication`) disabled | Proves the channel-binding check is absent, which is what makes the relay work; IIS hosting the enrollment endpoint. |

## Worked Contrast

**Weak configuration — web enrollment accepts NTLM with Extended Protection disabled:**

```powershell
# IIS on the CA: Windows Authentication enabled, Extended Protection off
# any coerced machine authentication can be relayed into /certsrv and a certificate issued
Get-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site' `
    -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name enabled
```

**Hardened configuration — EPA required, NTLM removed, and HTTP enrollment disabled where unused:**

```powershell
Set-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site' `
    -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name enabled -Value $true
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter 'system.webServer/security/ipSecurity' -Name allowUnlisted -Value $false
# and: appcmd set config /section:windowsAuthentication /extendedProtection.tokenChecking:Require
# verification: a relayed authentication now fails the channel-binding check
```

**Why this matters:** ESC8 needs an endpoint that accepts NTLM without channel binding, so the control is EPA plus protocol restriction at the endpoint, and the verification is the relayed authentication failing rather than the certificate being refused later.

## When It Is NOT This Issue

- **HTTP enrollment present but EPA enforced.** With Extended Protection required, a relayed NTLM authentication fails the channel-binding check; the endpoint existing is not the finding.
- **`EDITF_ATTRIBUTESUBJECTALTNAME2` set but no client-auth templates published.** The flag only matters where a certificate can be used for logon; check the published EKU set.
- **`ManageCertificates` held by a tier-0 group.** CA role assignments to Domain Admins are the default; the finding begins when a non-tier-0 principal holds them.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-certificate-services-esc5-through-esc8` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-certificate-services-esc5-through-esc8` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-certificate-services-esc5-through-esc8
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1649]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`active-directory-certificate-services-esc1-through-esc4`](../active-directory-certificate-services-esc1-through-esc4/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-certificate-services-esc5-through-esc8` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1649`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/oxdf (5), CYBER_CPT/github_security_md (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
