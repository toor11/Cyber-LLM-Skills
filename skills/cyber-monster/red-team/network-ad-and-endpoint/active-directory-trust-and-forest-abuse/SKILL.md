---
name: active-directory-trust-and-forest-abuse
description: "Abuses AD trusts between domains and forests: SID filtering gaps, trust key extraction, cross-domain group membership, and forest-level escalation paths. Use in multi-domain environments."
family: network-ad-and-endpoint
tier: leaf
triggers: ["ad trust", "forest trust abuse", "sid filtering", "trust key", "inter-domain escalation"]
cwe: [CWE-269]
owasp: []
attack: [T1134]
capec: [CAPEC-122]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
corpus_sparse: true
---

# Active Directory Trust and Forest Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A trust is an authentication relationship with a security boundary that is only as strong as its filtering. SID filtering removes the trusted domain's SIDs from the PAC across an external or forest trust, but it is not enabled by default for every trust type, and selective authentication changes whether a user from the other side can even authenticate to a given service. Trust key material is also a durable asset: a compromised trust password permits inter-realm ticket forgery for as long as the key is unchanged.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the trust is a forest trust with SID filtering enabled **THEN** the SID-history path is closed; look at the trust key and at selective authentication configuration instead
2. **IF** the trust is an external trust **THEN** SID filtering is applied by default for external trusts on modern Windows, so check the actual state rather than assuming either way
3. **IF** a trust key is held **THEN** inter-realm ticket forgery applies until the trust password is reset on both sides
4. **IF** selective authentication is on **THEN** a user from the trusted domain needs an explicit `Allowed to Authenticate` ACE on the target; enumerate those ACEs
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `active-directory-trust-and-forest-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The trust key is the asset | [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) | Key material and rotation |
| The path continues through a delegated service | [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) | Delegation across the boundary |
| Certificate trust crosses the boundary | [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) | CA trust and cross-forest issuance |
| The trust is only the discovery step | [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) | Domain and forest mapping first |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the trust object and its attributes.** `trustDirection`, `trustType`, `trustAttributes` and `trustAuthOutgoing`/`trustAuthIncoming` on the `trustedDomain` object. The `trustAttributes` flags encode quarantine, SID filtering and forest-transitive behaviour, and they decide which paths are open.
2. **Determine SID filtering and selective authentication state explicitly.** `netdom trust /domain:x /quarantine` and the `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN` flag give the SID-filtering state; selective authentication is a separate flag. Reporting 'trust abuse possible' without those two reads is not a finding.
3. **Establish which direction the authentication flows.** A one-way inbound trust lets the other domain authenticate here; a one-way outbound trust is the reverse. Path direction determines which side must be compromised first, so it belongs in the finding statement.
4. **Baseline against a hardened trust.** Quarantine enabled, selective authentication where the business case allows, and a trust password age within policy. Deviation is the finding, and each deviation maps to a specific technique.
5. **State the proof.** Proof is the trust attribute values, the SID-filtering state, and the direction, plus any `Allowed to Authenticate` ACE if selective authentication is on. The resulting technique is described in terms of which of those is absent.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `trustAttributes` flag `QUARANTINED_DOMAIN` | Proves SID filtering is enabled, which closes SID-history injection across that trust; any AD trust. |
| `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION` | Proves TGT delegation across the trust is permitted, which weakens the boundary considerably; forest trusts. |
| `trustDirection` value | Proves which side can authenticate where, the first fact any trust path depends on; any AD trust. |
| `Allowed to Authenticate` ACE on a target | Proves selective authentication is configured and names exactly which foreign principals may reach the service; AD with selective authentication. |
| `trustAuthIncoming` timestamp | Proves trust key age, which bounds how long a compromised key remains usable; any AD trust. |

## Worked Contrast

**Weak configuration — forest trust without quarantine, permitting SID history across the boundary:**

```powershell
netdom trust corp.example /domain:partner.example /quarantine
# Quarantine:Disabled, so a SID from the partner forest is accepted in a PAC here
# an account in the partner forest can assert Domain Admin of this forest via SID history
```

**Hardened configuration — quarantine enabled with selective authentication where the design allows:**

```powershell
netdom trust corp.example /domain:partner.example /quarantine:Yes /passwordt:*
netdom trust corp.example /domain:partner.example /enablesidhistory:No
# verification: the quarantine read returns Enabled and a cross-forest PAC with a foreign SID is rejected
```

**Why this matters:** the boundary is enforced by SID filtering and selective authentication rather than by the trust existing, so the `netdom` state is the control and a rejected foreign SID is the verification.

## When It Is NOT This Issue

- **A trust that exists but carries no authentication.** A defined trust with no `Allowed to Authenticate` ACE under selective authentication is a record, not a path; check the ACEs before reporting.
- **SID history from a documented migration.** Migration projects use SID history legitimately inside one forest; across a trust with quarantine enabled the SIDs are filtered regardless.
- **A trust to a decommissioned domain.** A stale trust object pointing at a domain that no longer exists cannot be abused but is a hygiene finding; verify the target domain resolves before ranking it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-trust-and-forest-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-trust-and-forest-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-trust-and-forest-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1134]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-trust-and-forest-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1134`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
