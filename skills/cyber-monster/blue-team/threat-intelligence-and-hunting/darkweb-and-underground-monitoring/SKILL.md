---
name: darkweb-and-underground-monitoring
description: Monitors underground sources for leaked credentials, access sales and targeting discussions, with legal and operational safeguards. Use when credential or brand exposure monitoring is required.
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["darkweb monitoring", "underground monitoring", "leaked credentials monitoring"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management, threat-hunting]
---

# Darkweb and Underground Monitoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Underground monitoring looks for evidence that your organisation is being prepared against: credential listings, access broker posts, tooling sales, and data leak announcements. The programme is constrained by law and ethics before it is constrained by access, so the design questions are who may collect, what may be retained, and how a finding becomes a defensive action without touching the individuals involved. Most actionable output is credential exposure and initial-access brokerage, not actor gossip.

- **CWE-200 framing:** collected material frequently contains personal data of third parties; retention limits and handling rules are part of the control, not an afterthought.
- Access broker posts typically advertise the access method (VPN, RDP, web shell) alongside the victim profile, which is the detail that maps to a defensive control.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the finding is exposed credentials **THEN** open `compromised-credentials-and-token-revocation-playbook` for forced rotation and session revocation.
2. **IF** the finding is an announced data leak **THEN** the incident response extortion playbook owns the response; this skill owns the monitoring.
3. **IF** the collection would involve joining a closed community **THEN** stop and get legal and management approval in writing; participation changes the risk profile entirely.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Define the monitoring scope and the legal basis.** Organisation names, brands, domains, and executive names where a documented purpose exists. Record what may be retained and for how long.
2. **Monitor sources that are safe to access.** Public leak-site indexes, paste monitors, credential exposure services, and vendor reporting. Reading an index is materially different from joining a marketplace.
3. **Choose the branch on the finding type.** Credential exposure takes the rotate-and-revoke branch; access brokerage takes the exposure-validation branch; data leak announcement takes the incident-response branch with evidence preservation.
4. **Define the baseline-vs-probe differential.** Baseline: the same search for a control brand that is not yours. Probe: your brand. This distinguishes a genuine mention from a search artefact, since index coverage is uneven.
5. **State the stop condition and the proof.** Stop when each finding has a source, a retrieval date, a verification step, and an owner action; proof is the artefact plus the action record, and the individual-level data is minimised to what the action requires.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Credential listing containing a corporate domain and a valid-looking password format | Proves exposure worth forcing rotation on; the domain is the discriminator, not the email display name. |
| Access broker post advertising VPN access to a company matching your profile | Proves preparation against an organisation like yours; the advertised access method maps to a control to verify. |
| Leak-site announcement naming your organisation | Proves an extortion event, which is an incident rather than an intelligence item. |
| Mention in a control brand with no matching domain | Proves a search artefact; the control comparison is what prevents a false escalation. |

## Worked Contrast

**Monitoring that collects broadly and escalates mentions:**

```text
Monitor: all leak sites, all paste sites, keyword = company name
Findings this week:
- 3 mentions of the company name (2 unrelated, 1 unknown context)
- 1 credential list claimed to include our domain
Action: escalate all four to the SOC for review
Retention: indefinite, raw data stored on the analyst's workstation
```

**Scoped monitoring with verification, minimisation, and an action per finding:**

```text
Scope: domains example.com, example.net; brands 'Example', 'Exmpl'. Legal basis: brand protection
        and credential-exposure programme. Retention: 90 days for raw artefacts, actions recorded durably.
Collection: public leak-site indexes and credential-exposure service only. No community participation.

Finding D1 - credential list citing @example.com (1,412 entries, unverified)
  verification: 3 sampled addresses exist in the directory (existence only, no password test)
  action: forced password reset for the affected population + session revocation, ticket SEC-6702
  minimisation: stored counts and domain only; individual entries discarded after the reset

Finding D2 - access broker post: 'VPN access, EU manufacturer, 900 employees, $4k'
  verification: profile matches our sector and size band but not uniquely; no proof of our tenant
  action: verify MFA enforcement and anomaly alerting on all VPN concentrators (control check, not an incident)
  owner: network-security

Finding D3 - leak-site mention of 'Example' (context: a different company, same generic name)
  verification: control comparison against a genuine unrelated brand shows the same pattern
  action: none; recorded as a search artefact
```

**Why this matters:** The first programme collects everything, retains it indefinitely on a workstation, and escalates mentions, so the SOC receives noise and the organisation holds personal data it has no basis for. The second scopes collection, verifies without testing credentials, minimises what it retains, and produces three different actions - one of which is correctly no action.

## When It Is NOT This Issue

- **Company name matching a generic word.** Use the domain as the discriminator; a name-only match is an artefact.
- **Credential list dated years ago.** Still worth a forced reset if the password policy has not changed, but not an incident.
- **Access broker post without a unique identifier.** It is a sector signal, not a compromise of your tenant; verify controls rather than declaring an incident.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `credential leak` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `darkweb-and-underground-monitoring` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: darkweb-and-underground-monitoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`hypothesis-driven-hunting`](../hypothesis-driven-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `darkweb-and-underground-monitoring` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 24 |
| Distinct dataset sources | 5 |
| Top sources | osint-tool-database (16), CYBER_CPT/gh_advisories (3), hackerone_disclosed_reports (2), CYBER_CPT/osv (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
