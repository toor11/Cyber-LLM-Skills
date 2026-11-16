---
name: third-party-and-vendor-risk
description: "Assesses third party risk: vendor security questionnaires, assurance evidence review and ongoing monitoring. Use when evaluating suppliers or outsourcers."
family: purple-team-and-program
tier: core
triggers: ["third party risk", "vendor assessment", "supplier security"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-437]
related: [purple-teaming-and-adversary-emulation, remediation-tracking-and-verification, security-program-and-control-frameworks, control-testing-and-audit-evidence]
---

# Third Party and Vendor Risk - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

Vendor risk is the management of a dependency you do not control: what the vendor can reach, what they promise, and how you would know if they stopped delivering. The useful assessment is specific to the access the vendor has - a payroll processor holding identity data is a different risk from a component supplier with no network path. Questionnaires are one input among several, and the strongest evidence is usually technical: the OAuth scopes granted, the network path open, and the data actually shared.

- **CWE-1357 framing:** reliance on an insufficiently trustworthy component, where trust spans security practice, updateability, and maintainability.
- Concentration risk is part of the assessment: ten vendors on one cloud provider is one outage, not ten independent ones.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the vendor supplies software you run **THEN** the SBOM and provenance side is in `dependency-and-package-risk-review`.
2. **IF** the vendor requires OAuth consent **THEN** check the scopes against the integration's actual need; consent grants are the most common over-permission.
3. **IF** the vendor suffered a breach **THEN** the supply-chain incident response playbook owns the response.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Classify the vendor by what they can reach.** Data class held, network path, identity integration, and whether they process on your behalf or only supply a product. The classification sets the assessment depth.
2. **Collect evidence that is hard to fake.** OAuth scopes actually granted, network flows observed, the data fields actually shared, and the vendor's current attestations with their dates. A questionnaire answer is corroboration, not evidence.
3. **Choose the branch on the access level.** Processing identity data takes the full assessment plus contract clauses; limited network access takes the technical-review branch; no-access supply takes the component-provenance branch.
4. **Define the baseline-vs-probe differential.** Baseline: the access you believe you granted. Probe: the access observed in the identity provider and network logs. The delta is the finding, and it is usually broader than intended.
5. **State the stop condition and the proof.** Stop when every vendor has a classification, observed access, an attestation with a date, and contract terms matching the access; proof is the scope or flow record, not the questionnaire.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| OAuth grant with write scopes where the integration only reads | Proves over-permission in the identity layer, which survives password rotation and MFA. |
| Vendor with a network path to a segment the integration does not need | Proves standing reach beyond the integration's function, usually from a legacy VPN or peering. |
| Attestation older than the vendor's own renewal cycle | Proves the assurance is historical; the report may not describe the current environment. |
| Contract without a notification clause for security incidents | Proves you would learn about a breach from the press rather than the vendor. |

## Worked Contrast

**Vendor assessment from a questionnaire score:**

```text
Vendor: payroll-processor
Questionnaire score: 82/100 (good)
Certifications: SOC 2 Type II reported (2023)
Data: employee records
Access: OAuth integration
Contract: standard terms
Decision: approved
Annual review: next year
```

**Assessment grounded in observed access with dated evidence:**

```text
Vendor: payroll-processor  Classification: processor of identity data (highest tier)
Data shared (verified from API logs, 2026-10): name, address, bank details, tax id, salary
  fields observed beyond the contract: date_of_birth added 2026-06 without change notice -> finding V-11

Identity access (verified in IdP, 2026-11-13)
  granted scopes: employees.read, payroll.write, webhooks.manage
  needed scopes : employees.read, payroll.write
  delta: webhooks.manage unused -> remove; ticket V-12

Network path (verified in flow logs)
  vendor egress to our API only via the integration subnet; no peering to HR segment

Assurance
  SOC 2 Type II period 2025-07..2026-06 (report dated 2026-08) - current
  ISO 27001 certificate expires 2027-03
  subprocessor list reviewed 2026-09: 2 new subprocessors disclosed, both approved

Contract
  breach notification within 72h (clause 9.2); audit right (clause 11); data deletion on exit (annex C)

Decision: approved with two findings (V-11 data minimisation, V-12 scope removal), review 2027-04
```

**Why this matters:** The first assessment rests on a self-reported score and a 2023 report, and never checks what access actually exists, so the findings that matter are invisible. The second verifies the data fields from API logs, the scopes from the identity provider, and the network path from flow logs, then records the deltas as findings - which is what makes the approval defensible.

## When It Is NOT This Issue

- **Vendor with no data access and no integration.** Component suppliers belong in provenance review; a full questionnaire adds no risk reduction.
- **Scope granted but never exercised.** Still a finding (remove it), but lower urgency than an exercised over-scope.
- **Attestation covering a period before a major acquisition.** The report may not describe the current entity; ask for a bridging letter or a newer report.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `questionnaire` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `third-party-and-vendor-risk` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: third-party-and-vendor-risk
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-693 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) - Purple Team and Program (core)
- [`remediation-tracking-and-verification`](../remediation-tracking-and-verification/SKILL.md) - Purple Team and Program (core)
- [`security-program-and-control-frameworks`](../security-program-and-control-frameworks/SKILL.md) - Purple Team and Program (core)
- [`control-testing-and-audit-evidence`](../control-testing-and-audit-evidence/SKILL.md) - Purple Team and Program (core)
- [`risk-assessment-and-treatment`](../risk-assessment-and-treatment/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `third-party-and-vendor-risk` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/go_exploitdb (2), CYBER_CPT/ctf_search (1), CYBER_CPT/expku (1), CYBER_CPT/pentest_partners (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
