---
name: physical-and-facility-osint
description: "Gathers physical and facility intelligence: geolocation from imagery, business registration, facility and access observations, and physical entry prerequisites. Use when physical access or site targeting is in scope."
family: osint-and-red-operations
tier: leaf
triggers: ["physical osint", "geolocation", "facility recon", "site intelligence"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Physical and Facility OSINT - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Describing a physical site from public sources: imagery, business registrations at the address, planning and permit records, and transport or utility data that indicates activity. The work is documentary — the goal is an accurate description of the site and its occupants, not an assessment of how to enter it.

- **The address is the key, not the name.** Registration records are keyed by address, so resolving the address reveals every entity registered there, including ones absent from the target's own material.
- **Imagery has dates.** Satellite and street imagery are captured at specific times; a description of the site must state the imagery date it rests on.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is who occupies a site **THEN** query the address in the business register and compare the entity list with the target's claims.
2. **IF** the question is what the site looks like **THEN** record the imagery provider and capture date for every view used.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a resolved street address and at least one dated source describing the site — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Address-keyed registry queries, planning or permit records, and dated imagery; every observation stored with provider and capture date
- **First Check:** `curl -sS https://rdap.example/entity/01234567 | jq '.entities'`

1. Confirm the target surface: resolve the address to a canonical form with postcode and, where available, a coordinate, and record the source of the resolution.
2. Choose the branch: occupancy analysis via registrations, change analysis via planning records, and layout description via dated imagery.
3. Define the differential: compare the entity list at the address now with an earlier register snapshot or permit record; the differential is an occupant or structure that changed.
4. Name the stop condition: every entity registered at the address either identified or explicitly unresolved.
5. Prove it: each claim names the register or record, the retrieval date, and the imagery capture date, so a reader can tell how current the description is.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Address-keyed entity search` | Reveals occupants that the target's own material omits, which is often the finding. |
| `Planning or permit record with a decision date` | Documents structural change and its timing from an official source. |
| `Dated satellite or street imagery` | Describes the site as of a stated capture date; undated imagery is not evidence. |
| `Registered office versus operating site` | A registered office is a legal address and may be an accountant's premises, not an operating facility. |

## Worked Contrast

**Site Description From the Company Website Only:**

```text
The website says the company operates a warehouse at Unit 5, Industrial Estate.
Report: facility at Unit 5, single tenant.
# BUG: no register query, no imagery date, no check for other entities at the address
```

**Address-Keyed Occupancy With Dated Sources:**

```text
Address: Unit 5, Example Industrial Estate, AB1 2CD (resolved from the register, retrieved 2026-11-02).
Register at this address: Target Logistics Ltd; Northgate Storage Ltd; and a dissolved entity (2022).
Planning record: change of use approved 2024-05-14 for unit 5 (retrieved 2026-11-02).
Imagery: provider capture 2026-03-11 shows three loading bays and a fence line.
Conclusion: multi-occupancy site; the target occupies part of the unit.
```

**Why this matters:** The website describes the company's own claims and misses the other entity registered at the same address, which changes the description of the site. Querying the address in the register and dating the imagery produces a statement about occupancy and structure that a reader can check, with the capture date making clear how current it is.

## When It Is NOT This Issue

- **Registered office treated as an operating site.** Many entities register at an accountant's or agent's address.
- **Undated imagery used as current.** Imagery can be years old; the capture date is part of the claim.
- **Address match across postcode variants.** The same street exists in multiple postcodes; resolve to a coordinate before merging records.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `physical-and-facility-osint` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `physical-and-facility-osint` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: physical-and-facility-osint
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `physical-and-facility-osint` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 40 |
| Distinct dataset sources | 11 |
| Top sources | osint-tool-database (16), OffsecCyber (10), SecEval/owasp_mastg (3), CYBER_CPT/nuclei_templates (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 16 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
