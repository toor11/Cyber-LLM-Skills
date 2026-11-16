---
name: company-registry-and-beneficial-ownership-osint
description: Investigates corporate structures, subsidiaries, filings, and beneficial ownership across public registries (OpenCorporates, SEC EDGAR, GLEIF LEI, regional gazettes, and trademark/patent filings) to establish authorized asset ownership boundaries. Use during scoping, M&A due diligence, or vendor attribution.
family: osint-and-red-operations
tier: leaf
triggers: ["company registry osint", "opencorporates", "sec edgar osint", "beneficial ownership", "subsidiary mapping"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Company Registry and Beneficial Ownership OSINT - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Corporate structure work from official registries and identifiers: company registration numbers, legal entity identifiers (LEI), securities filings, and ownership disclosures. The discipline is jurisdictional — each registry publishes different fields, updates on its own schedule, and has its own definition of beneficial owner, so a conclusion must name the registry and the retrieval date.

- **The jurisdiction defines the field.** A shareholding threshold in one registry is not the same disclosure rule as another's, so compare like with like or state the difference.
- **An LEI is an identifier, not an ownership proof.** It resolves an entity globally; ownership still comes from a filing or a registry record.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is who owns an entity **THEN** name the registry and its disclosure threshold before answering, because below-threshold holders are absent by design.
2. **IF** two entities share a director **THEN** record it as an association and check whether the registry treats the role as a legal representative or a nominee.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a registration number or LEI, the registry that issued it, and the retrieval date — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** RDAP/registry JSON, `GLEIF` LEI records, and securities filings; each observation stored with the registry identifier and retrieval date
- **First Check:** `curl -sS 'https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=Target%20Holdings'`

1. Confirm the target surface: resolve the entity to a registration number and, where available, an LEI, and record which registry issued each.
2. Choose the branch: ownership disclosure for the beneficial-owner question, director history for control questions, and filings for financial or structural change.
3. Define the differential: compare the registry's current record with a filing from an earlier period; the differential is a change in ownership or officers, which is often the actual finding.
4. Name the stop condition: all disclosures above the registry's threshold, or an explicit statement that the registry does not publish beneficial ownership.
5. Prove it: each relation names the registry, the record identifier, the retrieval date, and the disclosure threshold that applies.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Registration number plus registry name` | The only unambiguous entity key; a company name alone collides across jurisdictions. |
| `LEI record with its own status and renewal date` | Resolves the entity globally and shows whether the reference data is current. |
| `Director or officer history with appointment dates` | Control questions are usually about change over time, not the current list. |
| `Registry disclosure threshold` | Determines what an absence of a named owner means, which is normally 'below threshold' rather than 'no owner'. |

## Worked Contrast

**Ownership Asserted From a Name Search:**

```text
Search the company name on a registry aggregator.
See one shareholder listed with 60%.
Conclude the entity is majority owned by that shareholder.
# BUG: aggregator may be stale, the threshold and jurisdiction are unstated, and the remaining 40% is unexamined
```

**Jurisdiction-Aware Ownership Record:**

```text
Entity: Target Holdings Ltd, registration 01234567, registry: national companies register (retrieved 2026-11-02).
LEI: 549300ABCDEF123456, status ISSUED, next renewal 2027-04-01.
Disclosure rule: shareholders above 25% must be disclosed.
Disclosed: Shareholder A 60% (appointed 2023-06-01), Shareholder B 30%.
Not disclosed: 10% held below threshold - recorded as unknown, not as absent.
```

**Why this matters:** The aggregator record does not state its jurisdiction or threshold, so the 60% figure cannot be interpreted and the remaining 40% is ignored. Naming the registry, the threshold, and the LEI status makes the ownership statement interpretable, and recording the sub-threshold remainder as unknown prevents an absence being read as no owner.

## When It Is NOT This Issue

- **Aggregator record read as registry record.** Aggregators lag and sometimes infer; confirm against the registry's own record.
- **Nominee director read as controller.** A nominee or corporate director is a legal role; control requires the ownership chain.
- **Absence of a disclosed owner read as no owner.** Most registries only disclose above a threshold; the remainder is unknown.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `company-registry-and-beneficial-ownership-osint` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `company-registry-and-beneficial-ownership-osint` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: company-registry-and-beneficial-ownership-osint
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `company-registry-and-beneficial-ownership-osint` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 2 |
| Top sources | osint-tool-database (16), osint-ctf-corpus-fr (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 1 cases |
| Grounding | multi-dataset corpus-grounded |
