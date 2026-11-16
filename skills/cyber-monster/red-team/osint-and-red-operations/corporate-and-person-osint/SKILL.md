---
name: corporate-and-person-osint
description: "Profiles organizations and people: employee enumeration, org structure, email patterns, social footprint and credential exposure. Use when preparing phishing, social engineering or a targeted assessment."
family: osint-and-red-operations
tier: core
triggers: ["person osint", "employee enumeration", "email pattern", "social media recon", "corporate osint"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, infrastructure-osint, red-team-operations-and-scoping, social-engineering-and-pretexting]
---


# Corporate and Person OSINT - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Building an organisation and people picture from public records: email address patterns inferred from published addresses, employee lists from team pages and conference material, reporting lines from filings and press releases, and social profiles tied to a verified identifier. The discipline is that a pattern is a hypothesis about a naming convention, and a single inferred address is an unverified guess.

- **A pattern needs at least two confirmed samples.** One published address suggests a convention; two from different people confirm it.
- **Attribution needs an identifier, not a name.** A profile is tied to a person by a verified work email, a badge photo in a company post, or a filing, never by a matching display name.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the email convention is inferred **THEN** label every generated address as unverified and never use one as evidence of employment.
2. **IF** a person appears in a filing **THEN** use the filing as the anchor and treat social profiles as corroboration, not the reverse.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an organisation anchor (domain, filing, or registry record) and at least two confirmed people records — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Registry and filing records as anchors, published team pages and conference material for people, and a provenance store for each observation
- **First Check:** `curl -sS https://rdap.example/domain/target.example | jq '.entities'`

1. Confirm the target surface: anchor the organisation on a registry record or a filing, and record its identifiers (registration number, LEI, domain).
2. Choose the branch: organisational mapping when the question is structure, people mapping when it is roles and contacts, and pattern inference when the question is address convention.
3. Define the differential: confirm the email convention against two independently published addresses, and treat a generated address as a probe whose differential is a delivery signal, not a fact.
4. Name the stop condition: a confirmed pattern plus a named role holder, or an explicit statement that only one sample exists.
5. Prove it: each person record carries the source of the role and the source of the identifier separately, and each inferred address is marked unverified.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Two confirmed published addresses` | Confirms a naming convention; one sample is a guess and three identical formats are still one observation if from one page. |
| `Registry or filing identifier for the organisation` | Anchors the entity so people and domains attach to a legal entity rather than to a name. |
| `Role source versus identity source` | Separates where the job title came from from where the person was identified, so each can be checked. |
| `Unverified flag on generated addresses` | Prevents an inferred address from entering a report as a fact. |

## Worked Contrast

**Address Pattern Applied as Fact:**

```text
Found one address: j.smith@target.example.
Assume firstinitial.lastname for everyone.
Generated: a.jones@target.example, m.brown@target.example.
# BUG: one sample, and the generated addresses are reported as staff contacts
```

**Pattern Confirmed by Two Independent Samples, Generations Labelled:**

```text
Sample 1: j.smith@target.example (published on the team page).
Sample 2: r.okafor@target.example (published in a conference programme, different page and date).
Convention: firstinitial.lastname@target.example - confirmed by two independent publications.
Generated for role holders with no published address: marked UNVERIFIED and excluded from the contact list.
```

**Why this matters:** A single address cannot distinguish firstinitial.lastname from firstname.lastname or from an alias scheme, so the generated set may be entirely wrong. Confirming with a second independent publication establishes the convention, and labelling the rest keeps inference out of the factual record.

## When It Is NOT This Issue

- **Namesake on a social platform.** A matching display name is not the same person; require a work identifier or a corroborating company post.
- **Former employee listed on a cached page.** Check the page date and the current team page before recording a role.
- **Generic mailbox read as a person.** `info@` and `sales@` are role mailboxes, not individuals.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `corporate-and-person-osint` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `corporate-and-person-osint` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: corporate-and-person-osint
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)
- [`ctf-and-lab-methodology`](../ctf-and-lab-methodology/SKILL.md) - OSINT and Red Operations (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `corporate-and-person-osint` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 1 |
| Top sources | osint-tool-database (16) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 0 cases |
| Grounding | multi-dataset corpus-grounded |
