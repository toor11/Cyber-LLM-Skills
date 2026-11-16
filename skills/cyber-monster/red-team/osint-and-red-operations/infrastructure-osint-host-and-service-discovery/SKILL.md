---
name: infrastructure-osint-host-and-service-discovery
description: Host and service discovery via internet scanners. Covers Shodan and Censys style queries, favicon and banner correlation, and converting scanner data into a target list. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: osint-and-red-operations
tier: leaf
triggers: ["shodan query", "censys", "internet scanner", "banner search"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [infrastructure-osint, infrastructure-osint-dns-and-certificate, osint-methodology, corporate-and-person-osint]
parent: infrastructure-osint
---


# Infrastructure OSINT Host and Service Discovery - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Enumerating services on attributed addresses using internet-wide scan datasets rather than direct scanning: product and version banners, TLS certificate associations, favicon hashes, and JARM-style fingerprints. The advantage is that the data is historical and third-party, so discovery needs no traffic to the target, and the discipline is to treat a dataset record as an observation with a scan date rather than as live state.

- **Dataset records carry scan dates.** A banner from three months ago describes the host then; confirm current state before reporting a service as present.
- **Fingerprints are queries, not conclusions.** A favicon hash or JARM fingerprint finds sibling hosts; it does not by itself attribute them to the organisation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the dataset supports field selection **THEN** request only the fields the question needs, because large banner fields are truncated by default and inflate responses.
2. **IF** a fingerprint match spans prefixes **THEN** attribute only the hosts inside the organisation's announced ranges.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an attributed address range or a fingerprint, and a dataset query interface with known field semantics — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`infrastructure-osint`](../infrastructure-osint/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Internet-wide scan dataset queries with explicit field lists, plus certificate and favicon association; every record stored with its scan date
- **First Check:** `shodan host 203.0.113.10`

1. Confirm the target surface: the attributed prefix set or the fingerprint value, and which dataset interface answers the question.
2. Choose the branch: banner query for product and version, certificate association for co-hosted names, fingerprint query for sibling infrastructure.
3. Define the differential: compare the dataset record's scan date with a current observation; the differential is a service present now that the dataset recorded, or absent now despite a recent record.
4. Name the stop condition: a result cap and a scan-date floor, so old records do not enter the inventory.
5. Prove it: each service record carries the dataset, the scan date, the banner fields used, and the attribution evidence for the address.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Dataset scan date per banner` | Separates a historical observation from a current one; without it the inventory drifts from reality. |
| `Explicit field list in a query` | Avoids the truncation default that silently drops large fields such as page bodies. |
| `favicon hash or certificate association` | Finds sibling hosts that share an artefact, which is a discovery technique rather than an attribution proof. |
| `Announced-prefix filter on results` | Keeps attribution inside ranges the organisation actually announces. |

## Worked Contrast

**Inventory Built From Unfiltered Search Results:**

```text
Query the dataset for 'target' and list every host returned.
Report all hosts as target infrastructure.
# BUG: matches brand strings in page text on unrelated hosts, no scan date, no prefix filter
```

**Prefix-Filtered Query With Scan Dates and Field Discipline:**

```text
Query: net:198.51.100.0/24 product:nginx, fields: ip_str, port, product, version, timestamp.
Filter: keep records whose timestamp is within the last 90 days.
Confirm: current TLS handshake on port 443 returns the same product major version.
Attribute: address inside AS64500 announced prefix; certificate subject matches the registrant handle.
```

**Why this matters:** A brand-string search matches page text on hosts that merely mention the organisation, and an undated record may describe a service that was removed. Filtering by announced prefix, requesting explicit fields, and confirming one current observation ties the inventory to the organisation and to the present.

## When It Is NOT This Issue

- **Brand string in page text.** A host mentioning the organisation is not operated by it; require prefix and certificate evidence.
- **Record older than the engagement window.** An old banner describes a service that may no longer exist.
- **Fingerprint collision.** Popular frameworks share favicon hashes; a match is a lead, not an attribution.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `infrastructure-osint-host-and-service-discovery` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `infrastructure-osint-host-and-service-discovery` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: infrastructure-osint-host-and-service-discovery
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint-dns-and-certificate`](../infrastructure-osint-dns-and-certificate/SKILL.md) - OSINT and Red Operations (leaf)
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `infrastructure-osint-host-and-service-discovery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 26 |
| Distinct dataset sources | 7 |
| Top sources | osint-tool-database (16), CYBER_CPT/github_security_md (4), CYBER_CPT/ctftime (2), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 16 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
