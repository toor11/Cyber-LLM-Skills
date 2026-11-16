---
name: infrastructure-osint-dns-and-certificate
description: DNS and certificate intelligence. Covers passive DNS, certificate transparency mining, zone transfer attempts and historical record correlation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: osint-and-red-operations
tier: leaf
triggers: ["passive dns", "certificate transparency", "crt.sh", "dns history"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [infrastructure-osint, infrastructure-osint-host-and-service-discovery, osint-methodology, corporate-and-person-osint]
parent: infrastructure-osint
---


# Infrastructure OSINT DNS and Certificate - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Name-level infrastructure work: passive DNS history to see what a name used to resolve to, certificate transparency to see which names were ever issued certificates and by whom, and authoritative queries to confirm current state. The distinction that matters is between historical records, which explain change over time, and authoritative answers, which describe now.

- **History explains, authority decides.** A passive DNS record shows a past mapping; only the authoritative server's current answer describes the present.
- **Certificate fields are attribution evidence.** Subject, issuer, and issuance date together tie a name to an organisation and a time window, far better than the name alone.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a name appears only in historical records **THEN** check the authoritative NS before reporting it as an asset.
2. **IF** a certificate's issuer is a hosting provider's ACME account **THEN** treat the subject as a hosted name, not as proof of ownership.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a name set, an authoritative resolver path, and a certificate transparency interface that returns records — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

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

- **Pinned Inputs:** Authoritative DNS queries via `dig`, passive DNS and CT records as historical evidence, with the retrieval interface and date recorded per observation
- **First Check:** `dig +trace target.example`

1. Confirm the target surface: list the names in scope and record the authoritative nameservers for the parent zone.
2. Choose the branch: passive DNS history for change over time, certificate transparency for name discovery and issuance dates, authoritative query for current state.
3. Define the differential: compare the historical mapping with the current authoritative answer; the differential is the change, and a name that no longer resolves is a historical observation.
4. Name the stop condition: a name set that stops growing, and a query budget per resolver.
5. Prove it: each observation records the interface used (CT log, passive DNS provider, authoritative server), the timestamp, and the exact query.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `dig +trace for the delegation path` | Shows where authority actually lies, which is what makes a current answer trustworthy. |
| `Certificate subject, issuer, and notBefore` | Ties a name to an organisation and a time window; issuer identity separates hosted names from owned ones. |
| `Passive DNS first-seen and last-seen` | Explains when a mapping changed, which no single live query can show. |
| `Authoritative NS pair comparison` | Two domains sharing an unusual NS pair is a weak but useful association signal. |

## Worked Contrast

**Reporting a Historical Record as Current:**

```text
Passive DNS shows old.target.example -> 203.0.113.10 in 2021.
Report: the organisation operates 203.0.113.10.
# BUG: the record is four years old; the name may not exist and the address may belong to someone else
```

**History Recorded as History, Current State Confirmed:**

```text
Passive DNS (retrieved 2026-11-02): old.target.example -> 203.0.113.10, first seen 2021-03-04, last seen 2021-09-18.
Authoritative query (2026-11-02): old.target.example -> NXDOMAIN.
Certificate transparency: certificate for old.target.example issued 2021-02-27 by a public CA, expired 2021-05-28.
Finding: the name was active in 2021 and has been withdrawn; the historical address is not evidence of current operation.
```

**Why this matters:** A historical mapping describes a past state, and using it as current claims infrastructure the organisation may no longer control. Confirming NXDOMAIN against the authoritative server and pairing it with the certificate's validity window produces a defensible statement about when the name was active.

## When It Is NOT This Issue

- **Historical record read as current.** Always confirm with an authoritative query before reporting an asset.
- **Wildcard DNS making every name resolve.** Test a random label; if it resolves, the zone is a wildcard and name enumeration is meaningless.
- **CT record for a name the organisation never controlled.** Certificates can be requested by third parties for a name in some validation paths; check the issuer and the subject.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `infrastructure-osint-dns-and-certificate` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `infrastructure-osint-dns-and-certificate` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: infrastructure-osint-dns-and-certificate
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint-host-and-service-discovery`](../infrastructure-osint-host-and-service-discovery/SKILL.md) - OSINT and Red Operations (leaf)
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `infrastructure-osint-dns-and-certificate` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 35 |
| Distinct dataset sources | 11 |
| Top sources | osint-tool-database (16), CYBER_CPT/L5/ctf_search (5), OffsecCyber (4), CYBER_CPT/nuclei_templates (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 16 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
