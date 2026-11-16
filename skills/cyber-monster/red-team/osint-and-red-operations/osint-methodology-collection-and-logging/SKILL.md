---
name: osint-methodology-collection-and-logging
description: OSINT collection and logging discipline. Covers building a repeatable collection plan with source registries, timestamps and provenance records. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: osint-and-red-operations
tier: leaf
triggers: ["osint collection plan", "source logging", "provenance"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, osint-methodology-verification-and-bias, corporate-and-person-osint, infrastructure-osint]
parent: osint-methodology
---


# OSINT Methodology Collection and Logging - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

The logging layer of an OSINT engagement: every retrieval produces a record with the source identifier, the exact query, the retrieval timestamp, the response hash, and the analyst, written at collection time so the trail exists before any analysis. This is what makes an assessment auditable and what lets a finding be retracted when a source changes.

- **Log the query, not just the answer.** A record without the query cannot be re-run, and registry responses vary by parameters in ways that change meaning.
- **Append-only beats editable.** A log that can be edited after the fact is not evidence; use an append-only table or a hash-chained log.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a source returns mutable data **THEN** store the raw payload hash beside the extracted fields, so extraction errors are distinguishable from source changes.
2. **IF** the record comes from a human source **THEN** log the channel, the time, and the exact wording, because paraphrase destroys the evidentiary value.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a defined record schema, an append-only store, and one retrieval logged end to end — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`osint-methodology`](../osint-methodology/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A record schema with `source`, `query`, `fetched_at`, `raw_sha256`, `analyst`, written on every retrieval; SQLite with WAL for concurrent collection
- **First Check:** `sqlite3 osint.db "SELECT COUNT(*) FROM obs WHERE fetched_at IS NULL;"`

1. Confirm the target surface: list the sources in scope and the fields each returns, so the schema can hold every source without lossy coercion.
2. Choose the branch: API collection (structured, hashable), page capture (store the rendered bytes), or human-source notes (verbatim text plus channel).
3. Define the differential: re-retrieve one record and compare hashes; an unchanged hash means the source is stable for the collection window, a changed hash means both observations must survive.
4. Name the stop condition: a per-source record cap and a collection window, both recorded, so coverage is explicit in the output.
5. Prove it: run a query that returns every observation for one entity with its source and timestamp, and confirm it reads as a defensible chain.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `raw_sha256 over canonical JSON` | Separates a source change from an extraction bug, which is the difference between a finding and a mistake. |
| `analyst column on every row` | Attributes each observation, which matters when more than one person collects. |
| `Append-only table with no UPDATE path` | Makes the log evidentiary; corrections are new rows referencing the old one. |
| `Collection window recorded per run` | Bounds the claim: an observation is true as of its retrieval time, not indefinitely. |

## Worked Contrast

**Logging After the Fact in a Document:**

```text
Notes: checked the registry, looks like the org is registered in 2019. Also saw some CT entries.
# BUG: no query, no timestamp, no hash, no source identifier; cannot be re-run or defended
```

**Record Written at Collection Time:**

```python
import hashlib, json, sqlite3, time

con = sqlite3.connect("osint.db", isolation_level=None)
con.execute("PRAGMA journal_mode=WAL")
con.execute("CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY, analyst TEXT, source TEXT, query TEXT, fetched_at TEXT, raw_sha256 TEXT, raw TEXT)")

def log(analyst, source, query, payload):
    raw = json.dumps(payload, sort_keys=True)
    con.execute("INSERT INTO log (analyst, source, query, fetched_at, raw_sha256, raw) VALUES (?,?,?,?,?,?)",
                (analyst, source, query,
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 hashlib.sha256(raw.encode()).hexdigest(), raw))

log("analyst-a", "rdap", "domain/target.example", {"handle": "EX-1"})
```

**Why this matters:** Notes written afterwards record an impression and lose the query, so nobody can tell whether the source was queried correctly or whether the answer changed. Writing the record during collection with the exact query, the timestamp, and the response hash produces a chain that survives challenge and supports retraction.

## When It Is NOT This Issue

- **Extraction error blamed on the source.** A field that looks different later may be a parsing bug; compare the stored hash before concluding the source changed.
- **Record with no analyst attribution in a team engagement.** Unattributed observations cannot be re-checked with the person who collected them.
- **Log written after analysis.** A log reconstructed from a draft report records the conclusion, not the observation.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `osint-methodology-collection-and-logging` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `osint-methodology-collection-and-logging` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: osint-methodology-collection-and-logging
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`osint-methodology-verification-and-bias`](../osint-methodology-verification-and-bias/SKILL.md) - OSINT and Red Operations (leaf)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `osint-methodology-collection-and-logging` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/nuclei_templates (7), CYBER_CPT/expku (2), CYBER_CPT/gh_advisories (2), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 6 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
