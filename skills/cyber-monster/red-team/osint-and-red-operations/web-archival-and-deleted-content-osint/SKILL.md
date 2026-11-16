---
name: web-archival-and-deleted-content-osint
description: Recovers historical and deleted web assets passively using Wayback Machine CDX APIs, Common Crawl index queries, `archive.today`, cached search snapshots, and historical `robots.txt`/`security.txt` diffs. Use when investigating removed pages or historical infrastructure changes.
family: osint-and-red-operations
tier: leaf
triggers: ["wayback cdx osint", "web archive investigation", "deleted page recovery", "common crawl osint"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Web Archival and Deleted Content OSINT - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Recovering content that is no longer live by querying web archives and crawler indexes, then reconstructing what changed and when. The CDX interface returns capture metadata (URL, timestamp, status, digest) which is the evidence; the archived body is the content. The discipline is that a capture describes the page at its timestamp, not the present.

- **CDX metadata is the finding's spine.** Timestamp, status code, and digest per capture let you show a change without relying on a rendered page.
- **Crawler indexes are complementary, not equivalent.** A crawl corpus may hold content the archive never captured, with a different retrieval date and licence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a URL 404s now **THEN** query the archive's CDX for captures and read the earliest and latest ones to bracket the change.
2. **IF** the page was JavaScript-rendered **THEN** expect the archive to hold the pre-render HTML, and check whether the content you need was ever in it.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the exact URL, the archive interface, and the date range of interest — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Archive CDX or Memento interfaces and a crawl index, with each capture's timestamp and digest recorded
- **First Check:** `curl -sS 'https://web.archive.org/cdx/search/cdx?url=target.example/pricing&output=json&limit=20'`

1. Confirm the target surface: the exact URL including query string, and the date range that brackets the change of interest.
2. Choose the branch: capture listing via CDX for change chronology, single-capture retrieval for content, and crawl index for content the archive lacks.
3. Define the differential: compare two captures' digests and their bodies; a digest change with an identical status brackets the change to a time window.
4. Name the stop condition: the earliest and latest captures within the range, or an explicit statement that the archive holds no capture.
5. Prove it: cite the capture timestamp, the digest, and the archived URL, so the claim can be reopened at the same point in the archive.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `CDX capture list with timestamp and digest` | The chronology; a digest change marks when content changed without needing to read every capture. |
| `Status code per capture` | Distinguishes a captured 200 from a captured 404, which is often the fact being proven. |
| `Memento or playback URL for a specific capture` | Addresses one point in time, so the citation is stable as the live site changes. |
| `Crawl index record with its own retrieval date` | Content the archive missed, with a date that may differ from any archive capture. |

## Worked Contrast

**Wayback Link Cited Without a Timestamp:**

```text
See web.archive.org for the old page.
Claim: the page said X in 2023.
# BUG: no capture timestamp, no digest, and the archive may have many captures with different content
```

**Specific Capture With Digest and Status:**

```text
CDX query for target.example/pricing, 2023-01-01..2023-12-31, output=json.
Capture 1: 20230314152211, status 200, digest ABC123.
Capture 2: 20230801101001, status 200, digest DEF456 (changed).
Quote from capture 1 playback URL; note the digest change brackets the edit between the two timestamps.
```

**Why this matters:** Pointing at an archive in general does not establish what the page said at a time, because the archive holds many captures with different content. Listing the captures with digests shows both the quoted content and when it changed, and the playback URL makes the citation stable.

## When It Is NOT This Issue

- **Latest capture read as the historical state.** The latest capture may be from last week; use the capture that brackets the period.
- **JavaScript-rendered content missing from a capture.** The archive stored pre-render HTML; absence there is not evidence the content never existed.
- **Archive blocking or exclusion.** Robots policy can prevent capture; an empty CDX may mean exclusion, not absence.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-archival-and-deleted-content-osint` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-archival-and-deleted-content-osint` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-archival-and-deleted-content-osint
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-archival-and-deleted-content-osint` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
