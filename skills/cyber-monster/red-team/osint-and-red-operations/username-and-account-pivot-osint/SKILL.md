---
name: username-and-account-pivot-osint
description: Correlates handles, usernames, avatars,PGP keys, and public commit emails across developer/social platforms while filtering false-positive handle collisions via creation dates, timezone cadence, and cross-linked bios. Use when pivoting from a single handle or commit author.
family: osint-and-red-operations
tier: leaf
triggers: ["username pivot osint", "maigret", "handle correlation", "commit email osint", "pgp key lookup"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Username and Account Pivot OSINT - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Pivoting from one account to others using artefacts that survive platform changes: the handle across services, commit author metadata, PGP key identities, and avatar perceptual hashes. The pivot is a hypothesis-generating step, so its output is a ranked candidate list with the signal behind each candidate, not a set of assertions.

- **Pivots generate candidates.** A pivot result is a lead; promoting a lead to a finding requires a second independent signal.
- **Absence is informative but not conclusive.** A service with no matching handle may have the person under a different name, so record the negative with the method used.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the handle appears on a technical platform **THEN** check commit metadata and keys before social platforms, because technical signals are harder to imitate.
2. **IF** a match is only an avatar **THEN** record it as a weak candidate and look for one corroborating artefact.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an anchor handle or identifier, and a defined candidate service list — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Handle enumeration against a fixed service list, git author metadata, keyserver lookups, and perceptual hashing, all written to a candidate table
- **First Check:** `git log --format='%ae %an' | sort -u`

1. Confirm the target surface: record the anchor handle and where it was first observed, with the observation date.
2. Choose the branch: technical pivot (commits, keys, certificates), platform pivot (handle across services), or artefact pivot (avatar, bio text).
3. Define the differential: for each candidate, name the second signal that would confirm it; the differential is whether that signal is present.
4. Name the stop condition: a candidate cap per service class and a rule that no candidate is reported above its signal strength.
5. Prove it: the candidate table records the service, the URL, the signal, and the strength, so a reviewer can re-check each lead individually.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Handle enumeration against a fixed service list` | Produces candidates at scale; the fixed list makes the coverage claim explicit. |
| `git commit author and email pair` | A technical signal that is difficult to imitate and carries timestamps. |
| `PGP key identity on a keyserver` | Ties an address to key material, which is a strong pivot anchor. |
| `Avatar perceptual hash` | Finds re-used imagery after re-encoding; weak alone, useful as corroboration. |

## Worked Contrast

**Pivot Output Treated as Findings:**

```text
Search handle 'nightowl' on 40 services.
Matches found on 9 services; report lists all 9 as the subject's accounts.
# BUG: no signal recorded, no strength, no attempt to distinguish coincidence
```

**Ranked Candidates With Signals and Strengths:**

```python
import json

candidates = [
    {"service": "code-host", "handle": "nightowl", "signal": "commit email == anchor", "strength": "strong"},
    {"service": "forum-a", "handle": "nightowl", "signal": "avatar phash == 95%", "strength": "weak"},
    {"service": "photo-site", "handle": "nightowl", "signal": "handle only", "strength": "weak"},
]
for c in candidates:
    c["status"] = "confirmed" if c["strength"] == "strong" else "candidate"
print(json.dumps(candidates, indent=2))
```

**Why this matters:** Nine handle matches of forty services is the expected base rate for a common handle, so the list says almost nothing. Attaching the signal and a strength to each candidate separates a commit-email match from a handle coincidence, and the confirmed set is then small enough to defend.

## When It Is NOT This Issue

- **Common handle with many matches.** Popular handles produce dozens of coincidental hits; require a second signal.
- **Service that reserves handles for unrelated purposes.** Some platforms assign handles automatically, so a match carries no information.
- **Cached profile page.** A deleted account's cached page describes the past; record the snapshot date.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `username-and-account-pivot-osint` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `username-and-account-pivot-osint` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: username-and-account-pivot-osint
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `username-and-account-pivot-osint` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
