---
name: osint-identity-and-email-correlation
description: "Correlates identities across platforms: username enumeration, email and phone exposure, breach data lookup and avatar reverse search. Use when you have one identifier and need a broader profile."
family: osint-and-red-operations
tier: leaf
triggers: ["username correlation", "email lookup", "breach data", "identity correlation"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# OSINT Identity and Email Correlation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Correlating accounts, addresses, and identities across services using identifiers that survive reuse: a verified email, a PGP key fingerprint, a commit author email, an avatar's perceptual hash, and a handle used consistently. The method is to establish one strong anchor and then test candidate links against it, rather than merging every profile that shares a username.

- **Handles are not identifiers.** The same handle on two services is a candidate link until a second signal (same PGP key, same commit email, same avatar hash) confirms it.
- **Breach data is corroboration, not proof.** A record in a breach corpus shows the address existed at a time; it does not prove who controlled it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** two accounts share only a handle **THEN** record a candidate link and look for a commit, key, or avatar match before promoting it.
2. **IF** the anchor is an email address **THEN** check for a PGP key and a git commit author before searching social platforms.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — one strong identifier (verified email, key fingerprint, or commit author) and candidate accounts to test against it — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Key servers and commit metadata as anchors, perceptual hashing for avatars, and a provenance store recording each candidate link separately from confirmed ones
- **First Check:** `gpg --search-keys user@target.example`

1. Confirm the target surface: establish the anchor identifier and record where it was observed and when.
2. Choose the branch: technical correlation (keys, commits, certificates) when the anchor is technical, platform correlation when it is a handle, and avatar correlation when the only shared artefact is an image.
3. Define the differential: test each candidate against a second signal; a candidate that matches only the handle stays a candidate, one that matches the key or commit email is confirmed.
4. Name the stop condition: two independent signals per confirmed link, or an explicit candidate-only status.
5. Prove it: each link records both signals with their sources, and each unconfirmed candidate is listed separately so it cannot be read as confirmed.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `PGP key fingerprint matching an email` | A strong anchor: key material is not casually reused across unrelated people. |
| `git commit author email and name pair` | Correlates a developer identity with an address across repositories, with timestamps as evidence. |
| `Avatar perceptual hash across platforms` | Detects re-used imagery even after re-encoding, which is a second signal when no technical identifier exists. |
| `Candidate versus confirmed link tables` | Keeps an unverified handle match from being reported as an identity. |

## Worked Contrast

**Merging Every Profile With the Same Handle:**

```text
Handle 'nightowl' found on forum-a, forum-b, and a code host.
Conclusion: one person, same individual across all three.
# BUG: handle reuse is common; no second signal was tested
```

**Anchor-First Correlation With Explicit Signals:**

```text
Anchor: user@target.example, key fingerprint 0xDEADBEEF (keyserver, observed 2026-10-02).
Code host: commit author email matches the anchor; commit signed by the same fingerprint -> CONFIRMED.
Forum-a: handle 'nightowl', avatar phash matches the code-host avatar -> CANDIDATE (two weak signals).
Forum-b: handle 'nightowl', no other overlap -> CANDIDATE (handle only).
```

**Why this matters:** A shared handle is the weakest possible signal and is frequently coincidental. Starting from a key fingerprint and testing candidates against it means a link is confirmed only where an identifier matches, and everything else stays a candidate with its evidence stated.

## When It Is NOT This Issue

- **Handle coincidence across unrelated communities.** Popular handles are reused; require a second signal.
- **Breach record read as proof of control.** The record shows the address existed in a corpus, not who used it.
- **Avatar similarity from a shared template.** Generic or stock images produce high perceptual similarity without any link.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `osint-identity-and-email-correlation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `osint-identity-and-email-correlation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: osint-identity-and-email-correlation
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `osint-identity-and-email-correlation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 25 |
| Distinct dataset sources | 7 |
| Top sources | osint-tool-database (16), CYBER_CPT/osv (3), CYBER_CPT/expku (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
