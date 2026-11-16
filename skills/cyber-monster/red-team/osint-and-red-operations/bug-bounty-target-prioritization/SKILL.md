---
name: bug-bounty-target-prioritization
description: "Prioritizes bounty targets: programme economics, attack surface value, competition and likelihood of unique findings. Use when choosing what to hunt on a bounty platform."
family: osint-and-red-operations
tier: leaf
triggers: ["bug bounty targeting", "target prioritization", "bounty program selection"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Bug Bounty Target Prioritization - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Choosing where to spend research time on a bug bounty programme: reading the policy for scope and payout shape, estimating the attack surface that is reachable and recently changed, and accounting for how many other researchers are working the same surface. The decision is an expected-value one, and the inputs are policy terms, surface size, change recency, and competition.

- **The policy defines the payout, not the programme page.** Scope exclusions, severity tables, and disclosure rules decide whether a finding is payable at all.
- **Recent change beats raw surface size.** A newly deployed endpoint has both fresh bugs and fewer researchers who have read it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the policy excludes a class of issue **THEN** deprioritise it regardless of severity, because an excluded finding is unpaid effort.
2. **IF** a surface is heavily covered by public write-ups **THEN** expect diminishing returns and look for recently added functionality instead.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the programme policy text, a scope list, and a signal of recent change (release notes, new hostnames, new API versions) — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A programme policy extract, a scope list, and a change signal; scored per surface with explicit weights
- **First Check:** `python -c "import yaml; d=yaml.safe_load(open('programme.yaml')); print(d['scope'], d['exclusions'])"`

1. Confirm the target surface: extract scope, exclusions, severity table, and disclosure terms from the policy, and record the retrieval date since policies change.
2. Choose the branch: breadth-first when the programme is new to you, depth-first on a recently changed component, and policy-gap analysis when the scope itself is ambiguous.
3. Define the differential: compare a surface's characteristics against the programme's payout table; the differential is the expected payout band, and a surface outside every band is not worth time.
4. Name the stop condition: a time budget per surface and a rule to abandon after a fixed number of hypotheses without signal.
5. Prove it: the prioritisation records the policy version, the scope entry, the change signal, and the reasoning, so the choice can be reviewed later.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Scope and exclusion extract with retrieval date` | Policies change; a prioritisation based on a stale policy is wasted effort. |
| `Severity table mapped to surface class` | Converts a technical surface into an expected payout band, which is the actual decision input. |
| `Change signal per surface` | New endpoints and versions concentrate both bugs and opportunity. |
| `Competition proxy from public write-ups` | Estimates how picked-over a surface is, which is otherwise invisible. |

## Worked Contrast

**Prioritisation by Surface Size Alone:**

```text
The programme has a large API surface, so start with the biggest endpoint list.
# BUG: no policy check, no payout mapping, no change signal, no competition estimate
```

**Prioritisation With Policy, Payout and Change Inputs:**

```text
Policy (retrieved 2026-11-02): scope api.client.example v2; excludes rate-limit and self-XSS; severity table pays critical/high only.
Change signal: v3 endpoints announced 2026-10-15, documented but not yet in the public client.
Payout mapping: auth and object-level access on v3 fall in the high band.
Competition proxy: no public write-ups reference v3 paths.
Decision: spend the first block on v3 object-level authorisation, deprioritise rate-limit testing as excluded.
```

**Why this matters:** The largest surface is usually the most picked-over, and rate-limit findings are explicitly unpaid on this programme, so size alone leads to effort that cannot be rewarded. Reading the policy, mapping surfaces to payout bands, and weighting recent change produces a decision that can be defended when the time budget is reviewed.

## When It Is NOT This Issue

- **Excluded issue class.** Testing it produces unpaid work regardless of technical severity.
- **Surface already covered by public write-ups.** The bugs are likely found; treat it as a low-yield area unless something changed.
- **Out-of-scope asset discovered during testing.** Report the scope gap to the programme rather than testing the asset.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `bug-bounty-target-prioritization` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `bug-bounty-target-prioritization` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: bug-bounty-target-prioritization
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `bug-bounty-target-prioritization` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 3 |
| Top sources | OffsecCyber (8), CYBER_CPT/github_security_md (3), CYBER_CPT/ctf_search (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
