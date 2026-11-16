---
name: security-arsenal-and-tool-index
description: Indexes which tool to reach for by task, with invocation patterns and limitations, without duplicating technique content. Use when you know the goal but not the tool.
family: osint-and-red-operations
tier: leaf
triggers: ["security tools", "tool index", "which tool", "tooling reference"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Security Arsenal and Tool Index - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Choosing the right tool for a question, and being able to justify the choice: an index that maps a technique to a tool, its invocation shape, its output format, an alternative when it is unavailable, and what it cannot answer. The value is not a list of tools but the mapping from question to evidence, plus the reason a weaker tool would be wrong.

- **Every entry names its blind spot.** A tool that cannot answer a class of question must say so, otherwise its silence is read as a negative result.
- **An alternative must produce comparable output.** A fallback that emits a different shape breaks every downstream comparison, so the index records the format.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the tool's licence or platform excludes the environment **THEN** use the recorded alternative and note the difference in output fidelity.
2. **IF** two tools answer the same question **THEN** prefer the one whose output is machine-readable and whose version is pinned.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a technique, a target platform, and a defined output format the downstream step can consume — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A versioned index mapping technique to tool, invocation, output format, blind spot, and alternative
- **First Check:** `python -c "import yaml; [print(e['tool'], e['format']) for e in yaml.safe_load(open('index.yaml'))['entries']]"`

1. Confirm the target surface: state the question and the output the next step needs, before choosing a tool.
2. Choose the branch: native tool when it answers the question with the required format, alternative when the native tool is unavailable on the platform, and a script when no tool answers the question at all.
3. Define the differential: run the chosen tool and one alternative on the same input, and compare the output for the fields the question needs; a missing field means the tool is wrong for the question.
4. Name the stop condition: one tool and one alternative per entry, each with a pinned version, so the choice is reproducible.
5. Prove it: the index entry records the invocation that produced the evidence and the format, so a reviewer can re-run it exactly.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Technique-to-tool mapping with invocation` | The core index entry; a tool name without an invocation is a suggestion, not a method. |
| `Output format per entry` | Decides whether the next step can consume the result without re-parsing prose. |
| `Recorded blind spot` | Prevents a tool's silence from being read as a negative finding. |
| `Alternative with fidelity note` | Keeps the method usable on a restricted platform while marking the difference in quality. |

## Worked Contrast

**Tool List With No Invocation or Format:**

```text
Useful tools: nmap, nuclei, semgrep, shodan, exiftool.
# BUG: no technique mapping, no invocation, no output format, no blind spot
```

**Index Entry With Invocation, Format and Blind Spot:**

```yaml
entries:
  - technique: http-service-inventory
    tool: nmap
    version: "7.95"
    invocation: nmap -sV -Pn -p 443 --script http-headers -oX out.xml target.example
    format: xml
    blind_spot: "cannot see services on ports outside the explicit -p list"
    alternative:
      tool: httpx
      fidelity: "status and headers only, no version detection"
```

**Why this matters:** A bare tool list cannot be executed and gives no way to know when the tool's answer is incomplete. Recording the invocation, the output format, and the blind spot makes each entry runnable and honest, and the alternative's fidelity note tells a reader how much weaker the fallback evidence is.

## When It Is NOT This Issue

- **Tool installed but version differs from the index.** Invocation flags change between versions; record the version or expect a different result.
- **Alternative tool used without noting fidelity.** Substitute evidence must be labelled, or the report overstates what was observed.
- **Tool absence read as capability absence.** No tool for a question means a script or a different technique, not that the question is unanswerable.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `security-arsenal-and-tool-index` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `security-arsenal-and-tool-index` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: security-arsenal-and-tool-index
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `security-arsenal-and-tool-index` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 36 |
| Distinct dataset sources | 15 |
| Top sources | CYBER_CPT/sigmahq (6), cyber-security/blue-team__threat-hunting-queries.json (4), cyber-security/vulnerability-intelligence__mitre-attack-techniques.json (4), OffsecCyber (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 12 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
