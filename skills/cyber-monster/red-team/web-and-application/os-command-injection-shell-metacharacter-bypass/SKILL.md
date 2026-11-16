---
name: os-command-injection-shell-metacharacter-bypass
description: Shell metacharacter filter bypass. Covers surviving filters that strip spaces, slashes, quotes or keywords using IFS, brace expansion, wildcards, encoding and alternate separators. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["command injection bypass", "metacharacter bypass", "ifs bypass", "no space rce"]
cwe: [CWE-78]
owasp: [A03:2021]
attack: [T1059]
capec: [CAPEC-88]
related: [os-command-injection, os-command-injection-blind-and-time-based, os-command-injection-argument-injection, os-command-injection-escalation-to-shell]
parent: os-command-injection
corpus_sparse: true
---

# Os Command Injection Shell Metacharacter Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A command-injection sink is partially defended by a blocklist that strips or rejects specific characters such as semicolons, pipes, spaces, or keywords, but the shell offers many equivalent constructs the filter never anticipated. Space is replaced by ${IFS} or $IFS$9, words are split with quotes or backslashes so keyword matching fails, globs like /???/c?t reconstruct binaries, brace expansion {cmd,arg} avoids spaces, and newlines or alternate separators slip past single-character checks. The decision point is the mistaken belief that character filtering is a security boundary before a shell that will still tokenise the result. The attacker reaches the same CWE-78 execution despite the filter. Confirmation is that a filtered benign command fails while an equivalent built from survivable constructs produces the same effect, proving the blocklist is not a boundary.

- **Precondition chain:** Request data reaches a shell, a blocklist filter strips or rejects certain characters or keywords, and the shell still offers survivable constructs (IFS, quoting, globs, brace expansion) that reconstruct the command.
- **Readable differential:** A plainly filtered command versus an equivalent built from survivable constructs; a finding exists when the reconstructed form executes while the direct form is blocked, and it stops once the sink uses an argument vector with no shell.
- **Empirical grounding:** CWE-78 under OWASP Top 10:2025 A05 Injection; SOURCES.md has no shell-metacharacter-bypass advisory, so grounding stays at the CWE taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to involve a character filter **THEN** start at parent class [`os-command-injection`](../os-command-injection/SKILL.md) for general triage
2. **IF** spaces are stripped or rejected **THEN** substitute ${IFS}, $IFS$9, or brace expansion and compare against the space-bearing form
3. **IF** specific keywords are blocked **THEN** split them with empty quotes or backslashes so matching fails but the shell rejoins them
4. **IF** slashes or paths are filtered **THEN** use glob wildcards such as /???/c?t to reconstruct the binary path
5. **IF** the filter is a WAF layer rather than application code **THEN** route to [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md)
6. **IF** the bypass depends on Unicode or best-fit mapping **THEN** route to [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md)
7. **IF** the input actually reaches an argument list with no shell **THEN** route to [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) because metacharacters are inert there
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)
9. **IF** every survivable construct is also neutralised and no command reconstructs **THEN** STOP and record the sink as effectively non-executing

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The filter is a WAF layer rather than application code | [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) | The differential is container-level parsing, not shell tokenisation |
| The bypass depends on Unicode or best-fit mapping | [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) | Normalisation before filtering is the invariant |
| Input reaches an argument list with no shell | [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) | There is no shell to tokenise, so metacharacters are inert |
| Need parent class methodology | [`os-command-injection`](../os-command-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm a shell sink and a filter.** Establish that input reaches a shell and that a blocklist strips or rejects specific characters; the bypass question only exists when both are true.
2. **Map exactly what the filter removes.** Test each candidate character and keyword in isolation and record which are stripped, which are rejected, and which pass untouched. This map drives construct selection.
3. **Record a filtered baseline.** Send a direct command that the filter blocks and confirm it does not execute. This is the behaviour an equivalent construct must reproduce.
4. **Select survivable constructs against the map.** For stripped spaces use ${IFS} or brace expansion; for blocked keywords use quote or backslash splitting; for filtered paths use glob wildcards. Choose the construct that specifically survives the observed filter.
5. **Prove equivalence with a benign marker.** Reconstruct a harmless command such as echo of a unique marker using the chosen constructs and confirm the marker appears, showing the shell tokenised the survivable form.
6. **Stop condition.** Halt when a reconstructed command either (a) executes while the direct form is blocked and both go inert once a shell-free call is used, (b) fails in every survivable construct, or (c) would require a destructive command to demonstrate. Case (a) confirms the filter is not a boundary, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a pair where the direct command is filtered out but an equivalent built from IFS, quoting, or globs produces the same benign marker, plus the source line showing character filtering precedes a shell. A blocked direct command alone is not proof the sink is safe.
8. **Close with the structural fix and verify it.** Remove the shell interpretation entirely by using an argument vector, or constrain the value to a strict allowlist, rather than extending the blocklist; re-run each survivable construct to confirm none now executes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A command that executes only after spaces are replaced with ${IFS} | Proves the blocklist stripped spaces but the shell still tokenised the IFS form, defeating the filter |
| A keyword that runs when split as c''at or c\at | Proves keyword matching is bypassed by quote or backslash splitting the shell discards |
| A binary reached through a glob like /???/c?t | Proves path filtering is defeated because the shell expands wildcards to the real path |
| Brace expansion {echo,marker} executing without spaces | Proves space and separator filtering is irrelevant to brace-expanded argument lists |
| A newline or alternate separator surviving a single-character check | Proves the filter inspected only one separator while the shell honours several |
| The direct form blocked while an equivalent construct runs | Proves the blocklist is not a boundary for this specific shell sink |

## Worked Contrast

**Vulnerable pattern:**

```python
import subprocess

BLOCKED = [";", "|", "&", " "]

def archive(name):
    # Blocklist misses ${IFS}, brace expansion, and newlines, so filtering is not a boundary
    for ch in BLOCKED:
        name = name.replace(ch, "")
    return subprocess.run("tar czf out.tgz " + name, shell=True)
```

**Hardened pattern:**

```python
import subprocess

def archive(name):
    if not name.isalnum():
        raise ValueError("name must be alphanumeric")
    # Argument vector with no shell: ${IFS}, braces, and wildcards are inert bytes
    return subprocess.run(["tar", "czf", "out.tgz", "--", name])
```

**Why this matters:** The vulnerable version trusts a character blocklist before a shell that still tokenises ${IFS} and brace forms; the fix enforces a strict value shape and runs a shell-free argument vector, so there is no tokeniser left for any survivable construct to exploit.

## When It Is NOT This Issue

- **Shell-free argument vector:** when the value reaches an argv with no shell, IFS, globs, and braces are literal bytes, so filter-bypass constructs do nothing.
- **Strict allowlist on the value:** an alphanumeric or enum constraint rejects the characters every bypass construct needs.
- **Direct command blocked and no construct survives:** if every equivalent also fails, the filter plus sink combination is effectively non-executing.
- **Filter is a WAF, not the sink:** a bypass at the WAF layer is a parser-differential finding routed elsewhere, not proof the origin executes.
- **Marker never appears:** a reconstructed command whose benign marker does not surface has not demonstrated tokenisation.
- **Construct triggers a validation error, not execution:** an input that is rejected rather than executed is the control working, not a bypass.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `os-command-injection-shell-metacharacter-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `os-command-injection-shell-metacharacter-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: os-command-injection-shell-metacharacter-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-78 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) - Blue Detection/Defense Counterpart
- [`os-command-injection`](../os-command-injection/SKILL.md) - Web and Application (core)
- [`os-command-injection-blind-and-time-based`](../os-command-injection-blind-and-time-based/SKILL.md) - Web and Application (leaf)
- [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) - Web and Application (leaf)
- [`os-command-injection-escalation-to-shell`](../os-command-injection-escalation-to-shell/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `os-command-injection-shell-metacharacter-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-78, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | OffsecCyber (1), CYBER_CPT/vulhub (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
