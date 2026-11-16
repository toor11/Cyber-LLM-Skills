---
name: os-command-injection-argument-injection
description: Argument injection without shell metacharacters. Covers injecting CLI options into tools like curl, git, tar, ffmpeg and imagemagick when input reaches an argument list rather than a shell. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["argument injection", "cli option injection", "parameter injection", "git argument injection"]
cwe: [CWE-78]
owasp: [A03:2021]
attack: [T1059]
capec: [CAPEC-88]
related: [os-command-injection, os-command-injection-blind-and-time-based, os-command-injection-shell-metacharacter-bypass, os-command-injection-escalation-to-shell]
parent: os-command-injection
---

# Os Command Injection Argument Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)

## Mechanism and Preconditions

Input reaches a child process as an element of its argument list rather than through a shell, so there is no metacharacter to abuse, yet a value that begins with a dash is parsed by the invoked tool as an option instead of data. Tools like curl, git, tar, ffmpeg, and ImageMagick expose flags such as -o, --output, --upload-pack, -K, or delegate directives that redirect output, run helpers, or read config files, so option smuggling turns a benign parameter into file write, file read, or helper execution. The decision point is how the value is positioned in the argument vector and whether an end-of-options terminator separates flags from data. The attacker gains tool-specific capabilities short of a shell. Confirmation is that an option-shaped value changes the tool's behaviour while a positional value does not.

- **Precondition chain:** Input is placed into a process argument vector, no end-of-options terminator separates flags from the value, and the invoked tool exposes an option that reads, writes, or executes through its flags.
- **Readable differential:** A positional value versus an option-shaped value in the same argument slot; a finding exists when the option-shaped value changes the tool's behaviour, and it stops once a `--` terminator or validation forces the value to be positional.
- **Empirical grounding:** Argument injection is CWE-88 and OS command injection is CWE-78, both under OWASP Top 10:2025 A05 Injection; SOURCES.md has no argument-injection-specific advisory, so grounding stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to be argument rather than shell injection **THEN** start at parent class [`os-command-injection`](../os-command-injection/SKILL.md) for general triage
2. **IF** the value is passed to curl or wget **THEN** probe output-redirecting flags such as -o and --output against a positional URL
3. **IF** the value is passed to git **THEN** probe --upload-pack or the GIT_SSH_COMMAND environment path for helper execution
4. **IF** the value is passed to tar **THEN** probe --to-command or checkpoint actions that run on extraction
5. **IF** the value is a filename handed to ImageMagick or ffmpeg **THEN** probe delegate and protocol options that read or fetch external resources
6. **IF** the injected option writes or reads a file rather than running a command **THEN** route to [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) for the file-access impact
7. **IF** the sink is actually a shell and metacharacters work **THEN** route to [`os-command-injection-shell-metacharacter-bypass`](../os-command-injection-shell-metacharacter-bypass/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)
9. **IF** a `--` terminator already separates flags from the value so no option is honoured **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The injected option writes or reads a file rather than running a command | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | Impact is file access through a flag, not command execution |
| Shell metacharacters, not CLI flags, reach the interpreter | [`os-command-injection-shell-metacharacter-bypass`](../os-command-injection-shell-metacharacter-bypass/SKILL.md) | The sink is a shell, so metacharacter filtering is the invariant |
| The confirmation channel is timing or an out-of-band callback | [`os-command-injection-blind-and-time-based`](../os-command-injection-blind-and-time-based/SKILL.md) | Verification shifts to an out-of-band oracle rather than tool behaviour |
| Need parent class methodology | [`os-command-injection`](../os-command-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the invoked tool and its argument vector.** Read how the process is built and find the exact slot the input occupies and whether a shell is involved at all. If no shell is present, this is the right skill.
2. **Enumerate the tool's dangerous options.** For the specific binary, list flags that write files, read config, set helpers, or change protocols (for example curl -o, git --upload-pack, tar --to-command). The tool's option set defines the reachable impact.
3. **Check for an end-of-options terminator.** Determine whether the call inserts `--` before the value or validates that the value is not option-shaped. Its absence is the core defect.
4. **Record a positional baseline.** Invoke the feature with a normal value and capture the tool's output and side effects. This is the behaviour an option-shaped value must change.
5. **Inject one option at a time.** Replace the value with a single dash-prefixed option and observe whether the tool honours it, iterating through write, read, and helper options separately so the specific capability is clear.
6. **Stop condition.** Halt when an injected option either (a) changes the tool's behaviour in a way a positional value cannot and is neutralised by a `--` terminator, (b) is treated as a plain argument in every form, or (c) would require writing to a sensitive path or fetching real secrets to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an option-shaped value altering the tool's output or producing a benign side effect (such as a file in an assessor-writable path), paired with the argument-construction line that lacks a terminator, and evidence the positional form does not do this.
8. **Close with the structural fix and verify it.** Insert `--` before all user values, reject values beginning with a dash, pass data through a dedicated non-option mechanism where the tool supports it, and re-run the option probes to confirm they are now treated as positional data.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A user value placed directly before a URL or path in a curl or wget call | Proves an argument slot that accepts -o or --output on any stack shelling out to the tool |
| Absence of a `--` terminator in the constructed argument vector | Proves flags and data are not separated, the root condition for option smuggling |
| A git invocation whose remote or option is request-derived | Proves --upload-pack or GIT_SSH_COMMAND helper execution is reachable without a shell |
| An ImageMagick or ffmpeg filename that selects a delegate or protocol | Proves a file-format option can trigger external reads or fetches on the media stack |
| A value beginning with a dash accepted where a filename was expected | Proves the tool parses the value as an option, the defining argument-injection signal |
| A tar call exposing --to-command or checkpoint actions on extraction | Proves archive options can run helpers, a write-side argument-injection surface |

## Worked Contrast

**Vulnerable pattern:**

```python
import subprocess

def fetch(url):
    # url reaches the argument list directly; a value like '-o/path' becomes a curl option
    return subprocess.run(["curl", "-s", url], capture_output=True)
```

**Hardened pattern:**

```python
import subprocess
from urllib.parse import urlsplit

def fetch(url):
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("only absolute http(s) URLs are accepted")
    # End-of-options guard forces the value to be positional even if it starts with '-'
    return subprocess.run(["curl", "-s", "--", url], capture_output=True)
```

**Why this matters:** The vulnerable call lets a dash-prefixed value become a curl option such as -o; the fix validates the value as an absolute URL and inserts a -- terminator so the argument parser treats it as positional data, closing option smuggling without a shell ever being involved.

## When It Is NOT This Issue

- **Terminator already present:** the call inserts `--` before the value, so dash-prefixed input is parsed as positional data.
- **Value validated as a strict type:** the input is confirmed to be an absolute URL, an integer, or an enum before it reaches the argument vector.
- **Tool exposes no dangerous option:** the specific binary and version offers no flag that writes, reads, or executes, so option smuggling has no payoff.
- **Shell sink mistaken for argument injection:** a working `;` or `|` means a shell is present, which is the parent or metacharacter skill, not this one.
- **Option honoured but effect is self-scoped:** the flag only alters the caller's own temporary output with no cross-user or sensitive-path impact.
- **Framework builds the vector safely:** a helper that quotes and positions arguments and forbids leading dashes already prevents the parse.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `os-command-injection-argument-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `os-command-injection-argument-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: os-command-injection-argument-injection
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
- [`os-command-injection-shell-metacharacter-bypass`](../os-command-injection-shell-metacharacter-bypass/SKILL.md) - Web and Application (leaf)
- [`os-command-injection-escalation-to-shell`](../os-command-injection-escalation-to-shell/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `os-command-injection-argument-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-78, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 23 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (12), CYBER_CPT/gh_advisories (3), hackerone_disclosed_reports (2), CYBER_CPT/gh_security_lab (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 11 cases |
| Grounding | multi-dataset corpus-grounded |
