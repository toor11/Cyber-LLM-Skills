---
name: os-command-injection
description: Exploits operating-system command injection through shell metacharacters, argument injection, blind and time-based confirmation, and escalation to a reverse shell. Use when input reaches system(), exec(), popen(), backticks, subprocess with a shell, or a CLI wrapper.
family: web-and-application
tier: core
triggers: ["command injection", "os command", "cmdi", "shell injection", "rce via command", "argument injection"]
cwe: [CWE-78]
owasp: [A03:2021]
attack: [T1059]
capec: [CAPEC-88]
related: [os-command-injection-blind-and-time-based, os-command-injection-argument-injection, os-command-injection-shell-metacharacter-bypass, sql-injection]
---

# Os Command Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)

## Mechanism and Preconditions

User input reaches an operating-system command invocation, through system(), exec(), popen(), backticks, or a subprocess call that uses a shell, so a value meant as data is tokenised by the shell as additional commands or arguments. The security decision is at the boundary between the application and the shell: whether input is passed as inert argument data or spliced into a command line the shell re-parses. The attacker gains execution under the service account, pivoting to file access, lateral movement, and persistence. Which metacharacter works depends on the exact sink and platform, and confirmation depends on the available channel: reflected output, response timing, an out-of-band callback, or a file side effect. The parent skill routes to the right confirmation and bypass variant once the sink is classified.

- **Precondition chain:** Request data reaches a shell or command invocation, the call interprets a shell rather than passing an argument vector, and at least one confirmation channel (output, timing, callback, or side effect) survives to the tester.
- **Readable differential:** The same request with a benign value versus one carrying a command separator; a finding exists when the response, timing, or a callback shows the extra command ran, and it reverts when the call uses an argument vector with no shell.
- **Empirical grounding:** CWE-78 OS Command Injection under OWASP Top 10:2025 A05 Injection; CVE-2025-58034 (FortiWeb OS command injection, chained with the CVE-2025-64446 path traversal, CISA alert November 2025) is a 2025 instance exploited in the wild.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves confirming execution without reflected output **THEN** switch to [`os-command-injection-blind-and-time-based`](../os-command-injection-blind-and-time-based/SKILL.md) (1 hop)
2. **IF** the input reaches a CLI argument list rather than a shell **THEN** switch to [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) (1 hop)
3. **IF** a filter strips spaces, slashes, or keywords from the input **THEN** switch to [`os-command-injection-shell-metacharacter-bypass`](../os-command-injection-shell-metacharacter-bypass/SKILL.md) (1 hop)
4. **IF** execution is confirmed and the goal is an interactive session **THEN** switch to [`os-command-injection-escalation-to-shell`](../os-command-injection-escalation-to-shell/SKILL.md) (1 hop)
5. **IF** the input reaches a language interpreter such as eval rather than a shell **THEN** route to [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) because the sink is language-level evaluation
6. **IF** execution flows through a deserialization gadget chain **THEN** route to [`insecure-deserialization`](../insecure-deserialization/SKILL.md) where object instantiation drives the command
7. **IF** a template expression executes code server-side **THEN** route to [`ssti`](../ssti/SKILL.md) because the interpreter is the template engine
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)
9. **IF** no separator changes the response, timing, or any callback after inspection **THEN** STOP and classify as a verified non-finding rather than forcing a payload

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Input reaches a language interpreter such as eval rather than a shell | [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) | The sink is language-level evaluation (CWE-94), not an OS shell (CWE-78) |
| A deserialization gadget chain yields command execution | [`insecure-deserialization`](../insecure-deserialization/SKILL.md) | Execution flows through object instantiation, not a command string |
| A template expression executes code on the server | [`ssti`](../ssti/SKILL.md) | The interpreter is the template engine, a distinct sink and fix |
| Target matches `os-command-injection-blind-and-time-based` | [`os-command-injection-blind-and-time-based`](../os-command-injection-blind-and-time-based/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `os-command-injection-argument-injection` | [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `os-command-injection-shell-metacharacter-bypass` | [`os-command-injection-shell-metacharacter-bypass`](../os-command-injection-shell-metacharacter-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `os-command-injection-escalation-to-shell` | [`os-command-injection-escalation-to-shell`](../os-command-injection-escalation-to-shell/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the command sink and classify the interpreter.** Read the code to see whether input hits a shell (system, popen, subprocess with shell), an argument vector, or a template, and on which platform. The interpreter type selects the variant skill.
2. **Choose the confirmation channel from observed evidence.** Decide whether command output is reflected, whether only timing is observable, or whether an out-of-band callback is the only signal. Pick the least intrusive channel that can still falsify the hypothesis.
3. **Record a paired benign baseline.** Send the same request twice with two harmless values (for example two valid hostnames) and capture response length, status, and elapsed time. Natural variation between them is the noise floor.
4. **Probe each separator in isolation.** Test `;`, `|`, `&&`, `$(...)`, and backticks one at a time with a benign command such as id or echo of a marker, rather than compound payloads, so the working separator is unambiguous.
5. **Confirm the command ran, not that the request errored.** A 500 or stderr leak is not execution; require a marker in output, a timing shift keyed to the injected command, or a callback that only the injected command could produce.
6. **Stop condition.** Halt when a probe either (a) produces a command-execution signal that disappears when the call uses an argument vector, (b) yields no change across two baselines on any channel, or (c) would require a destructive command or reading real secrets to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an identical request with one added separator producing a marker in output, a command-keyed delay, or an attacker-observed callback, plus the source line that passes input to a shell. A stack trace alone is not proof.
8. **Close with the structural fix and verify it.** Replace the shell call with an argument-vector invocation that takes no shell, validate the value against a strict type or allowlist, drop unnecessary privileges, and re-run the separator probe to confirm it is now inert.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `subprocess` call or `system()` built by concatenating request input | Proves the input is tokenised by a shell on Linux or Windows, the core CWE-78 sink |
| A command separator that adds a marker to the reflected output | Proves in-band execution where the response echoes command results on the affected stack |
| A `$(...)` or backtick substitution producing a value inside the output | Proves command substitution is evaluated, distinguishing a shell sink from an argument sink |
| A 500 that changes to a 200 with a marker once a separator is added | Proves the request reaches a shell rather than failing input validation |
| The executing identity returned by a benign id or whoami probe | Proves the service account under which commands run, scoping impact on the host |
| An argument value that starts with a dash and alters tool behaviour | Proves the sink may be an argument list rather than a shell, routing to the argument-injection variant |

## Worked Contrast

**Vulnerable Pattern (php - command injection):**

```php
}

$name = $_GET['name'] ?? '';
$path = __DIR__ . '/images/' . $name;
// Vulnerable: the filename is parsed as part of a shell command.
$output = shell_exec('/usr/bin/stat -c %s -- ' . $path . ' 2>&1');
echo json_encode(['size_bytes' => trim((string) $output)]);
```

**Fixed / Hardened Pattern (php - command injection):**

```php
}

$name = $_GET['name'] ?? null;
if (!is_string($name) || preg_match('/\A[A-Za-z0-9_-]{1,64}\.(?:gif|png|jpg|jpeg)\z/D', $name) !== 1) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid image name']);
    return;
}

$root = realpath(__DIR__ . '/images');
$path = realpath(__DIR__ . '/images/' . $name);
if ($root === false || $path === false || !str_starts_with($path, $root . DIRECTORY_SEPARATOR) || !is_file($path)) {
    http_response_code(404);
    echo json_encode(['error' => 'Image not found']);
    return;
}
```

**Why this matters:** An unauthenticated filename is parsed by a shell, allowing commands under the PHP worker account.

## When It Is NOT This Issue

- **Argument vector with no shell:** input is passed as a list element to execve-style APIs, so separators are inert data and no shell re-parses them.
- **Server error without execution:** a 500 or stderr leak occurs but no marker, delay, or callback shows a command ran; that is an input-handling bug, not CWE-78.
- **Allowlisted enum value:** the parameter is mapped to a fixed command through a closed server-side table, so arbitrary text never reaches the invocation.
- **Timing matches a slow baseline:** an endpoint that is naturally slow looks injectable; only a delay keyed to the injected command and reverting on fix counts.
- **Sandboxed or unprivileged runtime blocks reach:** a seccomp or container policy demonstrably prevents the invocation from executing the injected command.
- **Interpreter is a language eval, not a shell:** a working `__import__` or template expression is code injection or SSTI, a different sink with a different fix.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `os-command-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `os-command-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: os-command-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-78 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) - Blue Detection/Defense Counterpart
- [`os-command-injection-blind-and-time-based`](../os-command-injection-blind-and-time-based/SKILL.md) - Web and Application (leaf)
- [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) - Web and Application (leaf)
- [`os-command-injection-shell-metacharacter-bypass`](../os-command-injection-shell-metacharacter-bypass/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `os-command-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-78, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 70 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (31), securecode-web (16), CYBER_CPT/nuclei_templates (11), SecEval/cwe (5) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 12 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
