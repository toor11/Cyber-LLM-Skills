---
name: os-command-injection-blind-and-time-based
description: Blind and time-based command injection. Covers confirming execution without output using sleep and ping delays, DNS and HTTP callbacks, and file-based side effects. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["blind command injection", "time based rce", "cmdi blind", "ping delay"]
cwe: [CWE-78]
owasp: [A03:2021]
attack: [T1059]
capec: [CAPEC-88]
related: [os-command-injection, os-command-injection-argument-injection, os-command-injection-shell-metacharacter-bypass, os-command-injection-escalation-to-shell]
parent: os-command-injection
---

# Os Command Injection Blind and Time Based - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)

## Mechanism and Preconditions

Command injection exists but the application returns no command output, so execution must be confirmed through a side channel rather than a reflected result. The injected command produces an observable effect that is not the response body: a measurable delay from sleep or ping, an out-of-band DNS or HTTP callback, or a file side effect the tester can read elsewhere. The decision point is the same shell interpretation as the parent class, but the verification pivots entirely to timing and out-of-band oracles, which demands a disciplined baseline because jitter and slow endpoints mimic delays. The attacker gains the same execution, confirmed indirectly, and can even exfiltrate small data by encoding it into a callback hostname. Confirmation is a delay that scales with the injected sleep duration, or a callback that only the injected command could have produced.

- **Precondition chain:** Request data reaches a shell, command output is not reflected, and a timing or out-of-band channel (delay, DNS or HTTP callback, or a readable side effect) is observable to the tester.
- **Readable differential:** A benign value versus one appending a bounded sleep or a callback; a finding exists when elapsed time scales with the sleep or the callback fires, and it reverts to baseline when the call uses an argument vector with no shell.
- **Empirical grounding:** CWE-78 under OWASP Top 10:2025 A05 Injection, confirmed through out-of-band oracles rather than reflected output; SOURCES.md carries no blind-command-injection advisory, so grounding stays at the CWE and OAST-methodology level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to lack reflected output **THEN** start at parent class [`os-command-injection`](../os-command-injection/SKILL.md) for general triage
2. **IF** response timing is the only observable signal **THEN** establish a multi-sample baseline before testing and keep the sleep bounded
3. **IF** egress for callbacks appears available **THEN** prefer a DNS callback because it is usually the least filtered channel
4. **IF** timing is noisy and inconclusive **THEN** switch to an out-of-band callback oracle to separate signal from jitter
5. **IF** the oracle is a DNS or HTTP interaction rather than a delay **THEN** route to [`oast-and-blind-vulnerability-testing-dns-and-http-callbacks`](../oast-and-blind-vulnerability-testing-dns-and-http-callbacks/SKILL.md)
6. **IF** only latency distinguishes the probe **THEN** route to [`oast-and-blind-vulnerability-testing-timing-oracles`](../oast-and-blind-vulnerability-testing-timing-oracles/SKILL.md) for baseline discipline
7. **IF** output turns out to be reflected after all **THEN** return to parent [`os-command-injection`](../os-command-injection/SKILL.md) for in-band confirmation
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)
9. **IF** neither bounded delay nor any callback fires across repeated samples **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The oracle is a DNS or HTTP callback rather than a delay | [`oast-and-blind-vulnerability-testing-dns-and-http-callbacks`](../oast-and-blind-vulnerability-testing-dns-and-http-callbacks/SKILL.md) | The channel is an out-of-band interaction, not response timing |
| Only response latency distinguishes the probe | [`oast-and-blind-vulnerability-testing-timing-oracles`](../oast-and-blind-vulnerability-testing-timing-oracles/SKILL.md) | The invariant is a stable timing baseline across repeated samples |
| Command output is actually reflected after all | [`os-command-injection`](../os-command-injection/SKILL.md) | Confirmation reverts to the in-band parent methodology |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm output is genuinely absent.** Verify that no reflected result, error fragment, or state change surfaces the command, because a hidden in-band channel is easier and more reliable than timing.
2. **Establish a timing baseline over several samples.** Send three to five benign requests and record median and spread. Blind confirmation is only as trustworthy as this noise floor.
3. **Select the channel before probing.** Decide between a bounded sleep delay and an out-of-band callback based on observed egress; DNS is usually the least filtered when callbacks are viable.
4. **Probe each separator with a bounded delay.** Append a short sleep (four to six seconds) after each separator in turn and compare elapsed time against the baseline, keeping the delay long enough to clear jitter but short enough to iterate.
5. **Corroborate with a second channel.** Pair a timing result with a callback, or encode a benign token into a callback hostname, so a single noisy signal is not the whole case.
6. **Stop condition.** Halt when a probe either (a) produces a delay that scales with the injected duration or a callback that only the injected command explains, reverting when a shell-free call is used, (b) shows no timing or callback signal across repeated samples, or (c) would require exfiltrating real data to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a monotonic relationship between the injected sleep value and the median response time across repeats, or an attacker-observed callback carrying an injected token, plus the source line that reaches a shell. A single slow response is not proof.
8. **Close with the structural fix and verify it.** Replace the shell invocation with an argument vector that takes no shell, validate the input to a strict type, and re-run the delay and callback probes to confirm neither channel responds.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Elapsed time that scales with an injected sleep duration across repeats | Proves time-blind execution on a shell sink where no output is reflected, after clearing jitter |
| A DNS lookup arriving at an assessor server after a probe | Proves the injected command reached a resolver, an out-of-band confirmation on egress-capable hosts |
| An HTTP callback carrying a token embedded by the injected command | Proves execution and a data channel on stacks where DNS is filtered but HTTP egress exists |
| A benign token from a command appearing inside a callback hostname | Proves small-data exfiltration is feasible through hostname encoding, distinct to blind confirmation |
| No body change but a repeatable delay keyed to the payload | Proves the response channel is closed while a timing oracle remains open |
| A file side effect readable through a second request | Proves execution via an indirect artefact when neither timing nor callbacks are reliable |

## Worked Contrast

**Vulnerable pattern:**

```python
import subprocess

def resolve(host):
    # No output is returned to the caller, but the shell still interprets separators
    subprocess.run("nslookup " + host, shell=True, timeout=10)
```

**Hardened pattern:**

```python
import ipaddress
import subprocess

def resolve(host):
    ipaddress.ip_address(host)  # rejects anything that is not a bare IP literal
    # Fixed argument vector, no shell: there is no separator left to time-delay
    subprocess.run(["nslookup", "--", host], timeout=10)
```

**Why this matters:** The vulnerable version hides output but still concatenates into a shell, so a sleep or callback confirms execution; the fix validates the value as an IP and runs a shell-free argument vector, removing both the separator and the timing oracle it relied on.

## When It Is NOT This Issue

- **Naturally slow endpoint:** a route that is slow on its own mimics a delay; only a latency that scales with the injected sleep and reverts on fix counts.
- **Resolver pre-fetch:** a DNS callback can fire from a validation-time lookup that never executes the command, so a lookup alone is not execution.
- **Jitter within the noise band:** a delay inside the measured baseline spread across repeats is network variance, not a payload effect.
- **Egress blocked entirely:** if the host cannot reach the callback server and timing is flat, the primitive may exist but is unconfirmable through these channels.
- **Shell-free sink:** an argument vector with no shell shows no timing or callback response, so appearance of a separator in logs is not a finding.
- **Rate limiter causing delay:** a throttle that delays responses uniformly regardless of payload is a control, not injection.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `os-command-injection-blind-and-time-based` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `os-command-injection-blind-and-time-based` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: os-command-injection-blind-and-time-based
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-78 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) - Blue Detection/Defense Counterpart
- [`os-command-injection`](../os-command-injection/SKILL.md) - Web and Application (core)
- [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) - Web and Application (leaf)
- [`os-command-injection-shell-metacharacter-bypass`](../os-command-injection-shell-metacharacter-bypass/SKILL.md) - Web and Application (leaf)
- [`os-command-injection-escalation-to-shell`](../os-command-injection-escalation-to-shell/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `os-command-injection-blind-and-time-based` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-78, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 3 |
| Top sources | OffsecCyber (2), CYBER_CPT/go_exploitdb (2), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
