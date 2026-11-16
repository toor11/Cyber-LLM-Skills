---
name: os-command-injection-escalation-to-shell
description: Command injection escalation to interactive shell. Covers turning single-command execution into a stable reverse shell, including interpreter selection, tty upgrade and egress-restricted alternatives. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["command injection reverse shell", "cmdi to shell", "interactive shell upgrade"]
cwe: [CWE-78]
owasp: [A03:2021]
attack: [T1059]
capec: [CAPEC-88]
related: [os-command-injection, os-command-injection-blind-and-time-based, os-command-injection-argument-injection, os-command-injection-shell-metacharacter-bypass]
parent: os-command-injection
corpus_sparse: true
---

# Os Command Injection Escalation to Shell - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

This skill starts after single-command execution is already confirmed and concerns turning that primitive into a stable interactive session, which is a question of defensive hardening rather than new injection. The relevant decision point is whether the already-vulnerable command path should be allowed to reach an interpreter capable of an interactive shell, and whether the environment constrains interpreters, egress, and privileges. From a verification standpoint the goal is to prove the escalation is feasible without actually establishing a backdoor: which interpreters exist, whether egress is possible, and what account the process runs as. The structural weakness is the same CWE-78 sink plus a permissive runtime; the remediation is to remove the shell interpretation, restrict available interpreters, deny unnecessary egress, and drop privileges. Confirmation is that an interactive interpreter is present and egress is reachable, not that a session was opened.

- **Precondition chain:** Single-command execution is already confirmed, an interactive interpreter is available on the host, and the runtime permits the egress and privileges an interactive session would need.
- **Readable differential:** The host before hardening, where an interpreter and egress are reachable, versus after, where the sink runs a fixed argument vector under a constrained account; feasibility that disappears after hardening proves the control works.
- **Empirical grounding:** CWE-78 under OWASP Top 10:2025 A05 Injection, mapped to MITRE ATT&CK T1059 Command and Scripting Interpreter; SOURCES.md has no escalation-specific advisory, so grounding stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** single-command execution is not yet confirmed **THEN** start at parent class [`os-command-injection`](../os-command-injection/SKILL.md) and confirm execution first
2. **IF** execution is confirmed and interpreters are present **THEN** enumerate which interpreters exist before considering any upgrade
3. **IF** egress is restricted **THEN** assess whether an allowed port or DNS path exists before assuming a callback is feasible
4. **IF** the primitive is still single-command and unconfirmed **THEN** route back to [`os-command-injection`](../os-command-injection/SKILL.md) to establish the base finding
5. **IF** the injected value is a CLI flag rather than a shell command **THEN** route to [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) because no shell is present
6. **IF** egress is blocked and only timing confirms execution **THEN** route to [`os-command-injection-blind-and-time-based`](../os-command-injection-blind-and-time-based/SKILL.md)
7. **IF** the environment is a container that constrains interpreters and privileges **THEN** treat the constraint as a compensating control and record reduced feasibility
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)
9. **IF** no interactive interpreter exists and egress is fully denied **THEN** STOP and record escalation as infeasible in this environment

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Execution is still single-command and unconfirmed | [`os-command-injection`](../os-command-injection/SKILL.md) | Confirm execution before any interactive upgrade is considered |
| The injected value is a CLI flag, not a shell command | [`os-command-injection-argument-injection`](../os-command-injection-argument-injection/SKILL.md) | No shell is present, so an interactive session is not reachable |
| Egress is blocked and only timing confirms execution | [`os-command-injection-blind-and-time-based`](../os-command-injection-blind-and-time-based/SKILL.md) | A callback session is infeasible; stay with blind confirmation |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the base primitive first.** Verify single-command execution exists and is attributable, because escalation feasibility is meaningless without it.
2. **Enumerate available interpreters read-only.** Determine which of bash, sh, python3, perl, socat, or nc resolve on the host using a benign lookup; the presence of a capable interpreter is the first escalation precondition.
3. **Assess egress without opening a channel.** Establish whether the host can reach an assessor endpoint on an allowed port or via DNS, using a single benign resolution rather than a live connect-back.
4. **Identify the executing account and its limits.** Record the user, group, and any container or seccomp constraints, since these bound what an interactive session could do.
5. **Describe the upgrade path without performing it.** Note the interpreter and channel that would be used so the finding is concrete, but do not instantiate a session; feasibility is the deliverable.
6. **Stop condition.** Halt when the assessment shows either (a) a capable interpreter plus reachable egress under a usable account, which is confirmed feasibility that constraints then close, (b) no interpreter or no egress, which is infeasibility, or (c) a point where proceeding would require establishing an actual backdoor. Case (a) confirms, (b) is a non-finding for escalation, (c) is out of scope.
7. **State what counts as proof.** Proof is the enumerated presence of an interactive interpreter and a reachable egress path under the process account, paired with the confirmed base injection, not an opened reverse session. Absence of any interpreter is sufficient to rule escalation out.
8. **Close with the structural fix and verify it.** Remove the shell interpretation at the sink, restrict the image to the interpreters the service needs, deny outbound egress by default, and drop privileges; re-run the interpreter and egress enumeration to confirm feasibility is gone.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| bash, python3, or socat resolving on the host after confirmed execution | Proves an interactive-capable interpreter is available, the first precondition for a session upgrade |
| A reachable assessor endpoint on an allowed outbound port | Proves egress exists for a connect-back path on the host's network policy |
| The process account holding broad filesystem or network access | Proves the executing identity would make an interactive session high-impact on this host |
| Absence of every common interpreter on the host | Proves escalation to an interactive shell is infeasible even though single-command execution exists |
| A container with a minimal image and no shell | Proves a compensating control that caps the primitive at single commands |
| Default-allow outbound network policy from the app tier | Proves the egress precondition is satisfied, raising escalation feasibility |

## Worked Contrast

**Vulnerable pattern:**

```python
import subprocess

def run_diagnostic(cmd):
    # Operator-supplied string runs through a shell under the service account
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
```

**Hardened pattern:**

```python
import subprocess

ALLOWED = {"uptime": ["uptime"], "disk": ["df", "-h"]}

def run_diagnostic(name):
    argv = ALLOWED.get(name)
    if argv is None:
        raise ValueError("unknown diagnostic")
    # Only pre-declared argument vectors run; no shell means no interpreter to pivot into
    return subprocess.run(argv, capture_output=True, text=True)
```

**Why this matters:** The vulnerable diagnostic runs an arbitrary string through a shell, which is exactly what an interactive upgrade needs; the fix maps a name to a fixed argument vector with no shell, so there is no interpreter for the single-command primitive to escalate through.

## When It Is NOT This Issue

- **Base injection unconfirmed:** without proven single-command execution there is nothing to escalate, so escalation claims are premature.
- **No interpreter present:** a host lacking bash, python, perl, and socat cannot host an interactive session regardless of the primitive.
- **Egress fully denied:** a default-deny outbound policy blocks connect-back and most tunnels, capping impact at local single commands.
- **Minimal container image:** a distroless or shell-free image removes the interpreters an upgrade depends on.
- **Unprivileged, isolated account:** a locked-down service user with seccomp limits sharply reduces what a session could achieve.
- **Argument-list sink:** where input reaches an argv with no shell, a session is not reachable and this skill does not apply.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `os-command-injection-escalation-to-shell` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `os-command-injection-escalation-to-shell` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: os-command-injection-escalation-to-shell
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
- [`os-command-injection-shell-metacharacter-bypass`](../os-command-injection-shell-metacharacter-bypass/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `os-command-injection-escalation-to-shell` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-78, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
