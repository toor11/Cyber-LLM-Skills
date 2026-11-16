---
name: reverse-shells-and-payload-delivery
description: "Delivers and stabilizes reverse shells: listener selection, payload generation for each interpreter, tty upgrade, egress-restricted alternatives, and fileless delivery. Use immediately after achieving command execution."
family: network-ad-and-endpoint
tier: leaf
triggers: ["reverse shell", "payload delivery", "shell upgrade", "msfvenom", "stabilize shell"]
cwe: [CWE-284]
owasp: []
attack: [T1059]
capec: [CAPEC-563]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Reverse Shells and Payload Delivery - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

A reverse shell is an outbound connection from the compromised host to a listener, chosen because outbound traffic is usually permitted while inbound is not. The assessment-relevant property is not the shell itself but the delivery chain: what executed the shell, what network path it used, and which control should have stopped it. Since 2025 the dominant delivery is not a payload at all but a signed binary or an interpreter already on the host, invoked by a user instruction, which means the control is application control and egress filtering rather than file scanning.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the shell is spawned by a signed binary **THEN** the control is application control on that binary, not file scanning; see [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md)
2. **IF** the shell is spawned by an interpreter **THEN** script-block logging and interpreter constraints are the controls
3. **IF** the connection is over a permitted port **THEN** egress filtering by destination is the control, since port-based rules will not stop it
4. **IF** the objective is to understand what was delivered **THEN** the parent process and the network path are the evidence, not the shell code
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `reverse-shells-and-payload-delivery` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Signed-binary execution | [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) | Proxy selection |
| Beacon timing rather than a shell | [`c2-implant-and-beaconing`](../c2-implant-and-beaconing/SKILL.md) | Periodic check-in |
| The transport is a tunnel | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Forwarding and routing |
| Delivery was by phishing | [`initial-access-via-phishing`](../initial-access-via-phishing/SKILL.md) | How the user was persuaded |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify what executed the shell.** The parent process is the delivery mechanism. A shell spawned by `wsmprovhost.exe` is remote management; one spawned by `explorer.exe` is a user instruction; one spawned by `services.exe` is a service. The parent answers the delivery question.
2. **Read the outbound path.** Destination address, port and protocol. A shell to an address that is not in any sanctioned inventory, over a port that is normally permitted, is the finding: egress control is destination-based, not port-based.
3. **Baseline the interpreter's normal child processes.** PowerShell spawning `cmd.exe` is common in management tooling; PowerShell spawning `cmd.exe` that then opens a socket to an external address is not. The differential is the child's network behaviour.
4. **Name the stop condition and the containment rule.** Stop at the first proven execution-and-egress pair. A reverse shell is an interactive channel; leaving it open is a live exposure, so record the evidence and close it.
5. **State the proof.** Proof is the process tree with the shell's parent, plus the network event naming the destination, plus the control that permitted both. The shell's banner is not evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Interpreter child process with an outbound connection | Proves a shell channel, since interpreters rarely initiate external connections in normal operation; Windows and Linux. |
| `explorer.exe` as the parent of a shell | Proves user-instruction delivery, the fake-captcha pattern; Windows. |
| Shell over a permitted port to an unsanctioned destination | Proves egress filtering is port-based rather than destination-based, the actual control gap; any estate. |
| `/dev/tcp` or a named pipe in a shell command line | Proves a shell built without a binary, which file scanning cannot catch; Linux bash. |
| Long-lived connection carrying keystroke-sized packets | Proves an interactive channel rather than an automated one; any egress path. |

## Worked Contrast

**Weak configuration — egress permitted on 443 to any destination with no application control on interpreters:**

```bash
# firewall allows 443 outbound to any address, and PowerShell is unrestricted,
# so a single interpreter command produces an interactive channel over TLS
New-NetFirewallRule -DisplayName 'Allow-443' -Direction Outbound -Protocol TCP -RemotePort 443
```

**Hardened configuration — destination allowlist plus constrained interpreters and script-block logging:**

```bash
Remove-NetFirewallRule -DisplayName 'Allow-443'
New-NetFirewallRule -DisplayName 'HTTPS-Allowlist' -Direction Outbound -Protocol TCP `
    -RemotePort 443 -RemoteAddress 203.0.113.10 -Action Allow
# plus Application Control on script hosts and ScriptBlockLogging enabled
# verification: an interpreter connection to an unlisted destination is denied and logged
```

**Why this matters:** a reverse shell needs both an interpreter and a reachable destination, so the controls are the egress allowlist and the interpreter constraint, verified by a denied connection that still produces a log.

## When It Is NOT This Issue

- **An interpreter making a legitimate API call.** Management tooling and monitoring use HTTP from PowerShell; check the destination against the sanctioned inventory.
- **A developer running a local listener.** Loopback connections are not egress; check the destination address.
- **A remote-management session.** `wsmprovhost.exe` spawning a shell is WinRM, which is administration rather than a reverse shell; the source address decides.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `reverse-shells-and-payload-delivery` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `reverse-shells-and-payload-delivery` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: reverse-shells-and-payload-delivery
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `reverse-shells-and-payload-delivery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 34 |
| Distinct dataset sources | 9 |
| Top sources | CYBER_CPT/L5/ctf_search (11), OffsecCyber (8), CYBER_CPT/oxdf (5), CYBER_CPT/sigmahq (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
