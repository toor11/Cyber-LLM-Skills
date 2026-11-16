---
name: edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection
description: Sandbox and analysis environment detection. Covers detecting virtualized and instrumented environments through hardware, timing, artefact and behavioural checks. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["sandbox detection", "vm detection", "anti analysis", "analysis environment check"]
cwe: [CWE-693]
owasp: []
attack: [T1562]
capec: [CAPEC-578]
related: [edr-evasion-and-amsi-bypass, edr-evasion-and-amsi-bypass-amsi-bypass, edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion, edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls]
parent: edr-evasion-and-amsi-bypass
---

# EDR Evasion and AMSI Bypass Sandbox and Analysis Detection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md)

## Mechanism and Preconditions

Analysis environments differ from production in measurable ways: CPU count, memory size, disk size, hostname patterns, loaded drivers, running processes, user activity, and network latency. A technique that changes behaviour when it detects those differences is not evading a security control, it is selecting its target. The defender's counterpart is to make the analysis environment indistinguishable in the properties a sample can read, and to treat environment-probing behaviour itself as a detection signal.

- **CWE-693 (Protection Mechanism Failure):** The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the sample behaves differently in a sandbox **THEN** the probing behaviour is the finding; enumerate which properties it read
3. **IF** the sample sleeps or waits before acting **THEN** timing-based checks are the mechanism, and the differential is the behaviour after the delay
4. **IF** the question is whether the sandbox is convincing **THEN** compare observable properties against a production baseline rather than adding more tools
5. **IF** the sample checks for a specific vendor **THEN** driver and process names are the properties; the finding is the enumeration itself
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Telemetry suppression rather than environment detection | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | Event loss |
| API hook integrity | [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | User-mode hooking |
| The sample must be triaged rather than assessed | [`antivirus-evasion-and-obfuscation`](../antivirus-evasion-and-obfuscation/SKILL.md) | Content analysis |
| The environment is a malware analysis lab | [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) | Lab design |
| Need the class-level branch table first | [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **List the properties a sample can read without privilege.** Computer name, domain membership, CPU and memory, disk size and model, uptime, loaded drivers, running processes, recent user activity, and the presence of analysis tools. Every one of these is readable from an unprivileged process, so every one is a potential discriminator.
2. **Compare the analysis environment against a production baseline.** Take the same property list from a production host of the same build and role. The differences are the sample's opportunity, and they are the concrete remediation list.
3. **Treat probing as a detection signal.** Enumeration of drivers, processes or system properties in sequence is itself anomalous behaviour. Record which API calls occur before the sample's first meaningful action; that sequence is the detection.
4. **Name the stop condition and the containment rule.** Stop once the probing sequence and its effect on behaviour are recorded. Analysis runs in an isolated environment with no production network path, and the sample is handled per the sample-handling rules.
5. **State the proof.** Proof is the property list, the differential against production, and the API sequence observed before the behavioural change. A statement that a sample 'detects sandboxes' without the property list is not evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Win32_ComputerSystem` CPU and memory values | Proves the environment properties a sample reads first, and low values are the classic discriminator; Windows. |
| Uptime below a threshold | Proves a freshly started environment, which many samples treat as analysis; any platform. |
| Loaded driver list containing analysis or hypervisor artefacts | Proves the environment reveals itself through drivers rather than through files; Windows. |
| Sequential `CreateToolhelp32Snapshot` and registry reads before first action | Proves environment probing, which is detectable regardless of the result; Windows. |
| Sleep or wait calls disproportionate to the task | Proves timing-based evasion, where the differential is behaviour after the delay; any platform. |

## Worked Contrast

**Weak configuration — analysis environment with 2 vCPU, 4 GB RAM, 60 GB disk and a fresh uptime:**

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object NumberOfProcessors,TotalPhysicalMemory
Get-CimInstance Win32_LogicalDisk -Filter 'DeviceID="C:"' | Select-Object Size
# 2 vCPU / 4 GB / 60 GB and minutes of uptime: every property matches the
# published sandbox fingerprint
```

**Hardened configuration — analysis host matching a production profile, with realistic uptime and activity:**

```powershell
# provision 8 vCPU, 32 GB RAM, 500 GB disk, a production-like hostname,
# a domain join, and an uptime above a week before sample execution
Get-CimInstance Win32_ComputerSystem | Select-Object NumberOfProcessors,TotalPhysicalMemory
# verification: the property list matches the production baseline for the role
```

**Why this matters:** environment detection is a property comparison, so the control is the environment profile and the verification is the property list matching production rather than the sample's behaviour changing.

## When It Is NOT This Issue

- **A sample that fails in a sandbox because of a missing dependency.** A runtime or library absent from the analysis host is a lab configuration issue, not sandbox detection.
- **A sample that needs a network service the lab blocks.** Absence of command-and-control reachability produces no behaviour without any detection logic.
- **A sample that appears dormant because it waits hours.** Very long delays are timing evasion, but they are also consistent with a scheduled trigger; distinguish by the API sequence.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) - Blue Detection/Defense Counterpart
- [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`edr-evasion-and-amsi-bypass-amsi-bypass`](../edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/go_exploitdb (3), CYBER_CPT/gh_advisories (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
