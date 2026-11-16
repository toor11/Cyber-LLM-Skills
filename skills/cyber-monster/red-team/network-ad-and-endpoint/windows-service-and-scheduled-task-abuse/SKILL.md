---
name: windows-service-and-scheduled-task-abuse
description: "Abuses Windows services and scheduled tasks for execution and escalation: service permissions, binary path tampering, task creation as SYSTEM and task file replacement. Use when a service or task misconfiguration is present."
family: network-ad-and-endpoint
tier: leaf
triggers: ["service abuse", "scheduled task abuse", "service permissions", "sc create", "schtasks abuse"]
cwe: [CWE-269]
owasp: []
attack: [T1543]
capec: [CAPEC-233]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Windows Service and Scheduled Task Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Services and scheduled tasks are the two native mechanisms for running code as another identity, and both are configuration objects that Windows will faithfully execute. A service runs as its configured account with a defined failure and restart policy; a scheduled task runs with a stored credential or a service account and can be triggered by time, logon, or an event. Because both are legitimate administration primitives, the finding is almost always the authorisation over the object rather than the mechanism: who may create, modify, or run it.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the goal is immediate execution as SYSTEM **THEN** a service is the shorter path, but it leaves a service object that must be removed
2. **IF** the execution must be deferred or triggered **THEN** a scheduled task with an event or logon trigger is the mechanism; document the trigger as part of the finding
3. **IF** the object must survive a reboot **THEN** that is persistence; see [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md)
4. **IF** the mechanism is used by an installer **THEN** legitimate installers create services and tasks; check the signer and the source path before reporting
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `windows-service-and-scheduled-task-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The service path or DACL is the flaw | [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) | Escalation rather than execution |
| The task or service is for persistence | [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) | Durability and triggers |
| The task is created remotely | [`windows-lateral-movement-smb-and-remote-execution`](../windows-lateral-movement-smb-and-remote-execution/SKILL.md) | Remote creation as lateral movement |
| The mechanism is a WMI subscription | [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) | Event-driven persistence |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the authorising right for the object class.** Creating a service requires `SC_MANAGER_CREATE_SERVICE` on the SCM or local administrator; creating a task requires write on the task folder or the `Task Scheduler` service rights. Read the object's DACL, because the right is the finding.
2. **Read the object's current definition before creating anything.** For a service, the binary path, account, start type and failure actions; for a task, the XML with its triggers, principal and stored credential flag. Existing definitions are the baseline against which a new object stands out.
3. **Baseline the target's normal object population.** A hardened server has a small, stable set of services and tasks. A new service in `System32` with a suspicious name, or a task created outside a GPO, is the anomaly. The differential is the object population, not a single event.
4. **Set the stop condition at one created object and remove it.** Both mechanisms create durable state. Create one, capture the telemetry, and delete it within the same authorised window; leaving a service behind is a production change.
5. **State the proof.** Proof is the object definition plus the event that records its creation: 7045 for a service, 4698 for a task, and 4697 for a service installed through the security log. The execution event alone does not prove the mechanism.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Service Control Manager 7045 | Proves a service was installed, with `Service Name`, `Image Path` and `Service Account`; any Windows host. |
| Windows Security 4698 | Proves a scheduled task was created, with the task name and the creating principal; any Windows host. |
| Windows Security 4697 | Proves a service was installed through the security channel, which survives some log-clearing attempts; any Windows host. |
| Task XML with `LogonType: Password` | Proves a stored credential accompanies the task, which is a DPAPI or LSA secret exposure; any Windows host. |
| Service failure actions with a restart | Proves the service will restart after termination, which matters for cleanup and for persistence assessment; any Windows host. |

## Worked Contrast

**Weak configuration — any authenticated user can create a service or task on a member server:**

```powershell
sc.exe sdshow SCMANAME
# the SCM security descriptor grants SERVICE_CREATE to BUILTIN\Users,
# so a non-administrator can install a service running as LocalSystem
```

**Hardened configuration — service creation restricted to administrators and task folders ACL'd:**

```powershell
# restore the default SCM descriptor so only Administrators hold SERVICE_CREATE
sc.exe sdset SCMANAME "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
# and restrict write on \Windows\System32\Tasks to Administrators
# verification: a standard user's sc create now returns access denied
```

**Why this matters:** the mechanism is legitimate, so the control is the DACL on the SCM and the task folder, and the verification is a creation attempt failing for a non-administrative principal.

## When It Is NOT This Issue

- **A service created by a signed installer.** Installers legitimately create services; verify the signature and the source path before reporting the object as malicious.
- **A task created by a GPO.** Group Policy preferences create tasks with a documented owner; check the GPO linkage before treating the task as anomalous.
- **A service with a legitimate vendor path and account.** The presence of a service is not a finding; the finding is an unexpected binary path, account, or a DACL that permits modification.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-service-and-scheduled-task-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-service-and-scheduled-task-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-service-and-scheduled-task-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1543]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-service-and-scheduled-task-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1543`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/hacktricks (2), CYBER_CPT/expku (2), CYBER_CPT/sigmahq (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
