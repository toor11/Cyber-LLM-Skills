---
name: host-persistence-scheduled-and-wmi-persistence
description: Scheduled task and WMI persistence. Covers scheduled task creation, WMI event subscription persistence and task file manipulation with detection considerations. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["wmi persistence", "scheduled task persistence", "event subscription persistence"]
cwe: [CWE-269]
owasp: []
attack: [T1547]
capec: [CAPEC-563]
related: [host-persistence, host-persistence-registry-and-service-persistence, host-persistence-linux-and-macos-persistence, network-recon-and-port-scanning]
parent: host-persistence
---

# Host Persistence Scheduled and Wmi Persistence - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Scheduled tasks and WMI event subscriptions are trigger-driven: a task fires on a time, a logon, an idle state or an event, and a WMI subscription fires whenever a matching event reaches the `__EventFilter`. Both store a full definition — action, trigger, principal and sometimes a credential — so the durable object is self-describing and survives reboot without any file on disk. That property is why they are preferred over registry autostarts by operators who need to blend with administration.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`host-persistence`](../host-persistence/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the trigger must be an event rather than a time **THEN** WMI subscriptions or an event-triggered task are the mechanisms; both are pure configuration objects
3. **IF** the task must run as another user **THEN** the task principal stores the credential, which is itself a secret exposure
4. **IF** the mechanism must survive on a server with no interactive logons **THEN** a boot trigger or a WMI subscription in `root\subscription` works; a logon trigger does not
5. **IF** the mechanism is a service **THEN** see [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `host-persistence-scheduled-and-wmi-persistence` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Registry run keys and services | [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) | Value-based autostart |
| Linux and macOS triggers | [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) | systemd timers and launchd |
| The task is created remotely | [`windows-lateral-movement-smb-and-remote-execution`](../windows-lateral-movement-smb-and-remote-execution/SKILL.md) | Remote creation as movement |
| The mechanism is directory-level | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | AD-level durability |
| Need the class-level branch table first | [`host-persistence`](../host-persistence/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate tasks outside the Microsoft namespace first.** `Get-ScheduledTask` filtered to non-`\Microsoft\` paths gives the third-party and anomalous set. Then read each task's XML, because the trigger, principal and credential flag are only visible there.
2. **Enumerate the WMI subscription triad.** `__EventFilter`, `CommandLineEventConsumer` or `ActiveScriptEventConsumer`, and `__FilterToConsumerBinding` under `root\subscription`. All three must exist for the mechanism to fire, so their presence together is the finding.
3. **Read the principal and credential state.** A task with `LogonType: Password` stores a credential; a task with `S4U` does not store one but still runs as the account. The distinction matters for both impact and cleanup.
4. **Baseline against a reference image or a GPO-driven population.** Tasks created by group policy have a documented author and a source; a task with a blank author or a random name is the candidate. WMI subscriptions are absent on most hosts, so any presence deserves review.
5. **State the proof and stop.** Proof is the task XML or the three subscription objects plus the creating principal recorded in 4698 or 5861. Waiting for the trigger to fire is optional and is a state change.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Task outside `\Microsoft\` with a blank author | Proves a task created outside policy or installer, which is the candidate set; any Windows host. |
| Task XML with `LogonType: Password` | Proves a stored credential alongside the task, an LSA or DPAPI secret exposure; any Windows host. |
| `__EventFilter` with a `CommandLineEventConsumer` | Proves event-driven execution with no on-disk artefact beyond the WMI repository; any Windows host. |
| `__FilterToConsumerBinding` referencing a named consumer | Proves the subscription is complete and will fire, which distinguishes a staged object from a live one; any Windows host. |
| Task trigger `BootTrigger` with `SYSTEM` principal | Proves execution before any interactive logon, the most durable form; any Windows host. |

## Worked Contrast

**Weak configuration — task creation permitted to any authenticated user, and WMI subscriptions unmonitored:**

```powershell
$acl = Get-Acl 'C:\Windows\System32\Tasks'
$acl.Access | Where-Object { $_.IdentityReference -match 'Users|Authenticated' }
# any authenticated user can register a task in the root task folder,
# and no monitoring exists for root\subscription objects
```

**Hardened configuration — task folder restricted and WMI subscription creation audited:**

```powershell
$path = 'C:\Windows\System32\Tasks'
$acl = Get-Acl $path
$acl.Access | Where-Object { $_.IdentityReference -match 'Users|Authenticated' } |
    ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
Set-Acl -Path $path -AclObject $acl
# and enable WMI-Activity operational logging to capture subscription creation
# verification: a standard user's Register-ScheduledTask now fails with access denied
```

**Why this matters:** the mechanism needs a writable task store or an unmonitored subscription namespace, so the controls are the folder ACL and the WMI audit, verified by a failed registration and a logged subscription event.

## When It Is NOT This Issue

- **A task under `\Microsoft\Windows\`.** These are operating-system tasks; their presence is expected and their author is Microsoft.
- **A WMI subscription installed by a management agent.** Some monitoring products use permanent subscriptions; check the consumer's target against the agent inventory before reporting.
- **A task with a missing target binary.** The task cannot execute; check the action path exists before assigning severity.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `host-persistence-scheduled-and-wmi-persistence` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `host-persistence-scheduled-and-wmi-persistence` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: host-persistence-scheduled-and-wmi-persistence
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1547]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`host-persistence`](../host-persistence/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `host-persistence-scheduled-and-wmi-persistence` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1547`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/github_security_md (6), CYBER_CPT/sigmahq (4), CYBER_CPT/oxdf (4), CYBER_CPT/pstips (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
