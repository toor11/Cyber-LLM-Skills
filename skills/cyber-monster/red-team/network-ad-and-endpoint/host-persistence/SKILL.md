---
name: host-persistence
description: "Establishes persistence on compromised hosts: registry run keys, services, scheduled tasks, WMI subscriptions, startup folders, shell profiles and cron, with detection notes per mechanism. Use when sustained access must survive reboot or logoff."
family: network-ad-and-endpoint
tier: core
triggers: ["persistence", "host persistence", "registry run key", "wmi subscription", "scheduled task persistence"]
cwe: [CWE-269]
owasp: []
attack: [T1547]
capec: [CAPEC-563]
related: [host-persistence-registry-and-service-persistence, host-persistence-scheduled-and-wmi-persistence, host-persistence-linux-and-macos-persistence, network-recon-and-port-scanning]
---

# Host Persistence - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Host persistence is the set of mechanisms that survive a reboot, a logoff, or a service restart. On Windows the durable surfaces are services, scheduled tasks, registry run keys, WMI subscriptions and DLL search paths; on Linux and macOS they are systemd units and timers, cron, shell profiles, launch agents and daemons, and login hooks. The methodology treats each surface as a configuration object: read its current population, find the entries that are not explained by a package or a policy, and verify that the entry executes.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the host is Windows **THEN** use [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) and [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md)
2. **IF** the host is Linux or macOS **THEN** use [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md)
3. **IF** the mechanism must survive on a domain controller **THEN** see [`active-directory-persistence`](../active-directory-persistence/SKILL.md) for directory-level mechanisms
4. **IF** the mechanism must survive reimaging **THEN** no host mechanism does; that is a supply-chain or image question rather than a persistence one
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `host-persistence` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Windows registry and service surfaces | [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) | Run keys, services, COM hijack |
| Windows scheduled tasks and WMI subscriptions | [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) | Task XML and event subscriptions |
| Linux and macOS surfaces | [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) | systemd, cron, launchd, profiles |
| Directory-level persistence | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | SID history, krbtgt, AdminSDHolder |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate every autostart surface, not one.** Windows: `Run`, `RunOnce`, services, scheduled tasks, WMI subscriptions, `Winlogon` shell and userinit, and printing monitors. Linux: systemd units and timers, cron, `rc.local`, profile scripts, and `ld.so.preload`. macOS: launch agents and daemons, login items, and configuration profiles. A single-surface review always misses something.
2. **Compare the population against package or policy provenance.** On Windows, the file's signature and the task's author; on Linux, `dpkg -S` or `rpm -qf`; on macOS, `pkgutil --file-info` and the code signature. An entry with no provenance is the candidate set.
3. **Verify that the entry would execute.** A run key naming a deleted binary is noise; a service whose path is a writable directory is a finding. Check the target's existence and permission, since persistence requires the target to run.
4. **Baseline against a freshly imaged host of the same build.** Autostart populations are stable between images. A diff against a reference image is the cleanest possible evidence, and it also produces the remediation list.
5. **State the proof and stop.** Proof is the autostart entry plus the target file's provenance and permission. Rebooting to observe execution is a state change on a production host and is not required.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Run` and `RunOnce` registry values | Proves per-user or machine autostart at logon; any Windows host. |
| Service with a binary outside `System32` and no signature | Proves autostart at boot with no vendor provenance; any Windows host. |
| Scheduled task outside `\Microsoft\` | Proves autostart by trigger, often with a stored credential; any Windows host. |
| systemd unit in `/etc/systemd/system` with no package owner | Proves autostart at boot on Linux with no distribution provenance; any systemd host. |
| launchd plist in `~/Library/LaunchAgents` | Proves per-user autostart on macOS without administrator rights; any macOS host. |

## Worked Contrast

**Weak configuration — unrestricted user write access to machine-wide autostart locations:**

```powershell
Get-Acl 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Select-Object -ExpandProperty Access
# BUILTIN\Users has SetValue on the machine Run key, so any interactive user
# can add a machine-wide autostart entry
```

**Hardened configuration — autostart keys writable only by administrators and SYSTEM:**

```powershell
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$acl = Get-Acl $path
$acl.Access | Where-Object { $_.IdentityReference -match 'Users|Everyone' } |
    ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
Set-Acl -Path $path -AclObject $acl
# verification: the same ACE read shows only Administrators and SYSTEM
```

**Why this matters:** persistence needs a writable autostart surface, so the control is the ACL on that surface and the verification is the descriptor rather than a reboot test.

## When It Is NOT This Issue

- **An entry belonging to a signed vendor product.** Autostart entries are normal; provenance through signature or package ownership separates the expected from the anomalous.
- **A per-user autostart entry on the user's own profile.** A user writing to their own `Run` key or `LaunchAgents` is not a privilege boundary crossing; the finding requires machine-wide scope or another user's profile.
- **A disabled entry.** An autostart entry whose target is missing or whose service is disabled does not execute; check the state before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `host-persistence` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `host-persistence` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: host-persistence
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1547]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `host-persistence` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1547`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 21 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/github_security_md (13), CYBER_CPT/awesome_list (4), hackerone_disclosed_reports (1), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
