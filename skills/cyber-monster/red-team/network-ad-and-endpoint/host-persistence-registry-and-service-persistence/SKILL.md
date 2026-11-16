---
name: host-persistence-registry-and-service-persistence
description: Registry and service persistence. Covers run keys, services, Winlogon shell, IFEO and COM hijack persistence with detection notes for each. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["registry persistence", "run key persistence", "service persistence", "com hijack"]
cwe: [CWE-269]
owasp: []
attack: [T1547]
capec: [CAPEC-563]
related: [host-persistence, host-persistence-scheduled-and-wmi-persistence, host-persistence-linux-and-macos-persistence, network-recon-and-port-scanning]
parent: host-persistence
---

# Host Persistence Registry and Service Persistence - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

On Windows the registry is the directory of autostart configuration: `Run` and `RunOnce` keys, service definitions under `Services`, `Winlogon` shell and userinit values, COM registration that redirects a `CLSID` to a user-writable DLL, and image-file execution options that inject a debugger into every launch of a binary. Each is a configuration object with an ACL, so the finding pairs the entry with the permission that allowed it.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`host-persistence`](../host-persistence/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** a `Run` key is writable by a broad group **THEN** any interactive user can persist machine-wide; the ACL is the finding
3. **IF** a service points at a binary in a writable directory **THEN** the service reloads the binary at boot; see [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md)
4. **IF** a COM `CLSID` is registered to a user-writable DLL **THEN** the DLL loads in the context of whichever process instantiates the object, which is often privileged
5. **IF** an `Image File Execution Options` debugger value exists **THEN** the named binary runs under the configured debugger, which is a reliable execution hijack
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `host-persistence-registry-and-service-persistence` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Scheduled tasks and WMI subscriptions | [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) | Trigger-based mechanisms |
| The host is Linux or macOS | [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) | Different autostart surfaces |
| The persistence is directory-level | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | AD mechanisms |
| The service is the escalation rather than the persistence | [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) | Escalation semantics |
| Need the class-level branch table first | [`host-persistence`](../host-persistence/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate each registry surface with its ACL.** `Run` and `RunOnce` in both hives, `Winlogon` `Shell` and `Userinit`, `Services` subkeys, `InprocServer32` under `CLSID`, and `Image File Execution Options`. Reading the value alone is not enough; the ACL decides who could have written it.
2. **Check the target file's provenance.** Signature, path and permission for every executable named by an entry. A signed binary in `Program Files` is expected; an unsigned binary in a user profile is not.
3. **Verify the mechanism would execute.** A `Run` key fires at logon for the named user, a service at boot, a COM hijack when the object is instantiated, and an IFEO debugger on every launch of the named image. The trigger decides the certainty, so state it.
4. **Baseline against a reference image.** Autostart registry populations are stable. A diff against a known-good image of the same build yields a short candidate list, which is both the evidence and the remediation input.
5. **State the proof and stop.** Proof is the registry value, its ACL, and the target file's provenance. Reboot or logon to observe execution is optional and is a state change on a production host.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `HKLM\...\Run` value with a user-writable target | Proves machine-wide autostart at every logon with a replaceable binary; any Windows host. |
| Service `ImagePath` outside `System32` with no signature | Proves boot-time execution with no vendor provenance; any Windows host. |
| `Winlogon\Userinit` value with an extra path | Proves execution at logon in the user's session, a classic durable mechanism; any Windows host. |
| `CLSID\{...}\InprocServer32` pointing at a user-writable DLL | Proves execution in whichever process instantiates the object; any Windows host. |
| `Image File Execution Options\<image>\Debugger` value | Proves the named binary runs under an attacker-chosen debugger on every launch; any Windows host. |

## Worked Contrast

**Weak configuration — machine-wide Run key writable by interactive users:**

```powershell
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
(Get-Acl $path).Access | Where-Object { $_.RegistryRights -match 'SetValue' }
# BUILTIN\Users holds SetValue, so any user adds a machine-wide autostart entry
```

**Hardened configuration — Run key writable only by Administrators and SYSTEM:**

```powershell
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$acl = Get-Acl $path
$acl.Access | Where-Object { $_.IdentityReference -match 'Users|Everyone' } |
    ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
Set-Acl -Path $path -AclObject $acl
# verification: the descriptor read shows only Administrators and SYSTEM with SetValue
```

**Why this matters:** the durable capability is a writable autostart key, so the control is its ACL and the verification is the registry descriptor rather than a detection rule.

## When It Is NOT This Issue

- **A signed vendor `Run` entry.** Autostart entries from installed software are expected; provenance is the discriminator.
- **A per-user `HKCU` entry.** The user writing their own logon autostart is not a boundary crossing; the finding is machine-wide scope or another user's hive.
- **An `InprocServer32` for an unregistered or broken COM object.** A `CLSID` with no matching file cannot execute; check the target's existence before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `host-persistence-registry-and-service-persistence` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `host-persistence-registry-and-service-persistence` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: host-persistence-registry-and-service-persistence
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1547]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`host-persistence`](../host-persistence/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `host-persistence-registry-and-service-persistence` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1547`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/sigmahq (4), CYBER_CPT/atomic_red_team (2), CYBER_CPT/ctf_search (2), SecEval/attck (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
