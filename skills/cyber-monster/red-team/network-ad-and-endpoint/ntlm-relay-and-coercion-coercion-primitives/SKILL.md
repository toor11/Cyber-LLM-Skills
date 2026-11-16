---
name: ntlm-relay-and-coercion-coercion-primitives
description: NTLM authentication coercion primitives. Covers forced authentication through PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce and MS-RPRN paths, including patch-level availability. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["petitpotam", "printerbug", "dfscoerce", "coerce authentication", "shadowcoerce"]
cwe: [CWE-294]
owasp: []
attack: [T1557]
capec: [CAPEC-589]
related: [ntlm-relay-and-coercion, ntlm-relay-and-coercion-relay-targets, network-recon-and-port-scanning, service-enumeration]
parent: ntlm-relay-and-coercion
---

# NTLM Relay and Coercion Coercion Primitives - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

A coercion primitive is an RPC interface that accepts a UNC path and then makes the server authenticate to it. Each primitive has its own service dependency and its own patching history: MS-RPRN needs the print spooler, MS-EFSR needs the EFS service, MS-DFSNM needs the DFS namespace service, MS-FSRVP needs the File Server VSS agent, and MS-EVEN needs the event log service. The crucial insight is that 'patched' is usually the wrong frame — a primitive is typically unavailable because its backing service is not running, and enabling that service restores it.

- **CWE-269 (Improper Privilege Management):** privilege, delegation or ACL handling lets a principal act outside its intended sphere.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the spooler is disabled on the target **THEN** MS-RPRN will not work; check EFS, DFS and the VSS agent before concluding coercion is impossible
3. **IF** the target is a Windows Server 2025 host **THEN** MS-EFSR requires the EFS service to be running, which is trigger-start by default; a bind attempt alone will not start it
4. **IF** a bind succeeds but no outbound connection appears **THEN** the RPC interface is reachable but the specific call path did not construct a usable UNC; try a different method on the same interface
5. **IF** NTLM outbound is restricted on the victim **THEN** coercion will produce no authentication regardless of the RPC result; check the policy first
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `ntlm-relay-and-coercion-coercion-primitives` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A target must be selected for the relayed authentication | [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) | Signing and EPA state |
| The endpoint is AD CS web enrollment | [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md) | ESC8 conditions |
| The coercion comes from name resolution | [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md) | Broadcast names instead of RPC |
| The coercion is only the first hop | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Reaching the listener across a boundary |
| Need the class-level branch table first | [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate which services the target is actually running.** Each primitive has exactly one service dependency. Read the service state over SCM or infer it from the RPC endpoint list, because a primitive whose service is stopped cannot work and no amount of retrying changes that.
2. **Send one primitive at a time and watch for the outbound connection.** The RPC return status is not the evidence; the evidence is a connection from the victim to the listener. A success status with no connection means the call path did not reach the authentication stage.
3. **Distinguish a precondition gap from a patch.** If the interface binds and the call succeeds but no authentication appears, the service is reachable but the specific operation is no longer coercive. If the bind fails, the service is not running. These are different findings and should be reported differently.
4. **Set the stop condition.** Stop at the first primitive that produces an outbound authentication. Trying every primitive in sequence against the same target produces a distinctive RPC alert pattern and adds nothing after the first success.
5. **State the proof.** Proof is a listener-side capture of an SMB or HTTP authentication from the victim's machine account, with the RPC call that produced it identified. The RPC status alone is not proof and must not be reported as one.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `MS-RPRN` `RpcRemoteFindFirstPrinterChangeNotificationEx` | Proves spooler-based coercion; any Windows host with the Print Spooler running, which hardened servers and DCs should not. |
| `MS-EFSR` `EfsRpcOpenFileRaw` / `EfsRpcAddUsersToFile` | Proves EFS-based coercion; requires the EFS service running, which is trigger-start by default on current Windows. |
| `MS-DFSNM` `NetrDfsRemoveStdRoot` | Proves DFS-based coercion; requires a DFS namespace service, common on domain controllers. |
| `MS-FSRVP` `IsPathSupported` | Proves VSS-agent coercion; requires the File Server VSS Agent Service. |
| `MS-EVEN` `ElfrOpenBELW` | Proves event-log-based coercion; requires the Event Log service, which is always running, making this the most portable primitive where the interface is reachable. |

## Worked Contrast

**Weak configuration — print spooler left running on member servers and domain controllers:**

```powershell
Get-Service Spooler | Select-Object Name,Status,StartType
# Spooler Running / Automatic on every server, so MS-RPRN coercion is available estate-wide
Get-Service Spooler -ComputerName dc01,fs01,app01
```

**Hardened configuration — spooler disabled where printing is not required:**

```powershell
Get-Service Spooler -ComputerName dc01,fs01,app01 | ForEach-Object {
    Set-Service -Name Spooler -StartupType Disabled -ComputerName $_.MachineName
    Stop-Service -Name Spooler -ComputerName $_.MachineName -Force
}
# verification: the MS-RPRN bind is rejected and no outbound authentication follows
```

**Why this matters:** the primitive is available only because its backing service runs, so the control is service state and the verification is the RPC bind failing rather than the coercion returning an error.

## When It Is NOT This Issue

- **An RPC bind rejection read as a patch.** A rejected bind means the service is not running, which is a configuration state that could change; it is not a code fix.
- **DFSCoerce calls completing with no callback.** The interface is reachable but the call did not produce an authentication on current Windows builds; that is a precondition gap, not a successful coercion.
- **A listener that receives its own traffic.** A capture on the assessment host that shows only its own RPC calls proves nothing about the victim; confirm the source address of the authentication.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ntlm-relay-and-coercion-coercion-primitives` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ntlm-relay-and-coercion-coercion-primitives` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ntlm-relay-and-coercion-coercion-primitives
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-294 | Mapping: T1557]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ntlm-relay-and-coercion-coercion-primitives` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-294, T1557`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (4), CYBER_CPT/github_security_md (3), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
