---
name: ntlm-relay-and-coercion
description: "Relays and coerces NTLM authentication: SMB and HTTP relay, LDAP relay for RBCD, authentication coercion primitives, and signing and channel-binding bypasses. Use when NTLM is enabled and a coercible service exists."
family: network-ad-and-endpoint
tier: core
triggers: ["ntlm relay", "ntlm coercion", "petitpotam", "printerbug", "responder relay", "smb signing"]
cwe: [CWE-294]
owasp: []
attack: [T1557]
capec: [CAPEC-589]
related: [ntlm-relay-and-coercion-coercion-primitives, ntlm-relay-and-coercion-relay-targets, network-recon-and-port-scanning, service-enumeration]
---

# NTLM Relay and Coercion - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

NTLM relay works because the protocol authenticates a session to whoever completes the challenge, not to the party that started it. Two conditions must both hold: an authentication must be obtainable from a victim, and a target service must accept that authentication without requiring integrity. Coercion is the first half — an RPC call that makes a machine authenticate to a path you control — and signing or channel-binding requirements are what close the second half. Since the NTLM deprecation programme began, the practical targets have narrowed to services that still accept NTLM without EPA, which is why the methodology is target-selection rather than protocol abuse.

- **CWE-269 (Improper Privilege Management):** privilege, delegation or ACL handling lets a principal act outside its intended sphere.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** no authentication can be obtained from any victim **THEN** start with coercion: [`ntlm-relay-and-coercion-coercion-primitives`](../ntlm-relay-and-coercion-coercion-primitives/SKILL.md)
2. **IF** an authentication is available and needs a destination **THEN** use [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) for signing and EPA state per target
3. **IF** the estate has disabled NTLM outbound **THEN** relay from that host is not possible; check the policy before building a path
4. **IF** the target is AD CS web enrollment **THEN** ESC8: go to [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `ntlm-relay-and-coercion` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| No authentication is being produced | [`ntlm-relay-and-coercion-coercion-primitives`](../ntlm-relay-and-coercion-coercion-primitives/SKILL.md) | RPC coercion preconditions per protocol |
| A target must be chosen | [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) | Signing, EPA and LDAP signing state |
| Certificate enrollment is the target | [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md) | ESC8 endpoint conditions |
| Name resolution must be poisoned to reach the listener | [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md) | Producing authentications via broadcast names |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish whether NTLM is even permitted.** Check `RestrictSendingNTLMTraffic` and the NTLM audit events on the victim side. In estates that are mid-migration, NTLM may be blocked outbound to unknown targets, which removes the primitive regardless of coercion.
2. **Choose the coercion primitive by what the victim runs.** MS-RPRN needs the spooler, MS-EFSR needs the EFS service running, MS-DFSNM needs DFS, MS-FSRVP needs the VSS agent. Send the smallest set of RPC calls that matches the observed services, not every primitive at once.
3. **Select targets by their signing and channel-binding state.** SMB signing required, LDAP signing required, LDAP channel binding enforced, and EPA on HTTP endpoints each independently defeat relay. A target list without those four columns is a guess.
4. **Name the stop condition.** Stop at the first successful authenticated session on a target, or immediately if the coercion produces no outbound authentication. A coercion that returns success but yields no connection is a precondition gap, not a patch, and must be reported that way.
5. **State the proof.** Proof is the coerced authentication arriving at the listener, the relay completing against the target, and the target's own 4624 showing the victim's machine account authenticating from the assessment host's address. The last point is what distinguishes relay from a legitimate logon.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `WorkstationName` versus `IpAddress` mismatch in 4624 | Proves relay: the logon claims the victim's name but arrives from a different address; any Windows target. |
| SMB signing not required | Proves the SMB relay path is open for that host; any Windows or Samba server. |
| LDAP signing not required and channel binding not enforced | Proves LDAP relay can create objects or set RBCD; domain controllers. |
| EPA disabled on an HTTP endpoint | Proves relay into that endpoint; IIS-hosted services including AD CS web enrollment. |
| Coercion RPC returning `ERROR_BAD_NETPATH` or success | Proves whether the victim attempted an outbound authentication, which is the coercion half; the RPC status alone is not proof. |

## Worked Contrast

**Weak configuration — SMB and LDAP signing optional across the estate, EPA off on internal web services:**

```powershell
# default member server: signing enabled but not required
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
# domain controllers: LDAP signing not required
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' /v LdapEnforceChannelBinding /t REG_DWORD /d 0
# coerced machine authentications can be relayed to any of these targets
```

**Hardened configuration — signing required everywhere, channel binding enforced, EPA on web endpoints:**

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' /v LdapEnforceChannelBinding /t REG_DWORD /d 2
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' /v RequireSigning /t REG_DWORD /d 1
# verification: the relay reaches session setup and fails, and the target logs 4625 not 4624
```

**Why this matters:** relay needs a target that does not verify integrity of the channel, so the controls are signing and channel binding, and the verification is the target refusing the relayed session rather than the listener failing to connect.

## When It Is NOT This Issue

- **Coercion success with no outbound connection.** An RPC call returning success only means the call was accepted; if the victim never connected to the listener, the precondition (service running, path reachable) was not met.
- **NTLM blocked outbound.** A host with `RestrictSendingNTLMTraffic=2` cannot be coerced into an NTLM authentication at all; check the policy before attributing a failure to patching.
- **Relay to a target that requires signing.** A completed TCP connection and a failed session setup is not a relay success; the target's 4625 with a signing error is the evidence of the control working.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ntlm-relay-and-coercion` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ntlm-relay-and-coercion` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ntlm-relay-and-coercion
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-294 | Mapping: T1557]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`ntlm-relay-and-coercion-coercion-primitives`](../ntlm-relay-and-coercion-coercion-primitives/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ntlm-relay-and-coercion` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-294, T1557`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 27 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/oxdf (12), CYBER_CPT/github_security_md (7), cyber-security/CyberSec-Dataset (5), CYBER_CPT/hacktricks (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
