---
name: lolbins-and-signed-binary-abuse-driver-blocklist-gaps
description: LOLDrivers and driver blocklist gaps. Covers locating signed-but-vulnerable drivers, checking blocklist status, and the operational constraints of loading them. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["loldrivers", "vulnerable signed driver", "driver blocklist"]
cwe: [CWE-284]
owasp: []
attack: [T1218]
capec: [CAPEC-564]
related: [lolbins-and-signed-binary-abuse, lolbins-and-signed-binary-abuse-execution-proxies, lolbins-and-signed-binary-abuse-download-and-staging, network-recon-and-port-scanning]
parent: lolbins-and-signed-binary-abuse
---

# Lolbins and Signed Binary Abuse Driver Blocklist Gaps - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)

## Mechanism and Preconditions

The driver blocklist is a deny-list, and a deny-list has gaps by construction: a driver absent from the list loads even when it contains a usable primitive, and the list ships on a quarterly cadence plus monthly updates, so a host that missed either is behind. Since 2025 the notable pattern is not a new vulnerability but reuse of an old driver version whose hash is absent from both the Microsoft blocklist and community catalogues, signed and re-signed into thousands of variants that keep the signature valid.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the driver hash is on the blocklist **THEN** the driver will not load on a current host; the finding is that the host accepted it previously or that HVCI is off
3. **IF** the driver is absent from the blocklist but catalogued elsewhere **THEN** that is a blocklist gap; record the catalogue entry and the host's blocklist version
4. **IF** the driver is a re-signed variant **THEN** hash-only blocking fails, so the finding is the absence of a publisher or name-based rule
5. **IF** the driver is already loaded **THEN** the blocklist prevents loading, not execution; record the load time against the policy change
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `lolbins-and-signed-binary-abuse-driver-blocklist-gaps` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A loaded driver is the escalation primitive | [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | Escalation via kernel code |
| The driver terminates security products | [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) | EDR evasion rather than escalation |
| The driver is a malware component | [`byovd-and-driver-abuse`](../byovd-and-driver-abuse/SKILL.md) | Campaign-level analysis |
| The binary is a user-mode proxy | [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) | Signed-binary execution |
| Need the class-level branch table first | [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate every kernel driver with hash and publisher.** `driverquery`, the service list filtered to kernel drivers, and a hash of each binary. Name, hash and publisher are the three keys any blocklist uses, so all three are needed.
2. **Read the blocklist version and enforcement state.** The `VulnerableDriverBlocklistEnable` value, the policy version, and whether HVCI is running. Enforcement is what matters; a blocklist present but not enforced changes nothing.
3. **Compare against both the Microsoft list and the community catalogue.** The Microsoft list is authoritative for support, the community catalogue covers drivers Microsoft has not listed. A driver present in the catalogue but absent from the blocklist is the gap, and it is the finding a report should name.
4. **Baseline a host at the current patch level.** A host with the current cumulative update and HVCI enabled is the reference. A driver that loads there but not on the reference is the gap.
5. **State the proof and stop.** Proof is the driver's hash, publisher, load state and the blocklist version in force. Loading a driver to test is a state change with crash risk and requires explicit authorisation.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Driver absent from the blocklist and present in a community catalogue | Proves a gap between the vendor's deny-list and the known-vulnerable set; any Windows host. |
| Multiple hashes of the same driver with one valid signature | Proves hash-only blocking is insufficient and publisher or name rules are needed; Windows hosts targeted by re-signed variants. |
| Driver loaded before the blocklist update was applied | Proves execution persists despite enforcement, because the blocklist governs loading; any Windows host. |
| HVCI not running while the blocklist is nominally enabled | Proves enforcement is weaker than policy suggests, since HVCI is what applies the list to many drivers; Windows 10 and 11. |
| Driver from a user profile or `%TEMP%` path | Proves the load path is user-writable, which means any local user can supply the driver; any Windows host. |

## Worked Contrast

**Weak configuration — blocklist present but not enforced, and HVCI off:**

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
    -Name VulnerableDriverBlocklistEnable
# value 0, and SecurityServicesRunning omits HVCI: the list exists but
# nothing consults it for a driver loaded from a user-writable path
```

**Hardened configuration — blocklist enforced, HVCI running, and driver loads audited:**

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
    -Name VulnerableDriverBlocklistEnable -Value 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' `
    -Name Enabled -Value 1
# verification: the value reads 1, HVCI appears in SecurityServicesRunning, and a listed driver fails to load
```

**Why this matters:** a deny-list only works when something consults it, so the controls are the enable value and HVCI, and the verification is a code-integrity failure on a listed driver.

## When It Is NOT This Issue

- **A driver in a community catalogue that Microsoft has assessed as not vulnerable.** The catalogues include abused drivers as well as vulnerable ones; check the classification.
- **A Microsoft-signed in-box driver.** These are part of the operating system and are not blocklist candidates.
- **A driver blocklist older than the last patch cycle.** That is a patch-management finding rather than a blocklist gap; state which it is.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `lolbins-and-signed-binary-abuse-driver-blocklist-gaps` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `lolbins-and-signed-binary-abuse-driver-blocklist-gaps` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: lolbins-and-signed-binary-abuse-driver-blocklist-gaps
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1218]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) - Blue Detection/Defense Counterpart
- [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`lolbins-and-signed-binary-abuse-download-and-staging`](../lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `lolbins-and-signed-binary-abuse-driver-blocklist-gaps` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1218`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/expku (3), CYBER_CPT/sigmahq (1), CYBER_CPT/oxdf (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
