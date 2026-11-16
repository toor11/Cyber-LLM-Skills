---
name: lolbins-and-signed-binary-abuse
description: "Executes and disguises activity using living-off-the-land binaries, signed Microsoft utilities, installers and drivers: LOLBAS, GTFOBins, LOLDrivers, and proxy execution. Use to avoid dropping custom tooling."
family: network-ad-and-endpoint
tier: core
triggers: ["lolbins", "lolbas", "gtfobins", "loldrivers", "proxy execution", "signed binary abuse"]
cwe: [CWE-284]
owasp: []
attack: [T1218]
capec: [CAPEC-564]
related: [lolbins-and-signed-binary-abuse-execution-proxies, lolbins-and-signed-binary-abuse-download-and-staging, lolbins-and-signed-binary-abuse-driver-blocklist-gaps, network-recon-and-port-scanning]
---

# Lolbins and Signed Binary Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)

## Mechanism and Preconditions

A signed operating-system binary that can download, decode, execute or proxy execution is a reliable way to run code without introducing an unsigned file. The technique works because application control and signature checks validate the binary, not its arguments. Since 2025 the dominant delivery pattern uses a signed binary to load content from a WebDAV or `@SSL` path, so the network indicator rather than the binary is the discriminating signal.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the binary must download something **THEN** use [`lolbins-and-signed-binary-abuse-download-and-staging`](../lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md)
2. **IF** the binary must execute another program or script **THEN** use [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md)
3. **IF** the binary must load a driver **THEN** use [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](../lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md)
4. **IF** the binary is invoked by a user instruction rather than by malware **THEN** that is the fake-captcha pattern; the `RunMRU` entry is the artefact, so pair with [`initial-access-via-phishing`](../initial-access-via-phishing/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `lolbins-and-signed-binary-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Download and staging behaviour | [`lolbins-and-signed-binary-abuse-download-and-staging`](../lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md) | Ingress rather than execution |
| Execution proxy selection | [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) | Which binary proxies which file type |
| Driver blocklist gaps | [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](../lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) | Kernel-mode loading |
| The binary is used after endpoint compromise | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | Telemetry that observes it |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish the application control policy in force.** App Control for Business, Smart App Control or a third-party allowlist decides whether the technique is even available. Read the policy state, because a signed binary allowed by default is the entire precondition.
2. **Map the binary to the file type it can execute.** `mshta` for HTA, `rundll32` for DLL exports and ordinals, `regsvr32` for scriptlets, `installutil` for .NET, `msbuild` for project files. The pairing is what makes the technique work, and the pairing is what a detection rule keys on.
3. **Baseline the binary's normal invocation.** Capture its normal command lines and parent processes in the estate. The differential is an unusual parent (`explorer.exe`, `wmiPrvSE.exe`) or an unusual argument (a URL, an ordinal, a remote path).
4. **Name the stop condition and the containment rule.** Stop at the first invocation that proves the policy permits the abuse. Do not leave a staged file behind, and record the process tree so the detection rule can be written from evidence.
5. **State the proof.** Proof is the command line, the parent process, and the file or URL the binary consumed, plus the application control state that allowed it. The binary's signature is not the finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `mshta.exe` with a URL argument and `explorer.exe` parent | Proves an instruction-driven HTA execution without a local file; Windows. |
| `rundll32.exe` loading a non-DLL by ordinal (`file,#1`) | Proves ordinal-based execution of a renamed payload, a 2025-era variant; Windows. |
| `regsvr32.exe /s /u /i:<url> scrobj.dll` | Proves scriptlet execution through a signed binary, no registration required; Windows. |
| `certutil -urlcache -f <url> <file>` | Proves download and staging through a certificate utility; Windows. |
| Application control policy in audit-only mode | Proves the control exists but does not enforce, which is why the abuse succeeds; Windows. |

## Worked Contrast

**Weak configuration — application control in audit-only mode with `mshta` and `rundll32` fully permitted:**

```powershell
$policy = Get-CIPolicy -FilePath .\policy.xml
# audit mode: the policy logs but does not block, so any signed binary runs
# with any argument, including a remote HTA or an ordinal load
```

**Hardened configuration — enforced allowlist that constrains script hosts and network-capable binaries:**

```powershell
Set-RuleOption -FilePath .\policy.xml -Option 3 -Delete   # remove audit-only
# add deny rules for mshta.exe, regsvr32.exe and rundll32.exe from user paths,
# and allow only the specific signed binaries the business needs
ConvertFrom-CIPolicy .\policy.xml .\policy.bin
# verification: the same invocation is blocked with a code-integrity event
```

**Why this matters:** the technique depends on an allow-by-default posture for signed binaries, so the control is the enforced policy and the verification is a code-integrity block event rather than a detection alert.

## When It Is NOT This Issue

- **A signed binary invoked by legitimate software.** Installers and management agents use these binaries routinely; the discriminator is the parent process and the argument shape.
- **`rundll32` loading an in-box DLL with a documented entry point.** That is normal Windows behaviour; only an unusual argument pattern or path is a finding.
- **`certutil` used to inspect a certificate.** The utility is a certificate tool first; the download arguments are what matter.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `lolbins-and-signed-binary-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `lolbins-and-signed-binary-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: lolbins-and-signed-binary-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1218]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) - Blue Detection/Defense Counterpart
- [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`lolbins-and-signed-binary-abuse-download-and-staging`](../lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](../lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `lolbins-and-signed-binary-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1218`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 39 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/mitre_attack_enterprise (12), CYBER_CPT/sigmahq (11), SecEval/attck (5), cyber-security/vulnerability-intelligence__mitre-attack-techniques.json (5) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
