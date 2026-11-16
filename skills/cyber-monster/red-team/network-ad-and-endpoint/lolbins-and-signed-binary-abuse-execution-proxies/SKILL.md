---
name: lolbins-and-signed-binary-abuse-execution-proxies
description: LOLBin execution proxies. Covers executing payloads through signed utilities such as mshta, rundll32, regsvr32, installutil and msbuild with detection notes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["mshta", "rundll32", "regsvr32", "installutil", "msbuild execution"]
cwe: [CWE-284]
owasp: []
attack: [T1218]
capec: [CAPEC-564]
related: [lolbins-and-signed-binary-abuse, lolbins-and-signed-binary-abuse-download-and-staging, lolbins-and-signed-binary-abuse-driver-blocklist-gaps, network-recon-and-port-scanning]
parent: lolbins-and-signed-binary-abuse
---

# Lolbins and Signed Binary Abuse Execution Proxies - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)

## Mechanism and Preconditions

An execution proxy is a signed binary that will run content of a type it is not normally associated with: an HTA through `mshta`, a DLL export through `rundll32`, a scriptlet through `regsvr32`, a .NET assembly through `installutil`, or a project file through `msbuild`. The technique is a pairing problem, because each binary accepts a narrow set of inputs; the defender's advantage is that the pairing is fixed and therefore enumerable.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the content is an HTA or inline script **THEN** `mshta` is the proxy; the parent process and the URL argument are the discriminating fields
3. **IF** the content is a DLL or an ordinal export **THEN** `rundll32` is the proxy; a non-DLL filename with `,#1` is the 2025 variant
4. **IF** the content is a scriptlet XML **THEN** `regsvr32 /s /u /i:<url> scrobj.dll` runs it without registration
5. **IF** the content is a .NET assembly **THEN** `installutil` or `msbuild` will load it; both are signed and often permitted
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `lolbins-and-signed-binary-abuse-execution-proxies` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The binary must download rather than execute | [`lolbins-and-signed-binary-abuse-download-and-staging`](../lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md) | Ingress and staging |
| The content is a driver | [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](../lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) | Kernel-mode loading |
| The invocation was a user instruction | [`initial-access-via-phishing`](../initial-access-via-phishing/SKILL.md) | Fake-captcha delivery |
| The question is which telemetry observes it | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | Event pipeline coverage |
| Need the class-level branch table first | [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify which proxy the environment's policy leaves available.** Application control often blocks some binaries and leaves others for business reasons. The available set is the actual risk surface, so read the policy rather than assuming.
2. **Establish the pairing the proxy accepts.** `mshta` takes an HTA path or URL; `rundll32` takes `dll,entrypoint` or `file,#ordinal`; `regsvr32` takes a scriptlet; `installutil` takes an assembly. The pairing is what a detection rule names, so record it exactly.
3. **Baseline the proxy's normal invocation in the estate.** `rundll32` is invoked constantly by legitimate software, so the baseline is essential. The differential is an unusual parent, a non-system path, or an argument containing a URL or ordinal.
4. **Name the stop condition and the containment rule.** Stop once the invocation and its effect are recorded. Do not leave the staged content behind, and keep the process tree for the detection rule.
5. **State the proof.** Proof is the command line, the parent process, and the file the proxy consumed, plus the policy state that allowed the binary. The signature is not the finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `mshta <url>` with `explorer.exe` parent | Proves instruction-driven remote HTA execution without a saved file; Windows. |
| `rundll32 <file>,#1` where the file is not a DLL | Proves ordinal execution of a renamed payload, a documented 2025 ClickFix variant; Windows. |
| `regsvr32 /s /u /i:<url> scrobj.dll` | Proves scriptlet execution through a signed binary, with no registration side effect; Windows. |
| `installutil /logfile= /LogToConsole=false <assembly>` | Proves .NET assembly execution through a signed utility; Windows with .NET Framework. |
| `msbuild <project>` with an inline task | Proves build-engine execution of embedded code; Windows with MSBuild installed. |

## Worked Contrast

**Weak configuration — script hosts permitted with any argument and no parent-process constraint:**

```powershell
# application control allows mshta.exe, rundll32.exe and regsvr32.exe from any path
# with any argument, so a downloaded file can be proxied into execution
Get-ChildItem 'C:\Windows\System32\mshta.exe','C:\Windows\System32\rundll32.exe' |
    Select-Object Name,VersionInfo
```

**Hardened configuration — script hosts constrained by path and argument, with a parent-process rule:**

```powershell
# application control: allow mshta only from System32 with an .hta argument under a managed path,
# and deny rundll32 loading files outside System32
# plus an EDR rule on parent process: explorer.exe -> mshta.exe with a URL argument
# verification: the same invocation produces a code-integrity block or an EDR alert
```

**Why this matters:** the proxy is legitimate software, so the control must constrain the path and the argument rather than the binary, and the verification is a block or alert on the constrained invocation.

## When It Is NOT This Issue

- **`rundll32` invoked by a printer driver or shell extension.** These are constant, legitimate invocations from `System32` with documented entry points; the baseline separates them.
- **`mshta` used by a line-of-business application.** Some applications still ship HTA front ends; check the path and signature before reporting.
- **`regsvr32` registering a signed in-box DLL.** Registration is its purpose; the `/i:<url>` form is what matters.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `lolbins-and-signed-binary-abuse-execution-proxies` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `lolbins-and-signed-binary-abuse-execution-proxies` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: lolbins-and-signed-binary-abuse-execution-proxies
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1218]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) - Blue Detection/Defense Counterpart
- [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`lolbins-and-signed-binary-abuse-download-and-staging`](../lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](../lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `lolbins-and-signed-binary-abuse-execution-proxies` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1218`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/atomic_red_team (18), CYBER_CPT/oxdf (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
