---
name: lolbins-and-signed-binary-abuse-download-and-staging
description: LOLBin download and staging. Covers staging payloads with certutil, bitsadmin, curl and PowerShell download paths, and decoding with native utilities. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["certutil download", "bitsadmin", "certutil decode", "lolbin staging"]
cwe: [CWE-284]
owasp: []
attack: [T1218]
capec: [CAPEC-564]
related: [lolbins-and-signed-binary-abuse, lolbins-and-signed-binary-abuse-execution-proxies, lolbins-and-signed-binary-abuse-driver-blocklist-gaps, network-recon-and-port-scanning]
parent: lolbins-and-signed-binary-abuse
---

# Lolbins and Signed Binary Abuse Download and Staging - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md)

## Mechanism and Preconditions

Staging is the step between delivery and execution: content arrives through a signed binary, is written to a path the user can write, and is then executed or loaded. The technique avoids introducing an unsigned executable over the network in a way that file-transfer controls might catch, because the transfer is performed by a binary the organisation already trusts. The discriminating telemetry is therefore the combination of a signed binary making a network request and a file appearing in a user-writable directory.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the content must arrive over HTTP or HTTPS **THEN** `certutil`, `bitsadmin`, `curl` and PowerShell's web cmdlets are the candidates; the policy question is whether each is permitted
3. **IF** the content must arrive over WebDAV **THEN** `@SSL` paths are the 2025 pattern; the network indicator is a WebDAV request from a signed binary
4. **IF** the content must be decoded before use **THEN** `certutil -decode` and `expand` are the staging pair; the decode step is a separate event
5. **IF** the content must be executed, not just stored **THEN** hand off to [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `lolbins-and-signed-binary-abuse-download-and-staging` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Execution rather than ingress | [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) | Which binary runs which file type |
| The staging is by a user instruction | [`initial-access-via-phishing`](../initial-access-via-phishing/SKILL.md) | Fake-captcha delivery |
| The staged file is a driver | [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](../lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) | Kernel-mode loading |
| The staged file must be exfiltrated | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Egress channels |
| Need the class-level branch table first | [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish which download-capable signed binaries the policy permits.** `certutil`, `bitsadmin`, `curl.exe`, `expand`, and the PowerShell web cmdlets. Each has a distinct detection signature, and the policy state decides which are available.
2. **Read the destination path's permissions.** A user-writable directory proves staging is possible without elevation. The path also determines what can execute it afterwards, so record both.
3. **Baseline legitimate use of each binary.** Some environments use `certutil` for certificate operations and `bitsadmin` for patching. The differential is a network argument (a URL) or a decode argument on a file that arrived moments earlier.
4. **Name the stop condition and the cleanup rule.** Stop once the network request and the resulting file are both observed. Remove the staged file, because leaving content behind changes the host's state.
5. **State the proof.** Proof is the command line with the URL, the DNS or proxy record for the destination, and the file's creation event with its path. One of the three alone is insufficient.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `certutil -urlcache -split -f <url> <path>` | Proves download through a certificate utility, the most common signed-binary stager; Windows. |
| `bitsadmin /transfer <job> <url> <path>` | Proves transfer through the background transfer service, which survives session end; Windows. |
| `expand <cab> -F:* <dir>` | Proves local decomposition of an archive, the second half of a two-stage delivery; Windows. |
| File creation in `%TEMP%` or `%APPDATA%` by a signed binary | Proves staging in a user-writable path, the artefact that persists after the download; Windows. |
| Sysmon event 22 from `certutil.exe` | Proves a DNS lookup by a binary that normally performs none, the network half of the differential; Windows with Sysmon. |

## Worked Contrast

**Weak configuration — download-capable signed binaries unrestricted and egress allowed to any destination:**

```powershell
# no application control rule constrains certutil or bitsadmin, and the
# egress rule permits HTTPS to any address
New-NetFirewallRule -DisplayName 'Allow-HTTPS-Any' -Direction Outbound -Protocol TCP `
    -RemotePort 443 -Action Allow
# a signed binary can fetch and decode arbitrary content
```

**Hardened configuration — binary-level constraints and egress to named destinations only:**

```powershell
# application control: allow certutil only for the certificate provider path
# egress: replace the any-destination rule with an explicit allowlist
Remove-NetFirewallRule -DisplayName 'Allow-HTTPS-Any'
New-NetFirewallRule -DisplayName 'HTTPS-Allowlist' -Direction Outbound -Protocol TCP `
    -RemotePort 443 -RemoteAddress 203.0.113.10,203.0.113.11 -Action Allow
# verification: the same download fails at the firewall and the binary is blocked by policy
```

**Why this matters:** staging needs both a permitted binary and a permitted destination, so the controls are the application control rule and the egress allowlist, verified by a failed request.

## When It Is NOT This Issue

- **`certutil` used for certificate operations.** Certificate inspection and export are its primary purpose; only URL and decode arguments indicate staging.
- **`bitsadmin` used by a patching product.** Background transfer is legitimate for updates; check the destination against the patch infrastructure inventory.
- **A file in `%TEMP%` created by an installer.** Temp files are normal; the finding requires the creating process to be a download-capable signed binary with a network argument.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `lolbins-and-signed-binary-abuse-download-and-staging` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `lolbins-and-signed-binary-abuse-download-and-staging` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: lolbins-and-signed-binary-abuse-download-and-staging
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
- [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](../lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `lolbins-and-signed-binary-abuse-download-and-staging` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1218`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/sigmahq (5), CYBER_CPT/lolbas (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
