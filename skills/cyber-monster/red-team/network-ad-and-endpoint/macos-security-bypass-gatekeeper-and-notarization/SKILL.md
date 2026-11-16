---
name: macos-security-bypass-gatekeeper-and-notarization
description: Gatekeeper and notarization bypass. Covers bypassing Gatekeeper checks through quarantine attribute manipulation, signed binary abuse and archive behaviours. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["gatekeeper bypass", "quarantine attribute", "notarization bypass"]
cwe: [CWE-269]
owasp: []
attack: [T1548]
capec: [CAPEC-233]
related: [macos-security-bypass, macos-security-bypass-tcc-and-privacy-bypass, network-recon-and-port-scanning, service-enumeration]
parent: macos-security-bypass
---

# Macos Security Bypass Gatekeeper and Notarization - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Gatekeeper assesses a downloaded bundle on first launch: it checks the quarantine attribute, validates the signature, and consults the notarization ticket. macOS 26 changed two behaviours — a validly notarized app is no longer scanned by XProtect before launch, and TCC prompts require a Developer ID signature with the hardened runtime — so notarization status now determines both whether an app runs and whether it can request protected data. The bypass classes are therefore about the assessment path rather than about the signature itself.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`macos-security-bypass`](../macos-security-bypass/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the bundle carries a quarantine attribute **THEN** assessment will run; the finding is what happens during it
3. **IF** an application launched without assessment **THEN** the quarantine attribute was absent or removed; that is the delivery anomaly
4. **IF** the binary is ad-hoc signed **THEN** on macOS 26 it cannot trigger a TCC prompt, which changes what the binary can achieve
5. **IF** the app is notarized but malicious **THEN** revocation is the control; the finding is that notarization is a malware-scanning gate rather than a trust guarantee
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `macos-security-bypass-gatekeeper-and-notarization` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| TCC and protected data | [`macos-security-bypass-tcc-and-privacy-bypass`](../macos-security-bypass-tcc-and-privacy-bypass/SKILL.md) | Privacy controls |
| Overall layer state | [`macos-security-bypass`](../macos-security-bypass/SKILL.md) | SIP and global assessment |
| Persistence after launch | [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) | launchd mechanisms |
| Delivery to the device | [`initial-access-via-phishing`](../initial-access-via-phishing/SKILL.md) | How the bundle arrives |
| Need the class-level branch table first | [`macos-security-bypass`](../macos-security-bypass/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the bundle's signature and notarization state.** `codesign -dv --verbose=4` for the authority, the hardened runtime flag and the team id; `spctl -a -vvv` for the assessment result. Both are non-destructive and answer the question without launching anything.
2. **Check the quarantine attribute and its origin.** `xattr -p com.apple.quarantine` gives the flags and the downloading application. An absent attribute on a downloaded bundle is the anomaly, because it means the download path bypassed the assessment marker.
3. **Determine the assessment behaviour on this OS version.** macOS 26 skips the XProtect scan for a validly notarized app, so notarization now carries more weight than before. A finding must state the OS version, because the same bundle behaves differently across versions.
4. **Name the stop condition and the safety rule.** Stop at the first configuration or attribute that explains the assessment outcome. Do not launch an unknown bundle to test the assessment; the signature and attribute reads are sufficient.
5. **State the proof.** Proof is the `codesign` authority and flags, the `spctl` verdict, and the quarantine attribute value. A successful launch is supporting evidence but is not attributable without those three.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `spctl -a -vvv` returning `rejected` | Proves assessment blocked the bundle, which is the control working; `accepted` proves the trust chain validated; macOS. |
| `com.apple.quarantine` value with flag `0083` | Proves the file was downloaded by a browser and not yet assessed; an absent attribute proves assessment will not run; macOS. |
| `codesign -dv` with `flags=0x10000(runtime)` | Proves the hardened runtime is enabled, which macOS 26 requires for TCC prompts; macOS. |
| Ad-hoc signature (`Signature=adhoc`) | Proves the binary cannot obtain a TCC prompt on macOS 26, which bounds its capability; macOS 26 and later. |
| Notarization ticket validated via CloudKit at launch | Proves the notarization path was used, and its absence on a quarantined bundle is the anomaly; macOS 26. |

## Worked Contrast

**Weak configuration — quarantine attribute stripped by a proxy or an installer, so assessment never runs:**

```bash
# the download proxy rewrites the response and the bundle arrives without
# com.apple.quarantine, so Gatekeeper performs no assessment on first launch
xattr -l ~/Downloads/Suspect.app
# (no output: no quarantine attribute, no assessment)
```

**Hardened configuration — quarantine preserved end to end and assessment enforced:**

```bash
# proxy: do not strip com.apple.quarantine; where a bundle must be re-marked:
xattr -w com.apple.quarantine '0083;00000000;Safari;' ~/Downloads/Suspect.app
spctl --global-enable
# verification: xattr shows the attribute and spctl -a reports rejected or accepted
```

**Why this matters:** assessment is triggered by the quarantine marker, so the control is preserving that marker and enabling assessment, verified by the attribute read and the spctl verdict.

## When It Is NOT This Issue

- **A bundle launched from a terminal.** Command-line launches do not go through LaunchServices, so no assessment occurs and no attribute changes; that is not a bypass of the configured control.
- **`spctl` disabled for a single app through the privacy pane.** A user-granted exception is a documented override; the finding is a global disable.
- **A self-signed internal app distributed by MDM.** Managed distribution can install without quarantine; check the MDM profile before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `macos-security-bypass-gatekeeper-and-notarization` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `macos-security-bypass-gatekeeper-and-notarization` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: macos-security-bypass-gatekeeper-and-notarization
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1548]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`macos-security-bypass`](../macos-security-bypass/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`macos-security-bypass-tcc-and-privacy-bypass`](../macos-security-bypass-tcc-and-privacy-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `macos-security-bypass-gatekeeper-and-notarization` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1548`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 25 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/atomic_red_team (16), CYBER_CPT/sigmahq (3), hackerone_disclosed_reports (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
