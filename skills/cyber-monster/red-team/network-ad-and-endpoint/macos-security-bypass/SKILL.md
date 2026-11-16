---
name: macos-security-bypass
description: "Escalates and bypasses security controls on macOS: TCC prompt abuse, Gatekeeper and notarization bypass, launchd persistence, keychain access, and SIP-adjacent weaknesses. Use on a macOS host."
family: network-ad-and-endpoint
tier: core
triggers: ["macos privesc", "tcc bypass", "gatekeeper bypass", "macos persistence", "keychain dump"]
cwe: [CWE-269]
owasp: []
attack: [T1548]
capec: [CAPEC-233]
related: [macos-security-bypass-tcc-and-privacy-bypass, macos-security-bypass-gatekeeper-and-notarization, network-recon-and-port-scanning, service-enumeration]
---

# Macos Security Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

macOS security is layered: code signing and notarization decide what may run, Gatekeeper and quarantine decide whether a download is assessed, TCC decides whether a process may reach protected data, and SIP protects the system volume. Each layer has a different bypass class, and each has a corresponding configuration state. Since macOS 26 the TCC layer requires a properly signed, hardened and notarized binary to even prompt, which changed the practical path from ad-hoc binaries to signed tooling.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is a downloaded application **THEN** use [`macos-security-bypass-gatekeeper-and-notarization`](../macos-security-bypass-gatekeeper-and-notarization/SKILL.md)
2. **IF** the target is protected user data **THEN** use [`macos-security-bypass-tcc-and-privacy-bypass`](../macos-security-bypass-tcc-and-privacy-bypass/SKILL.md)
3. **IF** the target is persistence **THEN** launch agents need no administrator rights; see [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md)
4. **IF** the target is the system volume itself **THEN** SIP must be disabled, which requires a recovery-mode change and is a visible, high-impact configuration state
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `macos-security-bypass` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Gatekeeper and notarization | [`macos-security-bypass-gatekeeper-and-notarization`](../macos-security-bypass-gatekeeper-and-notarization/SKILL.md) | Quarantine and assessment |
| TCC and privacy controls | [`macos-security-bypass-tcc-and-privacy-bypass`](../macos-security-bypass-tcc-and-privacy-bypass/SKILL.md) | Protected data access |
| Persistence surfaces | [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) | launchd and profiles |
| The host is a managed fleet | [`initial-access-via-phishing`](../initial-access-via-phishing/SKILL.md) | Delivery to the user |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the configuration state of each layer.** `spctl --status`, `csrutil status`, the TCC database's access rules, and the MDM enrollment state. Each layer's state is a command away, so there is no reason to infer it.
2. **Identify which layer the technique would cross.** A quarantine attribute, a signature requirement, a TCC grant, or a SIP protection. The layer determines both the technique class and the remediation, and mixing them produces findings nobody can act on.
3. **Baseline against a managed device of the same OS version.** A managed Mac with Gatekeeper enabled, SIP enabled, TCC populated by MDM and no unsigned launch agents is the reference. Deviation is the finding.
4. **Name the stop condition.** Stop at the first layer whose state permits the crossing. Disabling SIP requires a reboot into recovery and is a high-impact change, so it needs explicit authorisation and should never be part of a probe.
5. **State the proof.** Proof is the layer's configuration output plus the artefact it permits: the quarantine attribute absent, the TCC entry granting access, the unsigned launch agent present. A technique that worked without the configuration evidence is not attributable.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `spctl --status` reporting assessments disabled | Proves Gatekeeper is off, which removes the notarization requirement for every app; any macOS host. |
| `csrutil status` reporting disabled | Proves SIP is off, which permits modification of system paths; any macOS host. |
| TCC database entry granting `kTCCServiceSystemPolicyAllFiles` | Proves an application holds full disk access, the highest-value TCC grant; macOS with TCC. |
| Quarantine attribute absent on a downloaded bundle | Proves the download bypassed the assessment path, which is how a notarization bypass is delivered; macOS. |
| Launch agent with an ad-hoc signature | Proves persistence from a binary that cannot prompt for TCC on macOS 26 and later; macOS. |

## Worked Contrast

**Weak configuration — Gatekeeper assessments disabled and SIP off on a managed device:**

```bash
spctl --status
# assessments disabled
csrutil status
# System Integrity Protection status: disabled.
# any unsigned bundle runs and system paths are writable
```

**Hardened configuration — Gatekeeper and SIP enabled, MDM enforcing assessment:**

```bash
sudo spctl --global-enable
# SIP must be re-enabled from recoveryOS: csrutil enable
# and the MDM profile should enforce 'Allow applications from: App Store and identified developers'
# verification: spctl reports assessments enabled and csrutil reports enabled
```

**Why this matters:** the layers are configuration switches, so the controls are the two status values plus the MDM profile, and the verification is the status output rather than a bypass attempt.

## When It Is NOT This Issue

- **Gatekeeper prompting rather than blocking.** A prompt is the control working; only a launch without any assessment is a bypass.
- **SIP disabled on a development machine.** Developers disable SIP for debugging; check whether the device is in a managed scope before reporting.
- **A TCC grant made by the user.** User-granted permissions are the design; the finding is a grant made without a prompt, or one held by a binary the user did not intend to authorise.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `macos-security-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `macos-security-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: macos-security-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1548]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`macos-security-bypass-tcc-and-privacy-bypass`](../macos-security-bypass-tcc-and-privacy-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`macos-security-bypass-gatekeeper-and-notarization`](../macos-security-bypass-gatekeeper-and-notarization/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `macos-security-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1548`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/atomic_red_team (6), hackerone_disclosed_reports (1), CYBER_CPT/sigmahq (1), CYBER_CPT/mitre_attack_enterprise (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
