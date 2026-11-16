---
name: matter-protocol-commissioning-and-fabric-security
description: "Audits Matter smart-home devices and controllers: PASE/CASE session establishment, Device Attestation Certificate (DAC/PAI/PAA) chain validation, Access Control List (ACL) cluster scoping across fabrics, and OTA image verification. Use when assessing Matter-enabled IoT ecosystems."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["matter protocol security", "pase case matter", "device attestation certificate", "matter fabric acl"]
cwe: [CWE-287, CWE-295, CWE-284]
owasp: []
attack: []
capec: []
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
corpus_sparse: true
---

# Matter Protocol Commissioning and Fabric Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Matter's security rests on two protocol phases and one credential chain. Commissioning uses PASE, a SPAKE2+ exchange over the 27-bit setup passcode plus a 12-bit discriminator, which authenticates the commissioning channel only — it proves both sides know the passcode, nothing about the device's identity. The identity comes from Device Attestation: the device presents a DAC (Device Attestation Certificate) chained through a PAI to a PAA, and the commissioner verifies that chain against the Distributed Compliance Ledger and matches the Certification Declaration's VID/PID before issuing an operational NOC. From then on, CASE (Sigma1/2/3) secures operational traffic under the NOC, and access is decided by the Access Control List cluster with privileges `View`, `Operate`, `Manage`, and `Administer` per endpoint. The defects that matter follow from that structure: a commissioner that trusts a test or allow-all attestation verifier skips the entire identity chain; a PASE window left open lets anyone with the passcode commission; granting `Administer` over a group auth mode lets any group member rewrite the ACL; and a fabric that shares a root of trust across ecosystems means one fabric's compromise is another's. Matter 1.4.2 added certificate revocation lists and vendor-ID checks, and the specification releases through 2025-2026 continued tightening the commissioning flow.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the commissioner uses a test or allow-all attestation verifier **THEN** that is the finding; the DAC chain and the CD check are both skipped.
2. **IF** the device accepts a PASE session outside the commissioning window **THEN** the branch is window duration, and the passcode entropy is the only other control.
3. **IF** an ACL entry grants `Administer` with `AuthMode::kGroup` **THEN** any group member can rewrite the ACL, which is the privilege-escalation finding.
4. **IF** the fabric shares a PAA root with another ecosystem **THEN** the branch is cross-fabric trust; the finding is the shared root's blast radius.
5. **IF** the review is the transport rather than the fabric **THEN** start at [`iot-thread-and-openthread-security`](../iot-thread-and-openthread-security/SKILL.md).
6. **IF** the device's attestation chain does not resolve to a production PAA in the DCL **THEN** the device cannot be trusted to be what it claims, and that is the finding regardless of anything else.
7. **IF** every ACL entry is CASE-authenticated with the minimum privilege, attestation is production-verified, and the commissioning window closes **THEN** record `Verified Safe` with all three.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the phase.** Commissioning (PASE), attestation (DAC chain), operational (CASE and ACL). A finding in one phase is not evidence about another.
2. **Read the attestation path.** Which verifier the commissioner uses, whether it checks the CD's VID/PID, and whether the PAA roots come from the DCL. A test verifier is the finding.
3. **Read the ACL.** Every entry's privilege, auth mode, and subject. `Administer` with group auth is the escalation; `Operate` on a lock with CASE is the intended shape.
4. **Define the baseline-vs-probe differential.** Baseline: a commission with the production verifier and a valid device, which succeeds. Probe: a commission with a device presenting a test DAC, or an ACL write from a group member. Acceptance on the probe is the finding.
5. **Name the stop condition.** Stop at the first phase whose check is absent: a test verifier accepted, a group-auth `Administer`, or a commissioning window that never closes.
6. **State the proof.** Report the verifier, the certificate chain's root, the ACL entry, and the observed acceptance. If every phase checks, record the negative with the chain's PAA and the ACL entries.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `testAllowAllAttestationVerifier` in the commissioner | The DAC chain and CD check are bypassed, so any device is accepted as any vendor | Commissioner code |
| A DAC chaining to a test PAA rather than a DCL root | The device's identity claim is unverified, which is the finding | Device attestation |
| An ACL entry with `Privilege::kAdminister` and `AuthMode::kGroup` | Any group member can rewrite the ACL, which is control of the device | Access Control cluster |
| `Privilege::kOperate` with `AuthMode::kCase` on an actuator | The intended shape: an authenticated controller operating one cluster | Access Control cluster |
| A commissioning window with no timeout | The passcode is the only control, and it is 27 bits | Commissioning implementation |
| A PAA root shared between two ecosystems' fabrics | One fabric's root compromise reaches the other's devices | Fabric configuration |

## Worked Contrast

**Vulnerable: allow-all attestation, group-administer ACL, window never closed**

```cpp
// The commissioner accepts any device, and the ACL lets a group administer the
// device. The commissioning window is left open.
commissionerParams.deviceAttestationVerifier = testAllowAllAttestationVerifier;

// ACL entry: group auth with Administer on the whole endpoint.
entry.privilege = chip::Access::Privilege::kAdminister;
entry.authMode  = chip::Access::AuthMode::kGroup;
entry.subject   = groupId;
```

```cpp
// The window is opened and never closed:
server->OpenCommissioningWindow(CommissioningWindowManager::NoAdvertisementDuration,
                                kNoTimeout, kNoTimeout);
```

**Hardened: production DCL verification, CASE-only minimum privilege, bounded window**

```cpp
// Production verifier with DCL roots and a CD VID/PID check.
commissionerParams.deviceAttestationVerifier = prodDacVerifierWithDclRoots;
commissionerParams.cdVendorIdCheck = true;

// ACL: one CASE-authenticated controller, Operate only, on the actuator endpoint.
entry.privilege = chip::Access::Privilege::kOperate;
entry.authMode  = chip::Access::AuthMode::kCase;
entry.subject   = controllerNodeId;
entry.target    = actuatorEndpoint;

// The window closes after one commission or after the documented timeout.
server->OpenCommissioningWindow(kDocumentedAdvertisementDuration,
                                kSetupPasscodeVerifierTimeoutSeconds,
                                kDiscriminator);
```

**Why this matters:** The left combination means any device that knows a passcode is trusted as a legitimate vendor product, any member of a group can rewrite the access control list, and the window never closes so the passcode remains the only barrier. The right combination verifies the device against the production root and its certification declaration, restricts the controller to `Operate` over CASE on one endpoint, and bounds the window.

## When It Is NOT This Issue

- **A test attestation verifier in a development build or the certification test harness.** Confirm the build variant; the finding is its presence in a shipping commissioner.
- **A group-auth `Operate` entry on a lighting cluster.** Group operation is the designed model for that device class.
- **A commissioning window open during a documented installation period.** State the duration and the physical-access precondition.
- **A PAA root that appears in both an ecosystem's fabric and the DCL.** The DCL root is shared by design.
- **A device with no ACL entries beyond the commissioner's own.** The default fabric admin entry is expected.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `matter-protocol-commissioning-and-fabric-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `matter-protocol-commissioning-and-fabric-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: matter-protocol-commissioning-and-fabric-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287, CWE-295, CWE-284 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`firmware-extraction-and-emulation`](../firmware-extraction-and-emulation/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `matter-protocol-commissioning-and-fabric-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, CWE-295, CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
