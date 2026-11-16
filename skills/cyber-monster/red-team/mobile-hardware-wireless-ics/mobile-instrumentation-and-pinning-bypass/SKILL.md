---
name: mobile-instrumentation-and-pinning-bypass
description: "Instruments mobile apps at runtime and bypasses protections: Frida and Objection usage, SSL pinning defeat, root and jailbreak detection bypass, and anti-debug removal. Use when dynamic testing a mobile app."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["frida", "objection", "ssl pinning bypass", "root detection bypass", "jailbreak bypass"]
cwe: [CWE-295]
owasp: []
attack: []
capec: [CAPEC-578]
related: [android-app-security, ios-app-security, hardware-debug-interfaces, firmware-extraction-and-emulation]
---

# Mobile Instrumentation and Pinning Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Instrumentation review asks two separate questions and the answers are often confused. The first is whether the app's TLS trust is verifiable: certificate or public-key pinning implemented in the network security config (Android) or in a trust evaluation callback (iOS) raises the cost of interception, and pinning implemented as a runtime check in application code that compares strings is trivially removed because the check runs in the same process the attacker controls. The second is whether the app's integrity claims are meaningful: a client-side root or jailbreak check, a debugger check, or an emulator check is a signal, never a control, because it executes in an environment the attacker owns — the server is the only place a decision can be enforced, and Apple's App Attest (with server-side assertion verification) or Play Integrity is the mechanism that moves the decision there. The review output is therefore a classification: pinning that is declared and enforced by the platform, pinning that is code-level and removable, and integrity checks that gate a server action versus ones that only produce telemetry. Any finding that says "pinning can be bypassed" without saying what the bypass yields is a finding about the wrong thing.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** pinning is in `network_security_config.xml` with a `<pin-set>` **THEN** it is platform-enforced and the finding would be the pin expiry or the missing backup pin, not bypassability.
2. **IF** pinning is a string comparison in application code **THEN** the classification is removable and the finding is what the interception yields.
3. **IF** an integrity check gates a server action **THEN** the branch is attestation: the server must verify a signed assertion, not the client's boolean.
4. **IF** the check only logs or shows a warning **THEN** it is telemetry; recording it as a control is the finding.
5. **IF** the app uses App Attest or Play Integrity **THEN** check the server verifies the assertion, including the nonce and the environment.
6. **IF** the finding is a stored credential rather than transport trust **THEN** start at the platform's storage skill ([`android-app-security-storage-and-network`](../android-app-security-storage-and-network/SKILL.md) or [`ios-app-security-storage-and-url-handling`](../ios-app-security-storage-and-url-handling/SKILL.md)).
7. **IF** every pin is platform-declared with a backup pin and every integrity decision is server-verified **THEN** record `Verified Safe` with the config and the server verification site.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the pinning implementation.** The network security config, an OkHttp `CertificatePinner`, a `URLSessionDelegate` trust evaluation, or a library configuration. The mechanism decides whether it is a control.
2. **Locate the integrity implementation.** Root checks, debugger checks, emulator checks, and attestation. Classify each as client-side signal or server-verified assertion.
3. **Choose the branch.** Removable pinning, pin without rotation, integrity check gating a server action, or attestation not verified server-side.
4. **Define the baseline-vs-probe differential.** Baseline: a request from an unmodified build against the real endpoint, which succeeds. Probe: the same request through an interception proxy in a lab, which either fails (pinning holds) or succeeds (pinning is absent or removable). The differential is the request outcome, and the report states what the successful interception exposes.
5. **Name the stop condition.** Stop when the pinning mechanism is classified and the integrity decisions are located. Do not develop or distribute a bypass.
6. **State the proof.** Report the mechanism, the file and line, the probe outcome, and the consequence (which tokens or data an interception yields). For integrity, report whether the server verifies an assertion and what it checks.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `<pin-set>` in `network_security_config.xml` with two pins | Platform-enforced pinning with rotation room — a control | Android network security config |
| `CertificatePinner.Builder().add("api.example.com", "sha256/...")` | Library-level pinning enforced in the OkHttp client, which holds unless the call site is swapped | OkHttp |
| A string comparison of the certificate's subject in application code | Removable check in the attacker's own process, so it is not a control | Application code |
| `URLSessionDelegate` `didReceive challenge` returning `.cancelAuthenticationChallenge` on mismatch | Platform trust evaluation extended with a pin, which is a control | iOS URLSession |
| A root check whose result only sets a boolean used for a UI banner | Telemetry rather than a control; the finding is the classification | Application code |
| A server endpoint that rejects a request without a valid App Attest assertion | Attestation enforced where the attacker cannot reach it — the control | App Attest, Play Integrity |

## Worked Contrast

**Vulnerable: pinning as a removable string check, and an integrity boolean gating a server action**

```kotlin
// The pin is compared in application code, so it runs in the process the attacker
// controls; the integrity check gates a server call with a local boolean.
val expected = "sha256/AAAA..."
val actual = certificate.publicKey.encoded.sha256()
if (actual != expected) throw IOException("pin mismatch")   // removable

val rooted = RootBeer(context).isRooted
if (!rooted) {
    api.transfer(amount)          // the server trusts a client-side decision
}
```

**Hardened: platform-declared pinning with rotation, and a server-verified assertion**

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2027-06-01">
      <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
      <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

```kotlin
// The client sends an attestation assertion; the server verifies it and the nonce,
// so a modified client cannot reach the transfer endpoint at all.
val assertion = attestationClient.attest(nonce = serverNonce)
api.transfer(amount, attestation = assertion)   // server rejects an invalid assertion
```

**Why this matters:** The left check compares a string in the attacker's own process, so interception succeeds after one patch, and the server accepts a transfer because a client boolean said the device was not rooted. The right configuration declares the pin where the platform enforces it with a backup pin for rotation, and the server verifies a signed assertion bound to a nonce, so the decision is made where the attacker has no control.

## When It Is NOT This Issue

- **Pinning in the network security config that a determined attacker can still bypass with a repackaged app.** Platform pinning raises the cost and is the correct place; the finding would be its absence or its expiry.
- **A root check used for fraud telemetry, not to gate an action.** That is legitimate signal collection.
- **A debugger check that only delays analysis.** Deterrence is not a control and not a defect.
- **A single pin with no backup.** Operational risk against certificate rotation, not a security finding.
- **Attestation on a platform version that does not support it.** The mechanism is unavailable; record the platform qualifier.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `mobile-instrumentation-and-pinning-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `mobile-instrumentation-and-pinning-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: mobile-instrumentation-and-pinning-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-295 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`firmware-extraction-and-emulation`](../firmware-extraction-and-emulation/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `mobile-instrumentation-and-pinning-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-295`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 23 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/hacktricks (14), CYBER_CPT/github_security_md (4), OffsecCyber (1), cyber-security/CyberSec-Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
