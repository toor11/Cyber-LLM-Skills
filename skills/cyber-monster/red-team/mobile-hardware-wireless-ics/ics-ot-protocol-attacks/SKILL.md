---
name: ics-ot-protocol-attacks
description: "Assesses industrial control protocols: Modbus, DNP3, S7 and OPC UA exposure, unauthenticated control paths and safe testing constraints. Use when OT or ICS networks are in scope."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["ics security", "modbus", "dnp3", "s7", "ot protocol", "scada testing"]
cwe: [CWE-306]
owasp: []
attack: []
capec: [CAPEC-604]
related: [ics-ot-protocol-attacks-protocol-exposure-assessment, ics-ot-protocol-attacks-ot-network-architecture, android-app-security, ios-app-security]
---

# ICS OT Protocol Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

ICS protocol review begins with the fact that the protocols were designed for availability and determinism, not for authentication. Modbus/TCP has no authentication field at all; DNP3 has optional secure authentication that is frequently not deployed; S7comm has a password on some operations; EtherNet/IP CIP has a class-1 implicit path with no per-message identity; OPC UA is the exception, with a real security model whose defects are configuration (a deprecated `Basic128Rsa15` policy, an anonymous user token, an HTTPS endpoint left enabled). The 2025 CISA advisory for Siemens OPC UA is a clean example: the .NET Standard Stack before 1.5.374.158 allowed application authentication bypass when the deprecated `Basic128Rsa15` policy was enabled, and separately when the HTTPS endpoint was reachable. So the review has two halves: protocols with no authentication, where the control is architecture, and protocols with authentication, where the control is configuration. Every finding in the first half is about reachability; every finding in the second is about a specific security-policy setting, and both are read-only to establish.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the protocol is Modbus/TCP, DNP3 without secure authentication, or CIP class 1 **THEN** authentication is absent by design, so the finding is the reachability path.
2. **IF** the protocol is OPC UA **THEN** the branch is security policy configuration: the policy set, the user token types, and which endpoints are enabled.
3. **IF** the OPC UA policy includes `Basic128Rsa15` **THEN** the deprecated policy is the finding, and the version matters against the 2025 stack advisory.
4. **IF** an OPC UA server permits an anonymous user token **THEN** that is the finding regardless of the message security policy.
5. **IF** the question is the network architecture rather than the protocol **THEN** switch to [`ics-ot-protocol-attacks-ot-network-architecture`](../ics-ot-protocol-attacks-ot-network-architecture/SKILL.md).
6. **IF** the question is which protocols are exposed where **THEN** switch to [`ics-ot-protocol-attacks-protocol-exposure-assessment`](../ics-ot-protocol-attacks-protocol-exposure-assessment/SKILL.md).
7. **IF** the controller class is a PLC or RTU and the concern is the device itself **THEN** start at [`plc-and-scada-exploitation`](../plc-and-scada-exploitation/SKILL.md).
8. **IF** every unauthenticated protocol is confined to its zone and every OPC UA endpoint uses a current policy with certificate-based user tokens **THEN** record `Verified Safe` with both facts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `ics-ot-protocol-attacks-protocol-exposure-assessment` | [`ics-ot-protocol-attacks-protocol-exposure-assessment`](../ics-ot-protocol-attacks-protocol-exposure-assessment/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `ics-ot-protocol-attacks-ot-network-architecture` | [`ics-ot-protocol-attacks-ot-network-architecture`](../ics-ot-protocol-attacks-ot-network-architecture/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Classify each protocol by its authentication model.** Absent by design, optional and unverified, password-based, or certificate-based. The class decides whether the finding is architectural or configurational.
2. **For authentication-absent protocols, map reachability.** Which sources can reach the port, through which conduit. That mapping is the finding.
3. **For authenticated protocols, read the configuration.** The policy list, the user token policy list, and the endpoint list, per server. A single deprecated policy or an anonymous token is the finding.
4. **Define the baseline-vs-probe differential.** Baseline: a request from the authorised engineering host, which succeeds. Probe: the same request from outside the zone, or with a deprecated policy negotiated. Success on the probe is the finding.
5. **Name the stop condition.** Stop at the first successful request from a source outside the conduit, or the first endpoint that accepts a deprecated policy or anonymous token. Never write to a controller.
6. **State the proof.** Report the protocol, the source, the endpoint or policy, the result, and the control that should apply. If the request is refused, record the negative with the refusal code.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A Modbus/TCP function code 3 read answered from outside the zone | No authentication exists, so reachability is the whole control | Modbus/TCP |
| `Basic128Rsa15` in an OPC UA server's policy list | A deprecated policy whose weaknesses are documented and which the 2025 stack advisory names | OPC UA .NET Standard Stack |
| An OPC UA endpoint with `SecurityMode: None` | Messages are unauthenticated and unencrypted, so the session has no integrity | OPC UA endpoint configuration |
| An OPC UA `UserTokenPolicy` of type `Anonymous` | No user identity, so authorisation has nothing to decide on | OPC UA user token policies |
| DNP3 without secure authentication enabled | The protocol's optional security is absent, so the link has no message authentication | DNP3 outstation configuration |
| A policy list containing only `Basic256Sha256` with certificate user tokens | The current configuration, and the control to cite | OPC UA |

## Worked Contrast

**Vulnerable: OPC UA with a deprecated policy, anonymous tokens, and an HTTPS endpoint**

```xml
<!-- Server configuration: the deprecated policy is offered, anonymous is allowed,
     and the HTTPS endpoint is enabled even though nothing uses it. -->
<SecurityPolicies>
  <Policy>http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15</Policy>
  <Policy>http://opcfoundation.org/UA/SecurityPolicy#None</Policy>
</SecurityPolicies>
<UserTokenPolicies>
  <Policy>
    <TokenType>Anonymous</TokenType>
  </Policy>
</UserTokenPolicies>
<Endpoints>
  <Endpoint url="opc.tcp://0.0.0.0:4840" />
  <Endpoint url="https://0.0.0.0:4843" />
</Endpoints>
```

**Hardened: current policies only, certificate user tokens, one endpoint**

```xml
<!-- One current policy, certificate-based user identity, and only the endpoint in
     use. The deprecated policy and the HTTPS endpoint are removed. -->
<SecurityPolicies>
  <Policy>http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256</Policy>
</SecurityPolicies>
<UserTokenPolicies>
  <Policy>
    <TokenType>Certificate</TokenType>
    <IssuedTokenType>Certificate</IssuedTokenType>
  </Policy>
</UserTokenPolicies>
<Endpoints>
  <Endpoint url="opc.tcp://10.20.30.40:4840" />
</Endpoints>
```

**Why this matters:** The left server accepts a deprecated policy whose key exchange is documented as weak, allows anonymous sessions so there is no user identity to authorise, and exposes an HTTPS endpoint that the 2025 stack advisory names as an authentication-bypass path. The right server offers one current policy, requires a certificate for the user identity, and binds a single endpoint to one address.

## When It Is NOT This Issue

- **Modbus/TCP inside a zone whose conduit admits one engineering host.** The protocol has no authentication by design; the conduit is the control.
- **`SecurityPolicy#None` on a loopback-only diagnostics endpoint.** No remote reachability.
- **DNP3 without secure authentication on a serial link inside a substation.** The physical and network boundary is the control; state it.
- **An anonymous OPC UA token on a server that requires an application certificate and restricts user authorisation separately.** Check the authorisation layer before filing.
- **A deprecated policy present in the server's supported list but not offered on any endpoint.** The offered set is what matters.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ics-ot-protocol-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ics-ot-protocol-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ics-ot-protocol-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-306 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`ics-ot-protocol-attacks-protocol-exposure-assessment`](../ics-ot-protocol-attacks-protocol-exposure-assessment/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`ics-ot-protocol-attacks-ot-network-architecture`](../ics-ot-protocol-attacks-ot-network-architecture/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ics-ot-protocol-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-306`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/hacktricks (5), CYBER_CPT/ctftime (2), bugbounty-hunter-v1 (1), cyber-security/CyberSec-Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
