---
name: mqtt-and-coap-broker-security
description: "Audits IoT messaging brokers (Mosquitto, EMQX, AWS IoT Core, CoAP): anonymous bind, wildcard topic ACL bypass (`#` and `+` subscriptions), `$SYS/#` telemetry exposure, retained-message poisoning, and mTLS client-ID binding. Use when testing MQTT or CoAP endpoints."
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["mqtt security", "mosquitto wildcard acl", "coap security", "$sys topic exposure", "iot broker audit"]
cwe: [CWE-284, CWE-306]
owasp: []
attack: []
capec: []
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
corpus_sparse: true
---

# Mqtt and Coap Broker Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

MQTT and CoAP broker review is about the authorisation model, and both protocols have a model that is easy to leave at its default. MQTT has no built-in authorisation: the broker decides, and its decision is usually a topic ACL — a publish/subscribe permission per client per topic pattern. The defects are specific: `anonymous` allowed with no authentication; a single shared username and password for every device; an ACL of `#` which grants every topic including the wildcards that reach other tenants; a retained message on a wildcard topic that hands a new subscriber the last value of every topic in the broker; and a bridge configured without a topic filter, which relays everything between two brokers. CoAP has the same shape with a different exposure: it runs over UDP, its resource model is URIs rather than topics, and the security option (DTLS or OSCORE) is frequently absent because the deployments are constrained. The `/.well-known/core` resource enumerates every resource on a CoAP server by default, which is the discovery equivalent of an open topic listing. The precondition in both is a network path to the broker, and the review question is what a single connected client can read and write.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the broker accepts an anonymous connection **THEN** that is the finding; the topic ACL is the only remaining control and it is usually permissive by default.
2. **IF** every device shares one username and password **THEN** one extracted credential writes to every device's topic, which is the fleet-credential finding.
3. **IF** the ACL grants `#` or `+/#` to a device client **THEN** that client reads and writes the whole namespace, including other tenants' topics.
4. **IF** a retained message exists on a wildcard-subscribed topic **THEN** a new client receives stale state from topics it was never meant to see.
5. **IF** the protocol is CoAP **THEN** the branch is DTLS or OSCORE presence plus the `/.well-known/core` exposure.
6. **IF** the finding is a device credential on the filesystem **THEN** start at [`firmware-extraction-and-emulation`](../firmware-extraction-and-emulation/SKILL.md) for the extraction path.
7. **IF** the broker requires per-device credentials, the ACL is scoped to the device's own topic prefix, anonymous is off, and CoAP has DTLS or OSCORE **THEN** record `Verified Safe` with all four.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Test the authentication gate.** A connection attempt with no credentials. An accepted CONNECT with `anonymous` permitted is the finding; a `CONNACK` with return code 5 is the control.
2. **Enumerate the topic or resource namespace.** With a granted session, subscribe to `#` and observe what arrives; for CoAP, request `/.well-known/core`. The namespace is the inventory.
3. **Choose the branch.** Anonymous access, fleet credential, over-broad ACL, retained-message leak, bridge without a filter, or absent transport security on CoAP.
4. **Define the baseline-vs-probe differential.** Baseline: a subscribe to the device's own topic, which returns its own data. Probe: a subscribe to `#` or to another tenant's prefix. Data from the probe is the finding, and the topic names in it are the evidence.
5. **Name the stop condition.** Stop at the first topic or resource outside the client's intended scope that returns data or accepts a write. Do not publish to a production actuator topic.
6. **State the proof.** Report the broker configuration line or the ACL entry, the probe subscription, the topics returned, and the write that was accepted. If the ACL scopes everything and anonymous is off, record the negative with the CONNACK and the ACL.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `allow_anonymous true` in `mosquitto.conf` | Any client connects without credentials, so the ACL is the only barrier | Mosquitto configuration |
| `topic readwrite #` in an ACL file for a device user | The device client reads and writes every topic, including other tenants' | Mosquitto ACL |
| A retained message on `devices/+/status` | A new subscriber receives the last status of every device, which is a fleet inventory leak | MQTT retained messages |
| `connection bridge` with `topic # both` | Every message crosses between two brokers, which merges two trust domains | Mosquitto bridge configuration |
| `/.well-known/core` returning a resource list | A CoAP server enumerating its own resources to an unauthenticated client | CoAP discovery |
| `topic readwrite devices/%u/#` with a per-device username | The ACL is scoped to the client's own prefix, which is the control | Mosquitto ACL |

## Worked Contrast

**Vulnerable: anonymous access, wildcard ACL, retained state, unfiltered bridge**

```conf
# mosquitto.conf
listener 1883
allow_anonymous true
acl_file /etc/mosquitto/acl
```

```text
# acl
user device
topic readwrite #
```

```conf
# A bridge that relays every topic in both directions.
connection cloud
address cloud.example.com:1883
topic # both
```

**Hardened: authenticated per-device clients, prefix-scoped ACL, filtered bridge, no retained wildcards**

```conf
# mosquitto.conf
listener 8883
allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl
require_certificate true
use_identity_as_username true
```

```text
# acl — each client reaches exactly its own prefix
pattern readwrite devices/%u/#
user bridge-cloud
topic read telemetry/#
topic write commands/#
```

```conf
# The bridge relays one subtree, not everything.
connection cloud
address cloud.example.com:8883
topic telemetry/# out 1
topic commands/# in 1
```

**Why this matters:** The left broker lets anyone connect, gives each device the whole namespace, retains a status per device that any subscriber can enumerate, and bridges every topic to a second broker — so one anonymous client maps the entire fleet and can write to any actuator. The right broker requires mutual TLS with the certificate's identity as the username, scopes each client to its own prefix by pattern, and bridges only two named subtrees in the directions they are needed.

## When It Is NOT This Issue

- **A broker on a management VLAN reachable only from a gateway.** The network is the control; state the path.
- **A shared credential on a broker where every client legitimately needs the same namespace.** Rare, and the finding becomes the credential's rotation.
- **A retained message on a device's own status topic that only the device and its owner subscribe to.** Retained state is the MQTT design.
- **CoAP without DTLS on a link that is already protected by a lower layer.** State the lower layer before filing.
- **`/.well-known/core` exposed on a device with no writable resources.** Discovery without authority.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `mqtt-and-coap-broker-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `mqtt-and-coap-broker-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: mqtt-and-coap-broker-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284, CWE-306 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `mqtt-and-coap-broker-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, CWE-306`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
