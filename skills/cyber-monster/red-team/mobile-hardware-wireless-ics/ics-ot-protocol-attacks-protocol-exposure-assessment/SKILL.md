---
name: ics-ot-protocol-attacks-protocol-exposure-assessment
description: ICS protocol exposure assessment. Covers safely enumerating ICS protocols, identifying unauthenticated control paths and documenting exposure without disrupting process. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["ics enumeration", "ot protocol exposure", "modbus scan"]
cwe: [CWE-306]
owasp: []
attack: []
capec: [CAPEC-604]
related: [ics-ot-protocol-attacks, ics-ot-protocol-attacks-ot-network-architecture, android-app-security, ios-app-security]
parent: ics-ot-protocol-attacks
corpus_sparse: true
---

# ICS OT Protocol Attacks Protocol Exposure Assessment - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Protocol exposure assessment is the inventory question: which OT protocols are reachable, from where, and by what. The method is passive-first, because active scanning of a control network can disrupt a controller, and every OT assessment standard says so. Passive discovery reads existing traffic on a span or tap and builds the asset and protocol inventory from it: source and destination pairs, protocol and function codes, and the device identities that the protocols leak in their responses. Active probing is then limited to the specific gaps — a subnet with no traffic, a device class with no observed responses — and uses read-only requests against a narrow set of ports. The exposure findings that matter are the ones with a path: a protocol port reachable from a zone that should not reach it; a device answering from an unexpected subnet; a broadcast or multicast protocol that leaks asset identities beyond its zone; and a wireless path that carries a control protocol. The output is a matrix of protocol by zone by source, and its value is that it is derived from observed traffic rather than from a scan.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you have a span or a tap **THEN** passive discovery is the method, and it is the only method that cannot disturb a controller.
2. **IF** a subnet produced no passive traffic **THEN** the active probe is a read-only request against a narrow port list, and it is justified by that gap.
3. **IF** the protocol is broadcast or multicast **THEN** the branch is leakage beyond the zone, which the capture shows directly.
4. **IF** a device answers from a subnet outside its documented zone **THEN** the branch is a path that the documentation does not have.
5. **IF** the question is the zone structure rather than the protocol inventory **THEN** switch to [`ics-ot-protocol-attacks-ot-network-architecture`](../ics-ot-protocol-attacks-ot-network-architecture/SKILL.md).
6. **IF** the question is a protocol's authentication model **THEN** start at [`ics-ot-protocol-attacks`](../ics-ot-protocol-attacks/SKILL.md).
7. **IF** every protocol is observed only within its zone and every device answers only its documented peers **THEN** record `Verified Safe` with the protocol-by-zone matrix.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`ics-ot-protocol-attacks`](../ics-ot-protocol-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Place the capture.** A span on the zone's uplink, a tap at the conduit, or a mirror on the core switch. Record where it sits, because the placement determines what the inventory can and cannot show.
2. **Build the inventory from traffic.** Talker-listener pairs, protocol and function codes, and device identities from protocol responses. This is the asset list, and it is more accurate than a scan because it reflects real traffic.
3. **Choose the branch.** Reachable from the wrong zone, broadcast leakage, undocumented peer, or a subnet with no visibility.
4. **Define the baseline-vs-probe differential.** Baseline: the capture from inside the zone, which shows the expected peers. Probe: a capture at the conduit, which shows what crosses. A protocol pair present at the conduit and absent from the design is the finding.
5. **Name the stop condition.** Stop when the matrix is complete for the captured window, or at the first pair that crosses a boundary without a conduit. Do not actively query a controller to fill a gap you can leave documented.
6. **State the proof.** Report the capture point, the window, the pairs observed, the protocols, and the boundary crossed. If the capture is complete and everything is intra-zone, record the negative with the matrix.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A `modbus` pair at the conduit capture with one peer outside the zone | Reachability across a boundary, derived from real traffic rather than a scan | Zeek or tshark log |
| A CIP class-1 multicast seen on a subnet with no CIP assets | Broadcast leakage of control traffic beyond its zone | Packet capture |
| A device answering from an address outside its documented subnet | A path the documentation does not have, which is either a route or a misconfiguration | Protocol responses |
| A subnet with no observed traffic | No visibility, so the inventory is incomplete there and the active probe is justified | Capture coverage |
| A protocol list per zone that matches the design | The control, and the deliverable | Capture analysis |
| A function-code histogram showing only reads on a monitored link | Expected behaviour; a write function code would be the anomaly | Protocol analysis |

## Worked Contrast

**Vulnerable: assessment by active scan of the whole control network**

```text
# An aggressive scan against controllers, which is the method to avoid:
nmap -sS -p- --min-rate 2000 10.20.30.0/24
# Result: controllers that were idle began answering ARP and TCP for the first time,
# one HMI dropped its session, and the inventory is still incomplete.
```

**Hardened: passive inventory from a span, with a narrow read-only gap fill**

```text
# Passive first: the capture at the conduit gives the asset and protocol inventory.
$ tshark -r conduit.pcapng -T fields -e ip.src -e ip.dst -e _ws.col.Protocol \
  | sort | uniq -c | sort -rn | head
  18422  10.20.30.15  10.20.30.40  Modbus/TCP
   6120  10.20.20.5   10.20.30.12  S7comm
    940  10.20.2.10   10.20.30.40  DNP3

# Then, only for the subnet with no captured traffic, a read-only gap fill:
$ nmap -Pn -sT -p 502,102 --script modbus-discover 10.20.40.0/28 --max-rate 20
```

**Why this matters:** The left method changes the state of the network it is measuring — controllers respond to traffic they never see, sessions drop — which is unacceptable in a process environment, and it still misses protocols that do not answer a probe. The right method derives the inventory from traffic that already exists, and confines active requests to a narrow port list at a low rate against the one subnet the capture could not see.

## When It Is NOT This Issue

- **A protocol observed only between assets in the same zone.** That is the expected state; the matrix is the deliverable.
- **A broadcast protocol inside its own zone.** Multicast within a zone is the design.
- **An incomplete inventory for an unmonitored segment.** Coverage is a limitation, and the report states it rather than filling it with a scan.
- **A read function code in the traffic.** Reads are the normal control-plane behaviour.
- **A device identity leaked in a protocol response inside its zone.** Expected; the finding would be the same leak across a conduit.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ics-ot-protocol-attacks-protocol-exposure-assessment` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ics-ot-protocol-attacks-protocol-exposure-assessment` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ics-ot-protocol-attacks-protocol-exposure-assessment
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-306 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`ics-ot-protocol-attacks`](../ics-ot-protocol-attacks/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ics-ot-protocol-attacks-ot-network-architecture`](../ics-ot-protocol-attacks-ot-network-architecture/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ics-ot-protocol-attacks-protocol-exposure-assessment` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-306`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
