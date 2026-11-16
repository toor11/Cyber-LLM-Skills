---
name: ics-ot-protocol-attacks-ot-network-architecture
description: OT network architecture weaknesses. Covers IT/OT segmentation gaps, jump host trust, remote access paths and the safety constraints that shape testing. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["ot segmentation", "it ot boundary", "ot remote access"]
cwe: [CWE-306]
owasp: []
attack: []
capec: [CAPEC-604]
related: [ics-ot-protocol-attacks, ics-ot-protocol-attacks-protocol-exposure-assessment, android-app-security, ios-app-security]
parent: ics-ot-protocol-attacks
---

# ICS OT Protocol Attacks OT Network Architecture - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

OT network architecture review is the discipline of zones and conduits, and it is the only control that works for protocols with no authentication. A zone is a group of assets with the same security requirements; a conduit is the controlled path between zones, with a defined protocol, source, and destination. The reference model is the Purdue hierarchy — level 0 process, level 1 controllers, level 2 supervisory, level 3 site operations, level 3.5 the DMZ, level 4 enterprise — and the purpose of the levels is to make the crossing points explicit. The defects that matter are structural: a flat network where the enterprise reaches level 1 directly; a dual-homed engineering workstation that bridges two zones without a firewall; a remote-access path that terminates inside the control zone rather than in the DMZ; a wireless bridge that carries the control protocol across a physical boundary; and a vendor support tunnel that is always on. Each is provable from the switch and firewall configuration and from the route table, without touching a controller, which is what makes architecture the right first review for an OT site.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a host at level 3 or above has a route to a level 1 subnet **THEN** the zones are not separated, which is the finding regardless of the protocols in use.
2. **IF** a host has interfaces in two zones **THEN** it is a bridge; the finding is the host, and its firewall rules are the control.
3. **IF** remote access terminates inside the control zone **THEN** the branch is the access path; the DMZ is where it should terminate.
4. **IF** a wireless bridge carries a control protocol **THEN** the branch is the physical conduit, and its authentication is the control.
5. **IF** a vendor tunnel is always on **THEN** the branch is the third-party path; the finding is its standing access.
6. **IF** the question is a protocol's own security **THEN** start at [`ics-ot-protocol-attacks`](../ics-ot-protocol-attacks/SKILL.md).
7. **IF** the question is which assets exist and where **THEN** switch to [`ics-ot-protocol-attacks-protocol-exposure-assessment`](../ics-ot-protocol-attacks-protocol-exposure-assessment/SKILL.md).
8. **IF** every control asset is reachable only from its own zone through a named conduit, no host spans two zones, and remote access terminates in the DMZ **THEN** record `Verified Safe` with the zone map.

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

1. **Draw the zone map from configuration, not from the design document.** Subnets, VLANs, firewall rules, and route tables. The design document is a claim; the rules are the fact.
2. **Find the crossing points.** Every rule that permits traffic between two zones, every host with interfaces in two, and every remote-access termination. Each is a conduit and each needs a justification.
3. **Choose the branch.** Flat network, dual-homed bridge, remote access in the wrong zone, wireless conduit, or standing third-party path.
4. **Define the baseline-vs-probe differential.** Baseline: a connection from inside the zone to a controller, which is expected. Probe: the same connection from the enterprise zone, which either routes and succeeds or is refused. Success is the finding; a refusal or a missing route is the control.
5. **Name the stop condition.** Stop at the first crossing that reaches a controller port without a named conduit. Do not attempt to change a rule.
6. **State the proof.** Report the source zone, the destination zone, the rule or the interface that permits it, and the protocol reached. If the path is refused, record the negative with the rule that refuses it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `permit ip 10.0.0.0/8 10.20.30.0/24` on a firewall between enterprise and control | A flat path from every enterprise host to the controller subnet | Firewall rule set |
| A host with a NIC in the control VLAN and a NIC in the enterprise VLAN | A bridge with no firewall in the path, which is the classic pivot | Engineering workstation |
| A VPN concentrator whose pool is inside the control subnet | Remote access terminates inside the zone it should be outside of | VPN configuration |
| A wireless bridge carrying Modbus between two buildings | A physical conduit with no protocol authentication | Wireless bridge configuration |
| A vendor tunnel that reconnects automatically with no time limit | Standing third-party access to the control zone | Remote support appliance |
| A conduit permitting one protocol from one host, logged both ways | The architectural control, and the citation for a non-finding | Firewall configuration |

## Worked Contrast

**Vulnerable: flat enterprise-to-control path and a dual-homed workstation**

```text
# Firewall between enterprise and control:
permit ip 10.0.0.0/8 10.20.30.0/24
permit ip 10.20.30.0/24 10.0.0.0/8

# And the engineering workstation has an interface in each zone:
$ ip -brief addr
eth0    UP    10.0.5.22/24      # enterprise
eth1    UP    10.20.30.15/24    # control
```

**Hardened: named conduits only, no dual-homed host, DMZ termination**

```text
# Only the specific engineering host reaches the specific controller, and the
# historian reaches the data source through a one-way path.
permit tcp host 10.20.30.15 host 10.20.30.40 eq 502 log
permit tcp host 10.20.2.10 host 10.20.30.40 eq 102 log
deny   ip any 10.20.30.0/24 log

# The engineering workstation has one interface and reaches the control zone only
# through the conduit:
$ ip -brief addr
eth0    UP    10.0.5.22/24
```

```text
# Remote access terminates in the DMZ, not in the control zone:
vpn pool 172.16.10.0/24            # DMZ transit subnet
```

**Why this matters:** The left rules give every enterprise host a path to controllers that have no authentication, and the dual-homed workstation is a bridge that bypasses the firewall entirely — so neither rule set matters if a user on that host can be phished. The right rules admit two named hosts on two named ports with logging, deny everything else, and remove the dual-homed bridge so the only path is the logged conduit.

## When It Is NOT This Issue

- **A dual-homed host whose firewall rules permit only one protocol to one destination.** It is a bridge with a control; report the rule rather than the interface count.
- **A VPN pool in the DMZ that requires MFA and is brokered by a jump host.** Correct architecture.
- **A wireless bridge carrying only encrypted, authenticated application traffic.** The transport security is the control.
- **A vendor tunnel that is enabled only during a scheduled window with a session record.** Bounded access.
- **A historian with a read-only one-way path from the control zone.** That is the designed direction.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ics-ot-protocol-attacks-ot-network-architecture` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ics-ot-protocol-attacks-ot-network-architecture` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ics-ot-protocol-attacks-ot-network-architecture
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-306 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`ics-ot-protocol-attacks`](../ics-ot-protocol-attacks/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ics-ot-protocol-attacks-protocol-exposure-assessment`](../ics-ot-protocol-attacks-protocol-exposure-assessment/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ics-ot-protocol-attacks-ot-network-architecture` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-306`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 36 |
| Distinct dataset sources | 11 |
| Top sources | OffsecCyber (10), CYBER_CPT/mitre_attack_enterprise (6), SecEval/attck (4), cyber-security/blue-team__threat-hunting-queries.json (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
