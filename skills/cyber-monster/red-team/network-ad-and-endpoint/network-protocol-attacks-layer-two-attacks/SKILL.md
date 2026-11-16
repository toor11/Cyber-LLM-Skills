---
name: network-protocol-attacks-layer-two-attacks
description: Layer two network attacks. Covers ARP spoofing, VLAN hopping, STP manipulation and switch CAM table exhaustion for interception or segmentation bypass. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["arp spoofing", "vlan hopping", "stp attack", "cam table flooding"]
cwe: [CWE-284]
owasp: []
attack: [T1557]
capec: [CAPEC-612]
related: [network-protocol-attacks, network-protocol-attacks-name-resolution-poisoning, network-protocol-attacks-ipv6-and-dhcp-abuse, network-protocol-attacks-capture-and-intercept]
parent: network-protocol-attacks
---

# Network Protocol Attacks Layer Two Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Layer-two attacks manipulate the switch's own decision logic: VLAN tags to reach a segment you were not placed on, spanning-tree messages to become the root bridge, and MAC flooding to force unknown-unicast flooding. These techniques change the topology rather than a host's cache, so the evidence lives in switch state — VLAN membership, root bridge identity, CAM table size — not in a victim's configuration. The safety rule is correspondingly stricter: a successful STP attack can black-hole a production VLAN.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the trunk port is unknown **THEN** confirm whether the port is access or trunk with `show interfaces trunk` or DTP frames before attempting any tag manipulation
3. **IF** the objective is traffic visibility **THEN** flooding and mirroring are two routes; check for an existing SPAN session before forcing CAM overflow
4. **IF** the question is whether VLAN separation actually holds **THEN** treat it as a segmentation test and pair with [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md)
5. **IF** the switch runs MST or rapid-PVST **THEN** root takeover behaviour differs and the blast radius is larger; get explicit written approval before any BPDU is sent
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `network-protocol-attacks-layer-two-attacks` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The deliverable is a boundary verdict | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Rule-level evidence rather than topology |
| Interception is the objective | [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) | Frame redirection once visibility exists |
| Native VLAN mismatch suspected | [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) | Class-level protocol reasoning |
| VoIP or OT VLAN is in scope | [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) | Availability risk changes the approval path |
| Need the class-level branch table first | [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the switch's configuration from the wire, not from assumptions.** DTP frames reveal whether a port will negotiate a trunk; CDP or LLDP reveals the neighbour and the native VLAN. Both are passive and safe. Only after those reads should any active test be considered.
2. **Choose the least disruptive branch.** Passive reads, then a single tagged frame to test native-VLAN handling, then — only with approval — a BPDU test. Each step has a different availability risk, and the report must say which step produced the finding.
3. **Baseline the switch's own counters.** Record CAM table size, STP root identity, and trunk state before and after. The differential is a change in device state, and the device is the only witness that matters here.
4. **Set a hard availability stop condition.** Abort on any topology-change notification, any root-bridge change, or CAM table exhaustion on a switch carrying production. A VLAN outage caused by an assessment is a reportable incident, not a finding.
5. **Define proof.** VLAN separation is broken when a frame tagged for one VLAN is delivered to a host on another, proven by the receiving host's capture. Root takeover is proven by the switch's own `show spanning-tree` naming the assessment host as root.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| DTP frame advertisement | Proves whether a port will negotiate a trunk, which is the precondition for most VLAN attacks; Cisco access ports with DTP enabled. |
| `show spanning-tree vlan 20` | Proves the current root bridge identity and priority, the baseline against which a takeover is measured; Cisco. |
| `show mac address-table count` | Proves CAM utilisation before and after flooding, the device-side evidence of a CAM overflow; Cisco. |
| 802.1Q tagged frame delivery test | Proves native-VLAN or double-tagging handling by whether a host on another VLAN receives the frame; any 802.1Q switch. |
| `show interfaces trunk` | Proves which VLANs are allowed on a trunk, and therefore what a hop could reach; Cisco and most enterprise switches. |

## Worked Contrast

**Weak configuration — access port left in dynamic mode with an unused native VLAN:**

```bash
interface GigabitEthernet1/0/12
 switchport mode dynamic auto
 switchport nonegotiate disabled
# DTP negotiates a trunk, and the native VLAN is VLAN 1, shared with every other port
```

**Hardened configuration — hardcoded access port, unused native VLAN, DTP disabled:**

```bash
interface GigabitEthernet1/0/12
 switchport mode access
 switchport access vlan 120
 switchport nonegotiate
 spanning-tree bpduguard enable
# no trunk negotiation, no shared native VLAN, and BPDUs from a host port shut it down
```

**Why this matters:** the attack depends on the port being willing to become a trunk and on a shared native VLAN, so hardcoding the mode and moving the native VLAN removes the precondition at the device rather than at the endpoint.

## When It Is NOT This Issue

- **Virtual switch or hypervisor trunk.** A hypervisor management interface legitimately presents tagged frames; confirm the source is the hypervisor before reporting a VLAN hop.
- **Voice VLAN on an IP phone port.** A phone port carries a voice VLAN by design; a tagged frame there is expected, not a violation.
- **STP topology change from a legitimate redesign.** Root changes during maintenance windows are normal; correlate with the change record before attributing them.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `network-protocol-attacks-layer-two-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-protocol-attacks-layer-two-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: network-protocol-attacks-layer-two-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1557]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-protocol-attacks-ipv6-and-dhcp-abuse`](../network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-protocol-attacks-layer-two-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1557`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/ctf_search (3), SecEval/cs161_textbook (1), CYBER_CPT/L5/ctf_search (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
