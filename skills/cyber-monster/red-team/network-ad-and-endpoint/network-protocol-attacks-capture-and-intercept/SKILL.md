---
name: network-protocol-attacks-capture-and-intercept
description: Traffic capture and interception. Covers passive and active traffic capture, TLS stripping where applicable, and extracting credentials from cleartext protocols. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["traffic interception", "packet capture attack", "credential sniffing", "tls strip"]
cwe: [CWE-284]
owasp: []
attack: [T1557]
capec: [CAPEC-612]
related: [network-protocol-attacks, network-protocol-attacks-name-resolution-poisoning, network-protocol-attacks-ipv6-and-dhcp-abuse, network-protocol-attacks-layer-two-attacks]
parent: network-protocol-attacks
---

# Network Protocol Attacks Capture and Intercept - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Interception on a switched segment depends on convincing endpoints to send frames to you: ARP cache poisoning for IPv4 gateway traffic, NDP for IPv6, and port-mirroring or a MAC-flood for passive capture. Because the switch forwards only to the port that owns the destination MAC, a capture that sees nothing is usually a topology problem rather than a tool problem. The defensible finding is a captured exchange that the victim believed was private, evidenced by the victim's ARP or neighbour entry pointing at the assessment host.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the capture shows only broadcast traffic **THEN** confirm the port is a mirror or that ARP poisoning actually succeeded on the victim, not just on your own host
3. **IF** the target is IPv6 **THEN** neighbour discovery spoofing replaces ARP; handle it with the same differential but a different packet type
4. **IF** the question is whether the path is encrypted **THEN** capture first, then report what was readable rather than what was theoretically interceptable
5. **IF** the segment is wireless **THEN** roaming and client isolation change the answer entirely; confirm client isolation is off before claiming interception
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `network-protocol-attacks-capture-and-intercept` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Name spoofing rather than traffic interception | [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md) | Resolver answers instead of frame redirection |
| IPv6 neighbour and router behaviour | [`network-protocol-attacks-ipv6-and-dhcp-abuse`](../network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) | RA and DHCPv6 as the redirect mechanism |
| Switch and trunk conditions | [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) | VLAN and STP preconditions |
| The capture yields an authentication exchange | [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) | What can be done with the captured authentication |
| Need the class-level branch table first | [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish what the port can see before poisoning anything.** Capture for thirty seconds with no manipulation. Broadcast, multicast and your own traffic is the expected baseline on an access port; if you already see unicast between two other hosts, the port is mirrored and poisoning is unnecessary.
2. **Pick the redirect primitive for the address family.** ARP reply for IPv4, unsolicited neighbour advertisement for IPv6, and for switched traffic without poisoning, port mirror or MAC flooding with its own risk profile. Each primitive has a different blast radius and a different detection signature.
3. **Prove the redirect on the victim, not on the attacker.** The differential is the victim's own neighbour table and the attacker's packet capture showing the victim's frames arriving. Both are required; either alone is inconclusive, because a poisoned ARP cache on your host proves nothing about the victim.
4. **Bound the interception window.** Poison two hosts, not a subnet, restore the real mapping when done, and set a hard time limit. A subnet-wide ARP poison is the most common cause of assessment-induced outages and is never necessary to prove the finding.
5. **Define proof.** Proof is a captured authentication or payload exchange, plus the victim-side state showing why it was sent to the assessment host, plus confirmation that the encrypted-versus-plaintext status of the content is accurately described.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `arpspoof -i eth0 -t victim gateway` | Proves the victim's gateway traffic can be redirected; Linux, local segment. Pair with the victim's neighbour table as the victim-side evidence. |
| `tcpdump -ni eth0 host victim and not port 22` | Proves which flows actually traversed the assessment host, the only honest basis for an interception claim; any platform with libpcap. |
| `Get-NetNeighbor` before and after | Proves the victim's neighbour entry changed to the assessment host's MAC; Windows. This is the victim-side half of the differential. |
| `tc qdisc add dev eth0 root netem delay 10ms` | Proves traffic is transiting the host, since only forwarded frames are delayed; Linux. Use with care on production links. |
| TLS handshake in the capture | Proves the content was encrypted despite interception, which changes the finding from credential exposure to metadata exposure. |

## Worked Contrast

**Weak configuration — static ARP entries absent, gateway traffic accepted from any MAC with no DAI:**

```bash
# host side: nothing binds the gateway IP to a MAC
ip neigh show 10.20.30.1
# switch side: dynamic ARP inspection disabled on the access VLAN
# a single forged reply redirects the victim's gateway traffic
```

**Hardened configuration — dynamic ARP inspection plus static binding on critical hosts:**

```bash
# switch: ip arp inspection vlan 20 ; ip arp inspection validate src-mac dst-mac ip
# switch: arp access-list GATEWAY ; permit ip host 10.20.30.1 mac host 00:11:22:33:44:55
# host: netsh interface ipv4 add neighbors "Ethernet" 10.20.30.1 00-11-22-33-44-55
# the forged reply is now dropped by the switch and ignored by the host
```

**Why this matters:** interception requires the victim to accept an unauthenticated mapping, so the control is the validation of that mapping at both switch and host, and the verification is the forged reply being dropped rather than the capture failing.

## When It Is NOT This Issue

- **Switch port mirroring.** A port configured as a SPAN destination sees unicast without any poisoning; reporting that as a successful ARP attack misattributes a monitoring configuration as a vulnerability.
- **Hypervisor promiscuous mode.** On a virtual switch, every guest may see broadcast traffic by design; check the port group security policy before claiming interception.
- **Wireless client isolation disabled by design.** Guest wireless often permits peer traffic intentionally; scope the claim to the SSID and its policy.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `network-protocol-attacks-capture-and-intercept` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-protocol-attacks-capture-and-intercept` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: network-protocol-attacks-capture-and-intercept
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
- [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-protocol-attacks-capture-and-intercept` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1557`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/oxdf (19), CYBER_CPT/blackhills (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
