---
name: network-protocol-attacks
description: "Exploits network protocol weaknesses: LLMNR and NBT-NS poisoning, WPAD abuse, ARP spoofing, DHCP and IPv6 rogue services, and VLAN hopping. Use on a local network segment where layer two traffic is reachable."
family: network-ad-and-endpoint
tier: core
triggers: ["llmnr poisoning", "responder", "arp spoofing", "ipv6 dns takeover", "vlan hopping", "network mitm"]
cwe: [CWE-284]
owasp: []
attack: [T1557]
capec: [CAPEC-612]
related: [network-protocol-attacks-name-resolution-poisoning, network-protocol-attacks-ipv6-and-dhcp-abuse, network-protocol-attacks-layer-two-attacks, network-recon-and-port-scanning]
---

# Network Protocol Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Layer-two and name-resolution protocols were designed without authentication: ARP has no notion of who owns an address, NBT-NS and LLMNR answer whoever asks first, DHCP has no server authentication, and IPv6 routers advertise themselves. An attacker on the same segment can therefore answer a legitimate request more convincingly than the real service. The finding is never 'the tool ran' but 'a host accepted an unauthenticated answer it had no way to verify', proven by the victim's own state change.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the objective is capturing or altering traffic in transit **THEN** start with [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) for the ARP and gateway semantics
2. **IF** the estate has IPv6 enabled but no IPv6 DNS **THEN** use [`network-protocol-attacks-ipv6-and-dhcp-abuse`](../network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) so the rogue-DNS surface is scoped correctly
3. **IF** the segment is switched and VLAN boundaries matter **THEN** use [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) for trunk and STP conditions
4. **IF** broadcast name resolution is the vector **THEN** use [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `network-protocol-attacks` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Traffic interception on a switched segment | [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) | ARP and gateway impersonation mechanics |
| IPv6 presence without IPv6 management | [`network-protocol-attacks-ipv6-and-dhcp-abuse`](../network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) | Rogue RA and DHCPv6 DNS assignment |
| VLAN and spanning-tree conditions | [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) | Trunk negotiation and topology manipulation |
| Broadcast name resolution answers | [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md) | LLMNR, NBT-NS and mDNS poisoning |
| Captured authentication must be used | [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) | Relay targets and signing state |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm you are on the same broadcast domain.** Check the interface's subnet, the ARP table for live neighbours, and whether the switch port is an access port. A poisoned answer only reaches hosts that share the segment; claiming a VLAN-wide impact from a misconfigured port is a scope error.
2. **Choose the primitive that matches the protocol the victim actually uses.** ARP for gateway traffic, NBT-NS or LLMNR for name lookups, DHCPv6 or RA for address configuration. Pick based on observed victim behaviour, not on which tool is available.
3. **Define the baseline-versus-probe differential on the victim.** Record the victim's resolver cache, route table and ARP entry before the probe, then again after. The differential is the proof: an ARP entry that changed to the assessment host's MAC, or a DNS server that became an unexpected IPv6 address.
4. **Name the stop condition.** Stop when one victim demonstrates the state change, or immediately on any sign of production impact: duplicate-address detection, a session drop on a critical host, or an IPS block. Never run a segment-wide poison to 'be sure'.
5. **State what counts as proof.** Proof is the victim's own configuration or cache showing the attacker-supplied value, plus the request that caused it. A tool's log line saying it sent a packet is not proof that anything accepted it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `arping -I eth0 -c 3 10.20.30.1` | Proves the gateway's real MAC before and after, so an ARP entry change is attributable; Linux, local segment only. |
| LLMNR query on UDP 5355 | Proves a victim host still asks for names via LLMNR, which is the precondition for any name-resolution poisoning; any Windows host with LLMNR enabled. |
| `Get-DnsClientServerAddress` on the victim | Proves which DNS servers the victim is actually using, the field that changes when DHCPv6 or RA assignment succeeds; Windows. |
| DHCPv6 Solicit from a Windows client | Proves the client asks for IPv6 configuration even when no DHCPv6 server exists, which is the mitm6 precondition; Windows. |
| `Router Advertisement` with a lifetime | Proves the host accepts an unauthenticated RA, visible as a new default route; Linux and Windows differ in whether they accept it by default. |

## Worked Contrast

**Weak configuration — LLMNR and NBT-NS enabled with no network-level suppression:**

```powershell
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
    -Name EnableMulticast -PropertyType DWord -Value 1 -Force
# any host on the segment can answer a mistyped share name and receive NTLM
```

**Hardened configuration — multicast name resolution disabled by policy, DHCP guard and RA guard on access ports:**

```powershell
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
    -Name EnableMulticast -PropertyType DWord -Value 0 -Force
# switch side: ipv6 nd raguard policy + ip dhcp snooping vlan 20 on access ports
# the same mistyped name now fails fast with no outbound authentication
```

**Why this matters:** poisoning needs a protocol that will answer; disabling multicast resolution and guarding RA/DHCP at the access port removes the answer path rather than trying to detect the answerer.

## When It Is NOT This Issue

- **Wired-to-wireless roaming artefacts.** A MAC that appears to move between ports can be a legitimate roaming client or a virtual MAC on a hypervisor; check the vendor OUI and the switch's MAC move log.
- **Legitimate second DHCP server.** A branch router or an ISP CPE serving DHCP is normal; confirm the scope and the lease contents before calling it rogue.
- **ARP entry change after a failover.** Cluster failover and VRRP/HSRP transitions legitimately move a virtual MAC; correlate with the device's own logs.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `network-protocol-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-protocol-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: network-protocol-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1557]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-protocol-attacks-ipv6-and-dhcp-abuse`](../network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-protocol-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1557`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (20), SecEval/cs161_textbook (1), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
