---
name: network-protocol-attacks-ipv6-and-dhcp-abuse
description: IPv6 and DHCP abuse. Covers rogue DHCPv6 and router advertisements to become the default DNS path, plus DHCP starvation and rogue server abuse. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["ipv6 dns takeover", "mitm6", "rogue dhcp", "ra spoofing"]
cwe: [CWE-284]
owasp: []
attack: [T1557]
capec: [CAPEC-612]
related: [network-protocol-attacks, network-protocol-attacks-name-resolution-poisoning, network-protocol-attacks-layer-two-attacks, network-protocol-attacks-capture-and-intercept]
parent: network-protocol-attacks
---

# Network Protocol Attacks Ipv6 and Dhcp Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Windows prefers IPv6 when it is available, and it makes IPv6 available for itself via stateless autoconfiguration and DHCPv6 even on networks where nobody manages IPv6. An unauthenticated DHCPv6 Advertise or a router advertisement can therefore hand a host an attacker-chosen DNS server, and the host will prefer it over the DHCPv4-provided server. The finding is the host's own resolver configuration changing to an address the network team never issued.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the estate claims IPv6 is disabled **THEN** check endpoints for link-local addresses and DHCPv6 Solicit traffic; 'disabled by policy' rarely matches what the wire shows
3. **IF** the target already has an IPv4 DNS server **THEN** the differential is resolver preference, so check which server actually answers after the advertisement
4. **IF** the goal is DHCP starvation rather than DNS takeover **THEN** that is an availability test and needs an explicit written authorisation before any packet is sent
5. **IF** the segment uses DHCP snooping but not RA guard **THEN** RA-based assignment still works; treat v6 router advertisement and DHCPv6 as separate controls
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `network-protocol-attacks-ipv6-and-dhcp-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Frame-level interception rather than address assignment | [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) | ARP and neighbour redirection |
| Resolution poisoning on IPv4 | [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md) | LLMNR and NBT-NS answers |
| Switch-level guarding configuration | [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) | Access-port policy and trunk behaviour |
| Relay is the next step after DNS control | [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) | What an intercepted authentication enables |
| Need the class-level branch table first | [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish whether the segment has a legitimate IPv6 plan.** Look for a managed DHCPv6 server, an RA from the real router, and IPv6 DNS records. If there is no plan, every v6 answer on the segment is unauthenticated by definition, and the exposure is the absence of guarding rather than the tool.
2. **Read the endpoint's current configuration.** Link-local address, default route, DNS server list and whether DHCPv6 is in use. This is the baseline; without it an advertisement's effect cannot be attributed.
3. **Choose RA or DHCPv6 deliberately.** A router advertisement sets a default route and can set DNS via RDNSS; a DHCPv6 Advertise sets DNS without touching routing. The second is quieter and is what most real campaigns use, so prefer it for a realistic finding.
4. **Name the blast radius and stop condition.** Scope to named victim addresses, never a prefix. Stop on the first host whose resolver list changes, or immediately on duplicate address detection or an IPv6 neighbour conflict.
5. **Define proof.** Proof is the victim's resolver list containing the assessment address, the capture showing the advertisement that set it, and a name resolution that then went to that address. All three together describe DNS takeover; any one alone is a packet, not a finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| DHCPv6 Advertise from a non-server port | Proves an unauthenticated IPv6 configuration answer reached the victim; the message type 2 on UDP 547 to 546 is the artifact. |
| `Get-DnsClientServerAddress -AddressFamily IPv6` | Proves which IPv6 resolvers the host will use, the field that changes under a rogue advertisement; Windows. |
| Windows event 4100 (ISATAP router) | Proves the host accepted an IPv6 router configuration it did not have before, recorded by default; Windows. |
| `ip -6 route show default` | Proves whether a default IPv6 route exists, which an RA creates; Linux. |
| `ip -6 neigh` after a probe | Proves the victim resolved a name to the assessment address, the last link in the chain; Linux and Windows. |

## Worked Contrast

**Weak configuration — IPv6 enabled on endpoints with no RA guard or DHCPv6 guard on access ports:**

```bash
# switch access port: only IPv4 DHCP snooping is configured
ip dhcp snooping vlan 20
# no raguard, no ipv6 dhcp guard; any host may answer a DHCPv6 Solicit
```

**Hardened configuration — RA guard and DHCPv6 guard applied to every access port:**

```bash
ipv6 nd raguard policy HOST
 device-role host
interface range Gi1/0/1-48
 ipv6 nd raguard attach-policy HOST
 ipv6 dhcp guard attach-policy HOST
 ip dhcp snooping vlan 20
# server-role messages arriving on a host port are now dropped before the endpoint sees them
```

**Why this matters:** the endpoint cannot authenticate an IPv6 configuration answer, so the only durable control is filtering server-role messages at the access port; the verification is the DHCPv6 Solicit going unanswered.

## When It Is NOT This Issue

- **Real DHCPv6 server on a legitimate relay port.** A DHCPv6 Advertise is expected where IPv6 is managed; confirm the source address against the DHCP inventory and the port against the trusted-port list.
- **Teredo or ISATAP tunnels on legacy hosts.** Event 4100 can fire from a tunnel adapter without any attacker; check the interface index and the address family before attributing it.
- **Hypervisor-hosted IPv6 on a lab VLAN.** A virtual router advertisement from a hypervisor management plane is common; confirm the source MAC belongs to the hypervisor before treating it as rogue.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `network-protocol-attacks-ipv6-and-dhcp-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-protocol-attacks-ipv6-and-dhcp-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: network-protocol-attacks-ipv6-and-dhcp-abuse
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
- [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-protocol-attacks-ipv6-and-dhcp-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1557`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/oxdf (1), CYBER_CPT/blackhills (1), CYBER_CPT/hacktricks (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
