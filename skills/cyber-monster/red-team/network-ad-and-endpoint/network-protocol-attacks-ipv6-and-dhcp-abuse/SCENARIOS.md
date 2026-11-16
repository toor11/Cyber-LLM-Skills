# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`network-protocol-attacks-ipv6-and-dhcp-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: University

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** University is a monster insane level machine. I'll start with a website and exploit a CVE in the process of generating a PDF copy of my profile to get a shell on the host. I'll find the same user's creds in a PowerShell script, and use them to log into not only this host, but two
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: MITM6 Strikes Again: The Dark Side of IPv6

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # MITM6 Strikes Again: The Dark Side of IPv6 As the world becomes increasingly connected through the internet, cyber attacks have become more sophisticated and prevalent. One type of attack that you may not have heard of is the Machine-in-the-Middle IPv6 (MITM6) attack. In this a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: DHCPv6

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-284`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # DHCPv6 ### DHCPv6 vs. DHCPv4 Message Types Comparison A comparative view of DHCPv6 and DHCPv4 message types is presented in the table below: / DHCPv6 Message Type / DHCPv4 Message Type / / :--------------------------------- / :------------------ / / Solicit (1) / DHCPDISCOVER /
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Mitm6

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. It does this by replying to DHCPv6 messages, providing victims with a link-local IPv6 address and setting the attackers host as default DNS server. The following com
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: DHCPv6 spoofing

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-284`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # DHCPv6 spoofing ## Theory ### DHCPv6 spoofing and poisoning By default on Windows environments, IPv6 is enabled and has priority over IPv4. Usually, IPv6 is neither used nor configured. When a Windows machine boots or gets plugged in the network, it asks for an IPv6 configurati
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: The default configuration of Microsoft Windows 7 immediately prefers a new IPv6 and DHCPv6 service o

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-284`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # The default configuration of Microsoft Windows 7 immediately prefers a new IPv6 and DHCPv6 service over a currently used IPv4 and DHCPv4 service upon receipt of an IPv6 Router Advertisement (RA), and - **CVE**: CVE-2011-1652 - **Exploit Type**: InTheWild - **Exploit ID**: InThe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
