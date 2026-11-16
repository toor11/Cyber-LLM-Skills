# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`pivoting-and-tunneling`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Linux TBB SFTP URI allows local IP disclosure

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Browsing to a simple URL to an sftp URI allows bypasses socks proxy for DNS and browsing. Tested on a clean install of Ubuntu 16.04 with TBB 7.0.2 (4097d43aa0be86ae3fe43ec8f3ac5394) download from...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: PolarProxy 0.9 Released

- **Provenance:** Source: `CYBER_CPT/netresec`
- **Context / Surface:** PCAP / Network Forensics (en)
- **Root Cause / Analysis:** PolarProxy 0.9 Released PolarProxy was previously designed to only run as a transparent TLS proxy. But due to popular demand we’ve now extended PolarProxy to also include a SOCKS proxy and a HTTP CONNECT proxy.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: 新威胁：使用DNS Tunnel技术的Linux后门B1txor20正在通过Log4j漏洞传播

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** Botnet DNSMon DDoS PassiveDNS Mirai DTA Botnet 新威胁：使用DNS Tunnel技术的Linux后门B1txor20正在通过Log4j漏洞传播 Alex.Turing, Hui Wang Mar 15, 2022 • 14 min read 背景...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: TryHackMe - Sweettooth Inc. (non port forward method)

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe - Sweettooth Inc. (non port forward method) Hello everyone, this one is going to be the write-up for the Sweettooth Inc. room on TryHackMe. In this room, we’ll have to first enumerate a vulnerable database where we have to craft a JWT token to login into it and there we get the SSH credentials to the system.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: Reverse SOCKS Proxy Using Chisel — The Easy Way

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Reverse SOCKS Proxy Using Chisel — The Easy Way _Update:_ This post first described using a fork of Chisel from an unmerged pull request. This pull request is now merged into the main Chisel repo, so this is not needed anymore. You can now use the official Chisel repo.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: Tunneling Networks with Proxychains & Socks

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Tunneling Networks with Proxychains & Socks Introduction Welcome to this new article today I am going to show you how you can tunnel networks with Proxychains,Socks5 and Chisel.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: How to Tunnel and Pivot Networks using Ligolo-ng

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** How to Tunnel and Pivot Networks using Ligolo-ng On my journey to take on the OSCP I learned that pivoting/tunneling can be a confusing concept at first for beginners. After doing extensive research I came across an awesome easy to use tool called Ligolo-ng.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Pivoting for Newbies with Ligolo-ng

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Pivoting for Newbies with Ligolo-ng Lateral Movement Done Right Introduction Since January, I’ve been spending a considerable amount of my free time studying penetration testing and exploit development.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
