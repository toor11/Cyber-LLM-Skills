# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`pivoting-and-tunneling-dns-and-icmp-tunnels`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: 新威胁：使用DNS Tunnel技术的Linux后门B1txor20正在通过Log4j漏洞传播

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** Botnet DNSMon DDoS PassiveDNS Mirai DTA Botnet 新威胁：使用DNS Tunnel技术的Linux后门B1txor20正在通过Log4j漏洞传播 Alex.Turing, Hui Wang Mar 15, 2022 • 14 min read 背景...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Cracks in the Bedrock: Escaping the AWS AgentCore Sandbox

- **Provenance:** Source: `CYBER_CPT/unit42` | CWE: `CWE-284`
- **Context / Surface:** Source: unit42 (en)
- **Root Cause / Analysis:** # Cracks in the Bedrock: Escaping the AWS AgentCore Sandbox ## Executive Summary When researching the boundaries of cloud services, two of the main aspects that come to mind are network and identity. In this two-part series, we present our research into the boundaries and resilie
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Let’s Go Hunting! How to Hunt Command & Control Channels Using Bro IDS and RITA

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** 1. **Analyze the Request:** * **Role:** Master cybersecurity educator. * **Target Audience:** Bright but novice security learner. * **Goal:** Deeply elucidate, making complex intuitive and implicit explicit. * **UNBREAKABLE RULES:** * (a) Technical Correctness: Preserve all detai
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: PowerShell DNS Command & Control with dnscat2-powershell

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # PowerShell DNS Command & Control with dnscat2-powershell Imagine a scenario where a Penetration Tester is trying to set up command and control on an internal network blocking all outbound traffic, except traffic towards a few specific servers the tester has no access to. In thi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Pivoting Around Obstacles Dnscat2

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** ## DNS Tunneling with Dnscat2 ## Cloning dnscat2 and Setting Up the Server 'bash git clone https://github.com/iagox86/dnscat2.git ' 'bash cd dnscat2/server/ ' 'bash sudo gem install bundler ' 'bash sudo bundle install ' ## Starting the dnscat2 server 'bash sudo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Data Exfiltration: DNS tunnelling using iodine

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-284`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** DNS, as we all know, is the way that computers look up human readable names and turn them into IP addresses – and vice versa. Along with that basic function, there are referrals to other name servers, because the whole database is essentially decentralised, with each administrato
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: 内网渗透（二十二） 内网转发及隐蔽隧道：使用 Dns 进行命令控制 (Dnscat2)

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** dnscat2 ======= dnscat2 是一款开源软件，使用 DNS 协议创建加密的 C&C 通道，通过预共享密钥进行身份验证；使用 Shell 及 DNS 查询类型 (TXT、MX、CNAME、A、AAAA)，多个同时进行的会话类似于 SSH 中的隧道。dnscat2 的客户端是有 Windows 版和 Linux 版，服务端是用 Ruby 语言编写的。严格的说，dnscat2 是一个命令与控制工具。 使用 dnscat2 隧道的模式有两种，分别是直连模式和中继模式。 * 直连模式：客户端直接向指定 IP 地址的 DNS 服务器发起 DNS 解
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
