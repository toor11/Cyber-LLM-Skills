# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`insecure-deserialization-dotnet-gadgets`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Perspective

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Perspective is all about exploiting a ASP.NET application in many different ways. I'll start by uploading a SHTML file that allows me to read the configuration file for the application. With that, I'll leak one of the keys used by the application, and the fact that there are more
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Pov

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Pov offers only a web port. I'll abuse a file read and directory traversal in the web page to read the ASP.NET secrets used for VIEWSTATE, and then use ysoserial.net to make a malicious serlialized .NET payload to get execution. I'll pivot on a PowerShell credential, and then abu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Scrambled [From Linux]

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ## Recon ### nmap 'nmap' finds many TCP ports: 'bash oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.168 Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-09 12:45 UTC Nmap scan report for 10.10.11.168 Host is up (0.097s latency). Not shown: 65515 filtered ports PORT STATE SERV
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Sharp

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Sharp was all about C# and .NET. It started with a PortableKanban config. At the time of release, there was no public scripts decrypting the database, so it involved reverse engineering a real .NET binary. From there, I'll reverse and exploit a .NET remoting service with a serial
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: 金蝶 K3Cloud BinaryFormatter 反序列化漏洞

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-502`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # 金蝶 K3Cloud BinaryFormatter 反序列化漏洞 ## 漏洞描述 由于金蝶云星空能够使用 format 参数指定数据格式为二进制，攻击者可以通过发送由 BinaryFormatter 恶意序列化后的数据让服务端进行危险的BinaryFormatter 反序列化操作。反序列化过程中没有对数据进行签名或校验，导致攻击者可以在未授权状态下进行服务器远程代码执行。 ## 漏洞影响 'text 金蝶云星空 < 6.2.1012.4 7.0.352.16 < 金蝶云星空 <7.7.0.202111 8.0.0.202205 < 金蝶云星空
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: 代码审计 .Net 下的序列化与反序列化 (Binaryformatter)

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-502`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** #### 前言 本文将介绍 BinaryFormatter 序列化与反序列化漏洞的原理以及实际应用场景中的代码审计。 之前本博客就有发表过多篇 NET 反序列化漏洞的文章: 'JavaScriptSerializer'：https://www.websecuritys.cn/archives/136.html 'Json.Net': https://www.websecuritys.cn/archives/netxlh-1.html JavaScriptSerializer 和 Json.Net 要想在反序列化过程中执行命令，都需要一些特定条件。 如:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
