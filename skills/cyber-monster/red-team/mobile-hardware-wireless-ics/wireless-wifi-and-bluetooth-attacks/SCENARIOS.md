# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Evil Twin

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Evil Twin **ID**: T1557.004 **Type**: Technique **Tactics**: Credential Access, Collection **Platforms**: Network Devices Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on behaviors such as Network...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Evil Twin EAP-TLS

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Evil Twin EAP-TLS {{#include ../../banners/hacktricks-training.md}} EAP-TLS is the common "secure" choice for WPA2/3-Enterprise, but two practical weaknesses regularly show up during assessments: - **Unauthenticated identity leakage**: the outer EAP-Response/Identity is sent in cleartext before any...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: HTB: Wifinetic

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-327`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Wifinetic is a realitively simple box, but based on some cool tech Felemos did to virtualize a wireless network. I’ll start with anonymous access to an FTP server that contains a backup file with a WPA wireless config. That config has a pre-shared key (password) in it, that also
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: 金山Wps Office远程堆损坏漏洞导致代码执行

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-327`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** #### 总览 WPS Office是由Microsoft珠海的中国软件开发商金山软件开发的办公套件，适用于Microsoft Windows，macOS，Linux，iOS和Android。WPS Office由三个主要组件组成：WPS Writer，WPS Presentation和WPS Spreadsheet。个人基本版本可以免费使用。WPS Office软件中存在一个远程执行代码漏洞，是当Office软件在分析特制Office文件时不正确地处理内存中的对象时引起的。成功利用此漏洞的攻击者可以在当前用户的上下文中运行任意代码。故障可能会导致拒绝服
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: WPS的bug导致PowerShell调用Excel的Com对象失败 2

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-327`
- **Context / Surface:** Source: pstips (zh)
- **Root Cause / Analysis:** # WPS的bug导致PowerShell调用Excel的Com对象失败 ### 故障现象 在PowerShell中运行下列命令： 'powershell $Excel=New-Object -ComObject Excel.Application $Excel.Visible=$false ' 返回设置“Visible”时发生异常:“无法将类型为“Microsoft.Office.Interop.Excel.ApplicationClass”的 COM 对象强制转换为接口类型“Microsoft.Office.Interop.Excel.\_A
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Evil Twin

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-327`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # PicoCTF 2021 — Most Cookies ![\\"Mohammed] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*t89qLPl_sV1WjLsQatBtjg.png\\") ![\\"Private] (\\"https://miro.medium.com/v2/resize:fill:48:48/1*ASWoQzRKJSTqK3xi3MR7Tg.jpeg\\") Mohammed Al-Rasheed · Follow Published in Private User HQ
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Evil Twin

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-327`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # TryHackMe / Principles of Security Writeup ![\\"Trnty\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*Fec- k_5XH_CgkPQmHWkt-g.png\\") Trnty · Follow 1 min read · Sep 7, 2021 \-- Share Learn the principles of information security that secures data and protects systems from
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Wps

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-327`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** ### WPS (Wifi Protected Setup) ' 8 digits can be bruteforced - because 4 digits are checked separately Access Point will mostly block connection after to many requests ' ### Reaver needs the interface to be in monitor mode ' airmon-ng check kill airmon-ng start
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
