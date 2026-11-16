# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`c2-implant-and-beaconing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Hunting for Cobalt Strike in PCAP

- **Provenance:** Source: `CYBER_CPT/netresec`
- **Context / Surface:** PCAP / Network Forensics (en)
- **Root Cause / Analysis:** Hunting for Cobalt Strike in PCAP In this video I analyze a pcap file with network traffic from Cobalt Strike Beacon using CapLoader. [] (https://media.netresec.com/videos/Hunting-for-Cobalt-Strike-in-PCAP_1280x720.mp4) The pcap file and Cobalt Strike malware config can be downloaded from Recorded...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: Backfire

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Backfire is all about exploiting red team infrastructure, first Havoc, and then HardHatC2. I’ll start with a Havoc server and leak the configuration from the website. I’ll exploit an SSRF vulnerability to get access to the admin port internally. There’s an authenticated RCE vulne
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Bypassing Windows Defender: One TCP Socket Away From Meterpreter and Beacon Sessions

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Bypassing Windows Defender: One TCP Socket Away From Meterpreter and Beacon Sessions ## Context If you've tried executing an out of the box meterpreter payload on the box with Windows Defender, you know it may get picked up right away as can be seen in the below gif: This quick
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: powershell 的编写源码alias powershell { local('$args $cradle $runme $cmd'); # $0 is the entire command w

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** Sleep 环境的搭建 > C2：Cobalt Strike，一款多人运动工具，常常使用再后渗透阶段 > Aggressor Script：是 C2 3.0 以上版本的一个内置的脚本语言，他是由 Sleep 脚本解析，Sleep 脚本目前国内是没有中文版本的，可能是因为使用的人不多，在在后面我会去把这个语言进行翻译；在 CS 3.0 以上的版本，菜单、选项、事件、都有默认的 default.cna 构建。我们可以使用一些 IRC、Webhook 去对接机器人和监控，比如瞎子哥的 Server 上线监听，以及梼杌等插件的编写，所以本文也会在他们的代码基础上
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Generating shell completions

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Generating shell completions Cobra can generate shell completions for multiple shells. The currently supported shells are: - Bash - Zsh - fish - PowerShell Cobra will automatically provide your program with a fully functional 'completion' command, similarly to how it provides t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: User Guide

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # User Guide While you are welcome to provide your own organization, typically a Cobra-based application will follow the following organizational structure: ' ▾ appName/ ▾ cmd/ add.go your.go commands.go here.go main.go ' In a Cobra app, typically the main.go file is very bar
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Sliver is Vulnerable to Authenticated Nil-Pointer Dereference through its Handlers

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-284`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## 1. Executive Summary A vulnerability exists in the Sliver C2 server's Protobuf unmarshalling logic due to a systemic lack of nil-pointer validation. By extracting valid implant credentials and omitting nested fields in a signed message, an authenticated actor can trigger an un
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
