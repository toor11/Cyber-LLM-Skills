# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Reaper

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Reaper starts with a simple key validation service. I’ll find the binary on an open FTP and reverse it to find both a buffer overflow and a format string vulnerability. I’ll abuse the format string to leak a memory address to bypass ASLR. Then I’ll abuse the overflow with ROP to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Sending Commands from your Userland Program to your Kernel Driver via IOCTL

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Sending Commands from your Userland Program to your Kernel Driver via IOCTL This is a quick lab that demonstrates how to: * create a simple WDM kernel mode driver that can receive and respond to a custom defined input/output control code (IOCTL) that sent in from the userland p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Windows 2k3 SP2 TCP/IP IOCTL Privilege Escalation (MS14-070)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-284`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Microsoft Windows Server 2003 SP2 - TCP/IP IOCTL Privilege Escalation (MS14-070) EKU-ID: 42186 CVE: CVE-2014-4076;OSVDB-114532;MS14-070 Author: Tomislav Paskalev Published: 2015-08-12 'c /* ################################################################ # Exploit Title: Wind
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Intel Network Adapter Diagnostic Driver - IOCTL Handling

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-284`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Intel Network Adapter Diagnostic Driver - IOCTL Handling / / / / / --- / --- / --- / / EKU-ID: 40947 / CVE: [CVE-2015-2291;OSVDB-119634;OSVDB-119633] (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-CVE-2015-2291;OSVDB-119634;OSVDB-119633) / OSVDB-ID: / / Author: Glafkos Chara
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Norman Virus Control - 'nvcoaft51.sys' ioctl BF672028

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-284`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # SwampCTF 2019 - Write-ups ## Information ### CTF - Name : SwampCTF 2019 - Website : swampctf.com - Type : Online - Format : Jeopardy - CTF Time : link ## 50 - Leap of Faith - Stego > "You have to let it all go, Neo. Fear, doubt, and disbelief. Free your mind > (and your stego t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: PickleScan has multiple stdlib modules with direct RCE not in blocklist

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-284`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary picklescan v1.0.3 (latest) does not block at least 7 Python standard library modules that provide direct arbitrary command execution or code evaluation. A malicious pickle file importing these modules is reported as having 0 issues (CLEAN scan). This enables remote cod
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
