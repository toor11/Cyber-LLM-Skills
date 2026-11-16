# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`indicator-lifecycle-ioc-validation-scoring`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Validation machine: Hack The Box WriteUp

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-200`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Validation machine: Hack The Box WriteUp Calmly, while finishing my university studies, I’m going to start studying for the eJPT certification trying to hack as many easy machines in HackTheBox as I can. Furthermore, this series of writeups will be explanatory enough so anyone
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HackTheBox — Validation

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-200`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # HackTheBox — Validation As always, we start with nmap to discover open ports/services. # Nmap scan 'bash namp -sC -sV -oA validation 10.10.11.116 Nmap scan report for 10.10.11.116 Host is up (0.18s latency). Not shown: 992 closed ports PORT STATE SERVICE VERSION 22/tcp open s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB — Validation

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-200`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # HTB — Validation / 2/100 Howdy! Back today with write up number 2, featuring the machine Validation from HacktheBox. Lets dive in! # Ip: 10.10.11.116 ## Name: Validation ## Rating: Easy # Enumeration As always, lets kick things off by scanning all TCP ports with Nmap. Here I wi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Froxlor has Admin-to-Root Privilege Escalation via Input Validation Bypass + OS Command Injection

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-200`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary A typo in Froxlor's input validation code ('==' instead of '=') completely disables email format checking for all settings fields declared as email type. This allows an authenticated admin to store arbitrary strings — including shell metacharacters — in the 'panel.admi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Ryan’s CTF — Input Validation

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-200`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Ryan’s CTF — Input Validation Ryan CTF is nicely organized beginner CTF located at http://ctf.ryanic.com/. Challenges are pretty interesting, with only thing I disliked being that they are played through web shell. So let’s start: ## (Ab)use the ping-tool.html page on the web s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Ech0 has SSRF via DNS Resolution Bypass in Webhook URL Validation

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-200`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The 'validateWebhookURL' function in 'webhook_setting_service.go' attempts to block webhooks targeting private/internal IP addresses, but only checks literal IP strings via 'net.ParseIP()'. Hostnames that DNS-resolve to private IPs (e.g., '169.254.169.254.nip.io', '10.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
