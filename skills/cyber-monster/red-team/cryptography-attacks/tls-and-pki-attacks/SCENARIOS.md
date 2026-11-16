# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`tls-and-pki-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Built-in TLS module unexpectedly treats "rejectUnauthorized: undefined" as "rejectUnauthorized: false", d

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** > NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report! **Summary:**...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: CKAN has no certificate validation on STMP connection

- **Provenance:** Source: `CYBER_CPT/gh_security_lab`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Impact Configured SMTP server may be spoofed with any certificate (e.g. self-signed), leaving credentials and all emails sent open to MITM attacks. Patches The vulnerability has been patched in CKAN 2.10.10 and CKAN 2.11.5
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Pentesting Dropbox on Steroids

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-326`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Pentesting Dropbox on Steroids Many of you have probably already looked at Beau Bullock’s fine blog entry on a penetration testing dropbox. > **Jargon: Penetration testing dropbox** — A small, covert hardware device planted inside a target's physical network to give attackers r
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: BB-8

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # BB-8 (crypto, 200p) In the task we get a [source code] (server.py) of service we can connect to. We also get a lengthly [description] (README.txt) of the protocol we are working with. It is basically a standard BB-84 Quantum Key Distribution protocol. The service we can connect t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: ARP poisoning

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-326`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # ARP poisoning ## Theory The ARP (Address Resolution Protocol) is used to link IPv4 addresses with MAC addresses, allowing machines to communicate within networks. Since that protocol works in broadcast, attackers can try to impersonate machines by answering ARP requests (_"Who
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: certmitm automatic exploitation of TLS certificate validation vulnerabilities

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-326`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** certmitm automatic exploitation of TLS certificate validation vulnerabilities 2023-08-11 / Aapo Oksman aapo (oksman) Nixu Cybersecurity ● Senior Security Specialist ● Devices (IoT) ● Cryptography ● Network protocols Security Research & Bug Bounty ● aapo @ HackerOne/Bugcrowd/Intig
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Machine-in-the-Middle (MitM) BLE Attack

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-326`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Machine-in-the-Middle (MitM) BLE Attack ## Introduction Continuing with my ongoing Smart Lock attack research (see blog Reverse Engineering a Smart Lock), I decided to move my focus to a different type of attack technique, namely a **relay attack**. The **relay** attack is a fo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: 中间相遇攻击 - MITM

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-326`
- **Context / Surface:** Source: ctf_wiki (zh)
- **Root Cause / Analysis:** # 中间相遇攻击 - MITM ## 概述 中间相遇攻击是一种以空间换取时间的一种攻击方法，1977年由 Diffie 与 Hellman 提出。从个人角度看，者更多地指一种思想，不仅仅适用于密码学攻击，也适用于其他方面，可以降低算法的复杂度。 基本原理如下 假设 E 和 D 分别是加密函数和解密函数，k1 和 k2 分别是两次加密使用的密钥，则我们有 $C=E_{k_2}(E_{k_1}(P))$ $P=D_{k_1}(D_{k_2}(C))$ 则我们可以推出 $E_{k_1}(P)=D_{k_2}(C)$ 那么，当用户知道一对明文和密文时 1. 攻击
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
