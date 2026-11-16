# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`tls-and-pki-attacks-configuration-weaknesses`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Kryptos

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-326`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Kryptos feels different from most insane boxes. It brought an element of math / crypt into most of the challenges in a way that I really enjoyed. But it still layered challenges so that each step involved multiple exploits / bypasses, like all good insane boxes do. I’ll start by
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Kerberoasting: Requesting RC4 Encrypted TGS when AES is Enabled

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-326`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Kerberoasting: Requesting RC4 Encrypted TGS when AES is Enabled It is possible to kerberoast a user account with SPN even if the account supports Kerberos AES encryption by requesting an RC4 ecnrypted (instead of AES) TGS which easier to crack. ## Execution First off, let's con
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: phpDocumentor 1.3.0 rc4 - Remote Command Execution

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-326`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** #### SwampCTF 2018 - Apprentice's Return 399 - Pwn ##### Challenge For one such as yourself, apprentice to the arts of time manipulation, you must pass this first trial with a dreadful creature. Connect: nc chal1.swampctf.com 1802 ##### Solution File: 'text return: ELF 32-bit L
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: babycrypto

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # HTB: Blurry hackthebox ctf htb-blurry nmap debian ffuf subdomains rocketchat feroxbuster clearml python cve-2024-24590 python-pickle pytorch fickle Oct 12, 2024 ## Recon ### nmap nmap finds two open TCP ports, SSH (22) and HTTP (80): ' oxdf@hacky$ nmap -p- --min-rate 10000 10
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Linux Kernel 3.14-rc1 < 3.15-rc4 (x64) - Raw Mode PTY Echo Race Condition Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-326`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** \*\*G\*\*reetings, fellow cybersecurity enthusiasts and CTF players! In this writeup, we will dive into the solution of the “mini\_RSA” challenge from the BackdoorCTF 2023. \*\*Challenge Overview:\*\* Groot has encrypted a message using RSA with a key size of 512 bits and a publi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: TLS - Renegotiation

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-326`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # SHOPPY HACKTHEBOX WRITEUP ![\\"laluwan_w\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*bDqo3XeLM_o9hC0wuVY71A.png\\") laluwan_w · Follow 5 min read · Oct 2, 2022 \-- Share # INTRODUCTION Hallo semuannya kembali lagi dengan saya. pada tulisan yang singkat ini saya akan c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
