# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`rsa-attacks-factorization`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Old School

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # A Deep Drive on Proactive Threat Hunting We all know that the proactive threat hunting is need of the hour and as we have already discussed the basic requirement that highlights all generic step required for Threat Hunting Activity in our previous article "Threat Hunting – A pr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: RSA-buffet

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # LFI to RCE, Web Exploitation - Watcher : TryHackMe Walkthrough Linux boot2root CTF! Explore Broken Object Level Authorization (BOLA), API3:2023 practicing Local File Inclusion (LFI), Remote Code Execution (RCE), Python Library Hijacking, and Privilege Escalation. Learn how you
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Fermat String

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** Skip to content # Hacking Articles Raj Chandel’s Blog Menu * Courses We Offer * CTF Challenges * Penetration Testing * Web Penetration Testing * Red Teaming * Donate us * Home » * Hacking Tools » * How to Setup VyOS (Virtual Router Pentest Lab) » Hacking Tools, Penetration Testin
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Anti-Fermat

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # TryHackMe Writeup: MD2PDF https://tryhackme.com/room/md2pdf # Solution Start the machine and wait for the ip address to become available. You can test that you can connect to the machine by doing a simple ping command ping $IP. This clearly sounds like an xss vulnerability. # R
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Easy RSA 2

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Lab: DOM XSS in innerHTML sink using source location.search you can find the lab here = link At the start of the lap, we have a simple blog page with a search bar which will inject our payload. now let’s try my name as a value which is mahmoud to see how the site react. the val
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: RSA School 7th Grade

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** This is what we're given: 'python from Crypto.Util.number import * import sympy.ntheory as nt import random p=getPrime(1024) q=nt.nextprime(p) for _ in range(random.randint(500,10000)): q=nt.nextprime(q) N=p*q msg="UDCTF{REDACTED}" pt=bytes_to_long(msg) e=65537 ct=pow(pt,e,N) p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
