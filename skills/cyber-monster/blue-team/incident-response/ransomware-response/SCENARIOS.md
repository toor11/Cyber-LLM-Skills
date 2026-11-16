# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ransomware-response`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: WannaCrypt “Killswitch”

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** WannaCrypt (a.k.a. WannaCry) is the name of a malware used in the May 2017 global ransomware attack targeting Microsoft Windows operating systems via known vulnerabilities leaked by The Shadow Brokers.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: TryHackMe: Dunkle Materie Room Write-Up

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe: Dunkle Materie Room Write-Up Hi, this is my write-up for the room Dunkle Materie from the TryHackMe platform. This room is a medium room that lets users investigate the ransomware attack using an application called ProcDOT. This room is created by tryhackme, heavenraiza, and RussianPanda.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: CTF Crypto - PRNG & Key Recovery

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-778`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CTF Crypto - PRNG & Key Recovery ## Mersenne Twister (MT19937) State Recovery Python's 'random' module uses Mersenne Twister. If you can observe outputs, you can recover the state and predict future values. **Key properties:** - 624 × 32-bit internal state - Each output is temp
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: TryHackMe / Recovery Write Up

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe / Recovery Write Up # Introduction To summarize the problem, there is a guy called Alex who works for a company called Recoverysoft. So one day he gets a mail from his friend Teo saying that there was a vulnerability on the webserver and to fix that Teo had sent a bin
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Recovery : THM room, Writeup

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Recovery: THM room, Writeup > Here is a hint if you want to try it on your own. Reverse engineer the > fixutil binary. It modifies a library file. Reverse engineer that library > file as well. # Introduction What it says is, Alex works at Recoverysoft. He and his colleague got
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Recovery TryHackMe Writeup

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe: Recovery Walkthrough Link: https://tryhackme.com/room/recovery We are going this time for a machine with medium difficulty, it consists of challenges regarding malware analysis. Let’s get into the machine and check out the problem with the set of credentials provided
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Recovery — TryHackMe

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Recovery — TryHackMe Recovery se trata de una máquina Ubuntu bastante original en la que por error se ha ejecutado un binario llamado fixutil que contenía un malware. El malware ha encriptado la página web y nos presenta dificultades para poder acceder por ssh. Tendremos que ir
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: ZFS rescue

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-778`
- **Context / Surface:** Source: ctftime (mixed)
- **Root Cause / Analysis:** ## ZFS rescue ### 题目描述 > We had all our flags on this super old thumb drive. My friend said the data would be safe due to ZFS, but here we are... Something got corrupted and we can only remember that the password was from the rockyou.txt file... > > Can you recover the flag.txt?
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
