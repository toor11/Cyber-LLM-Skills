# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`file-carving-and-recovery`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: File/Data Carving & Recovery Tools

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** File/Data Carving & Recovery Tools Carving & Recovery tools More tools in https://github.com/Claudio-C/awesome-datarecovery Autopsy The most common tool used in forensics to extract files from images is **Autopsy**. Download it, install it and make it ingest the file to find "hidden" files.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: CTF Crypto - PRNG & Key Recovery

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-345`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CTF Crypto - PRNG & Key Recovery ## Mersenne Twister (MT19937) State Recovery Python's 'random' module uses Mersenne Twister. If you can observe outputs, you can recover the state and predict future values. **Key properties:** - 624 × 32-bit internal state - Each output is temp
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: TryHackMe / Recovery Write Up

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe / Recovery Write Up # Introduction To summarize the problem, there is a guy called Alex who works for a company called Recoverysoft. So one day he gets a mail from his friend Teo saying that there was a vulnerability on the webserver and to fix that Teo had sent a bin
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Dumping Lsass without Mimikatz with MiniDumpWriteDump

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-345`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Dumping Lsass without Mimikatz with MiniDumpWriteDump This lab explores multiple ways of how we can write a simple 'lsass' process dumper using 'MiniDumpWriteDump' API. Lsass process dumps created with 'MiniDumpWriteDump' can be loaded to mimikatz offline, where credential mate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Recovery : THM room, Writeup

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Recovery: THM room, Writeup > Here is a hint if you want to try it on your own. Reverse engineer the > fixutil binary. It modifies a library file. Reverse engineer that library > file as well. # Introduction What it says is, Alex works at Recoverysoft. He and his colleague got
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Recovery TryHackMe Writeup

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe: Recovery Walkthrough Link: https://tryhackme.com/room/recovery We are going this time for a machine with medium difficulty, it consists of challenges regarding malware analysis. Let’s get into the machine and check out the problem with the set of credentials provided
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: ElGamal

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # ElGamal RSA的数字签名方案几乎与其加密方案完全一致，只是利用私钥进行了签名。但是，对于ElGamal来说，其签名方案与相应的加密方案具有很大区别。 ## 基本原理 ### 密钥生成 基本步骤如下 1. 选取一个足够大的素数p（十进制位数不低于160），以便于在$Z_p$ 上求解离散对数问题是困难的。 2. 选取$Z_p^*$ 的生成元g。 3. 随机选取整数d,$0\leq d \leq p-2$ ，并计算$g^d \equiv y \bmod p$ 。 其中私钥为{d}，公钥为{p,g,y} 。 ### 签名 A选取随机数$k \in Z
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
