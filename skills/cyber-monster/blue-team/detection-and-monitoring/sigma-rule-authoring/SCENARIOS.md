# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sigma-rule-authoring`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: "CVE-2017-2636: Exploit the race condition in the n_hdlc Linux kernel driver"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-778`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # CVE-2017-2636: Exploit the race condition in the n\_hdlc Linux kernel driver Mar 24, 2017 This article discloses the exploitation of CVE-2017-2636, which is a race condition in the n\_hdlc Linux kernel driver. My PoC exploit for x86\_64 gains root privileges bypassing Superviso
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: O que é Race Condition? E como explorar essa vulnerabilidade?

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # O que é Race Condition? E como explorar essa vulnerabilidade na web? # O que é race condition? Race condition é uma vulnerabilidade que ocorre quando diferentes requisições são processadas compartilhando um ou mais recursos em comum no servidor, o que pode levar a colisões e, c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: "DiceCTF 2021 HashBrown Writeup: From Kernel Module Hashmap Resize Race Condition to FG-KASLR Bypass

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-778`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # DiceCTF 2021 HashBrown Writeup: From Kernel Module Hashmap Resize Race Condition to FG-KASLR Bypass This was the first time DiceCTF has been hosted (by DiceGang), and overall, I think it was a quite a successful experience and the CTF had a high level of difficulty. I wrote a s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: NSEC24 — Write-up : Linguistic Memory System (race condition)

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # NSEC24 — Write-up : Linguistic Memory System (race condition) # Challenge The challenge consists of a web application capable of learning new words in different languages. This is possible by uploading either a JSON file or a ZIP archive. The language of the website is based on
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: 多步骤竞态条件利用

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-778`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # 多步骤竞态条件利用 > 复杂业务逻辑中的竞态漏洞，涉及 TOCTOU、数据库事务、分布式系统等深层场景 ## 一、TOCTOU (Time-of-Check-Time-of-Use) 利用 ### 1.1 文件系统 TOCTOU（Symlink Race） ' 攻击原理: ├─ 程序检查文件权限/内容（Time-of-Check） ├─ 在检查通过后、使用前的时间窗口内 ├─ 攻击者将文件替换为符号链接 ├─ 程序使用已被替换的文件（Time-of-Use） └─ 经典 Linux 提权场景 示例: SUID 程序写入临时文件 1. 程序检查 /
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Race Condition- TryHackMe Walkthrough

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Race Condition- TryHackMe Walkthrough # Challenge 1 In addressing the initial challenge, our first step involved navigating to the specified directory. Specifically, we executed a directory change operation to '/home/walk'. We take a look at the anti_flag_reader.c file to under
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
