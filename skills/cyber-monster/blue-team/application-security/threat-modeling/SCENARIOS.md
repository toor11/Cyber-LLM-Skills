# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`threat-modeling`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Using threat modeling and prompt injection to audit Comet

- **Provenance:** Source: `CYBER_CPT/trail_of_bits`
- **Context / Surface:** Security Engineering (en)
- **Root Cause / Analysis:** Before launching their Comet browser, Perplexity hired us to test the security of their AI-powered browsing features. Using adversarial testing guided by our TRAIL threat model, we demonstrated how four prompt injection techniques could extract users’ private information from Gmail by exploiting...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Threat Modeling

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Threat Modeling {{#include ../banners/hacktricks-training.md}} Threat Modeling Welcome to HackTricks' comprehensive guide on Threat Modeling! Embark on an exploration of this critical aspect of cybersecurity, where we identify, understand, and strategize against potential vulnerabilities in a...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: DEFCON-27-Omer-Yair-Exploiting-Windows-Exploit-Mitigation-for-ROP-Exploits

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-20`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** # Exploiting Windows Exploit Mitigation for ROP Exploits ## Return Oriented Programming - Timeline **1996** - Smashing The Stack For Fun And Profit (Aleph One / Elias Levy) ## Stack Semantics (x86) 'asm FuncFirst: ... 0x7F200100 push 0x22002200 0x7F200101 push 0x00110011 0x7F20
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: ImageMagick (WriteBMPImage): 32-bit integer overflow when writing BMP scanline stride → heap buffer

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-20`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary A 32-bit integer overflow in the BMP encoder’s scanline-stride computation collapses 'bytes_per_line' (stride) to a tiny value while the per-row writer still emits '3 × width' bytes for 24-bpp images. The row base pointer advances using the (overflowed) stride, so the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: WebGoat SQL injection mitigation lesson 12

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-20`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # WebGoat SQL injection mitigation lesson 12 In the lesson for this exercise (lesson 11) WebGoat tells us that in case of ORDER BY SQL statement it is possible to check and eventually exploit the injection by substituting the ORDER BY column with a SQL statement 'sql Normal ORD
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Threat Modeling Cheat Sheet

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-20`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Threat Modeling Cheat Sheet ## Introduction Threat modeling is an important concept for modern application developers to understand. The goal of this cheatsheet is to provide a concise, but actionable, reference for both those new to threat modeling and those seeking a refreshe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Canary

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-20`
- **Context / Surface:** Source: ctf_wiki (zh)
- **Root Cause / Analysis:** # Canary ## 介绍 Canary 的意思是金丝雀，来源于英国矿井工人用来探查井下气体是否有毒的金丝雀笼子。工人们每次下井都会带上一只金丝雀。如果井下的气体有毒，金丝雀由于对毒性敏感就会停止鸣叫甚至死亡，从而使工人们得到预警。 我们知道，通常栈溢出的利用方式是通过溢出存在于栈上的局部变量，从而让多出来的数据覆盖 ebp、eip 等，从而达到劫持控制流的目的。栈溢出保护是一种缓冲区溢出攻击缓解手段，当函数存在缓冲区溢出攻击漏洞时，攻击者可以覆盖栈上的返回地址来让 shellcode 能够得到执行。当启用栈保护后，函数开始执行的时候会先往栈底插入 c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
