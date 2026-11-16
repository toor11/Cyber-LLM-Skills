# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-artifact-forensics-execution-artifacts`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: "EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-345`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** ### EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543) Recently, I’ve discovered that Linux KPTI has implementation issues that can allow any unprivileged local attacker to bypass KASLR on Intel based systems. While technically only an info-leak, it still provide
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB Sherlock: Campfire-1

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Campfire-1 is the first in a series of Sherlocks looking at identifying critical active directory vulnerabilities. This challenge requires looking at event log and prefetch data to see an attack run PowerView and the Rubeus to perform a Kerberoasting attack. ## Background ### Sce
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: prefetch side-channel attack

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_wiki (zh)
- **Root Cause / Analysis:** # prefetch side-channel attack Prefetch 侧信道攻击（Prefetch Side-channel Attacks）是由 Daniel Gruss 于论文 *Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR* 中提出来的一种辅助攻击手法，该攻击方法利用了 Intel CPU 中 'prefetch' 系指令的硬件设计上的弱点，通过对比在不同虚拟地址上执行 'prefetch' 指令的时间差以泄露内存相关信息，并绕过 KASLR 等保护。 CPU
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB Sherlock: Tracer

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Tracer] (/icons/sherlock-tracer.png) Tracer is all about a forensics investigation where the attacker used PSExec to move onto a machine. I’ll show how PSExec creates a service on the machine, creates named pipes to communicate over, and eventually drops a .key file. I’ll identi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Prefetch Perfection 2

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-345`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Not RSA — GrabCON CTF 2021 ![\\"Himanshu] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*s_JukBFuz5Yc0D56fP4uRQ.jpeg\\") Himanshu Das · Follow Sep 5, 2021 \-- Listen Share This is the writeup of a Crypto challenge which was in the GrabCON CTF 2021. This was a crypto challeng
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: prefetch side-channel attack

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_wiki (zh)
- **Root Cause / Analysis:** # prefetch side-channel attack Prefetch 側信道攻擊（Prefetch Side-channel Attacks）是由 [Daniel Gruss] (https://gruss.cc/) 於論文 _[Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR] (https://gruss.cc/files/prefetch.pdf)_ 中提出來的一種輔助攻擊手法，該攻擊方法利用了 Intel CPU 中 'prefetch' 係指令的硬件設計上的弱點，通
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
