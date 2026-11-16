# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`browser-and-application-forensics`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Browser Artifacts

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Browser Artifacts {{#include ../../../banners/hacktricks-training.md}} Browsers Artifacts Browser artifacts include various types of data stored by web browsers, such as navigation history, bookmarks, and cache data.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Cross-Cache Overflow & Page-level Heap Fengshui

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # Cross-Cache Overflow & Page-level Heap Fengshui > 注：这是两种联合起来的利用手法。 ## Cross-Cache Overflow 与我们此前一直关注于 slub allocator 的各种利用手法不同，**Cross-Cache Overflow** 实际上是**针对 buddy system** 的利用手法，其主要基于如下思路： - slub allocator 底层逻辑是向 buddy system 请求页面后再划分成特定大小 object 返还给上层调用者。 - 内存中用作不同 'kmem_c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Hack The Box —Cache Write-up

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Hack The Box —Cache Write-up # Summary Cache is a Linux box of medium difficulty from Hack The Box platform that was retired at 10 October 2020 at 19:00:00 UTC. The process to pwn this box consists of a few stages. Foothold is obtained from a combination of authentication bypas
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: LibraryVault (web)

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-345`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # 1. Introduction **Challenge**: LibraryVault **Event**: BSides Algiers 2025 (7th Edition) **Organized by**: Shellmates **Category**: Web Exploitation **Difficulty**: Hard At first glance, LibraryVault looked like a simple book library. But behind the login lurked an admin panel
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: "Reviving Exploits Against Cred Structs - Six Byte Cross Cache Overflow to Leakless Data-Oriented Ke

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-345`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** ### [Reviving Exploits Against Cred Structs - Six Byte Cross Cache Overflow to Leakless Data-Oriented Kernel Pwnage] (https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html) Last year in corCTF 2021, [D3v17] (https://syst3mfailure.io/) and I wrote two kernel ch
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Thailand-CTF 2018 — memory cache (pwn) Writeup

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Thailand-CTF 2018 — memory cache (pwn) Writeup เพื่อนๆ และพี่ Pichaya Morimoto ชวนมาแข่งตอนแรกก็ลังเลอยู่ เพราะว่าโจทย์ส่วนใหญ่จะไม่ได้เป็นแนว offensive แบบที่ผมชอบ แต่ปีนี้ต่างจากปีก่อนๆ มาก มีโจทย์แนว offensive นิดหนึ่ง แต่เป็นโจทย์ที่ผมชอบมาก เพราะซ่อน bug ได้เนียนมาก ทำให้
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HackTheBox Writeup — Cache

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # HackTheBox Writeup — Cache Hack the Box is an online platform where you can practice your penetration testing skills. This is my write-up for the HackTheBox machine ‘Cache’, which runs a Linux OS and is one of the ‘medium’ rated machines. # 1. Summary The initial foothold on th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
