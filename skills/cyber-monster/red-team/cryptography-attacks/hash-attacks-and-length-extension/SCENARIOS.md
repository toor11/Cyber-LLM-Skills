# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`hash-attacks-and-length-extension`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Length extension attack leading to HTML injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** At the profile setting page where I can set my personal website I found this url: *https://www.zomato.com/redirect?u=xxx&t=yyy* Where 'xxx' is the 'url' that we can control and 'yyy' is the 'hash'.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: MediaTek XFlash Carbonara DA2 Hash Bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** MediaTek XFlash Carbonara DA2 Hash Bypass Summary "Carbonara" abuses MediaTek's XFlash download path to run a modified Download Agent stage 2 (DA2) despite DA1 integrity checks. DA1 stores the expected SHA-256 of DA2 in RAM and compares it before branching.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Doors of Durin

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-328`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # CTF Journal 7 — Hack The Box — Mon God ![\\"Lionel] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*dmbNkD5D-u45r44go_cf0g.png\\") Lionel Frankenstein · Follow 4 min read · Oct 11, 2022 \-- Listen Share 2022/10/11 Task 1 How many TCP ports are open on the machine? Let’s do a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: MediaTek XFlash Carbonara DA2 Hash Bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-328`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # MediaTek XFlash Carbonara DA2 Hash Bypass ## Summary "Carbonara" abuses MediaTek's XFlash download path to run a modified Download Agent stage 2 (DA2) despite DA1 integrity checks. DA1 stores the expected SHA-256 of DA2 in RAM and compares it before branching. On many loaders,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Magic Dude5

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-328`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # HTB Jerry Makinesi ![\\"SefaG\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*ugqrx7uUrVd29bzmBskfSg.jpeg\\") SefaG · Follow 4 min read · Apr 10, 2020 \-- Share HTB Jerry # Özet: Bugün HTB Retired makinelerinden Jerry’ nin çözümünü paylaşacağım. Görüldüğü gibi Windows mak
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Everything you need to know about hash length extension attacks

- **Provenance:** Source: `CYBER_CPT/skullsecurity` | CWE: `CWE-328`
- **Context / Surface:** Source: skullsecurity (en)
- **Root Cause / Analysis:** **You can grab the hash\_extender tool on [Github] (https://github.com/iagox86/hash_extender)!** (Administrative note: I'm no longer at Tenable! I left on good terms, and now I'm a consultant at [Leviathan Security Group] (http://leviathansecurity.com/). Feel free to contact me if
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Length Extension Attack

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-328`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **Length Extension Attack** exploits the iterative structure of Merkle-Damgård hash functions (MD5, SHA-1, SHA-256). Given H(secret // message), an attacker can compute H(secret // message // padding // extension) without knowing the secret. ### Vulnerable Construction 'javascr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Forge (Crypto/PPC)

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-328`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # [HouseplantCTF] Music Lab - 포렌식 / 스테가노그래피 / Audacity 간단한 음악파일 스테가노그래피 문제 사실 대회에서는 MISC(기타등등)으로 분류되어있긴 했는데 스테가노그래피 문제여서 포렌식 카테고리로 넣었다. 문제파일로 주어지는것은 masterpiece.mid 파일이다. 사실 이번 문제를 풀면서 .mid 라는 확장자를 처음 봤는데 mid파일은 Music Instrument Digital Interface의 약자로 전자 악기끼리의 디지털 신호 교환을 목적으로 개발된
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
