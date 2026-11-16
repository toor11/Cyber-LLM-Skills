# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`block-cipher-modes-and-padding-oracles`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Phabricator is vulnerable to padding oracle attacks and chosen-ciphertext attacks.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Dear Phabricator bug bounty team, Summary --- Phabricator encrypts data with AES in CBC mode, but does not ensure integrity of the encrypted data. You must authenticate the data, by either using an HMAC or by using an authenticated block cipher mode like GCM.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: New York Flankees, TryHackMe CTF Write-up

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** New York Flankees, TryHackMe CTF write-up Showcasing how to perform a Padding Oracle attack against CBC mode encryption, a quick container escape and an early weekend. Brief recap In this room we will mainly explore how to carry out a padding oracle attack.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: Padding Oracle Attack

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-327`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # Padding Oracle Attack ## 介绍 Padding Oracle Attack 攻击一般需要满足以下几个条件 - 加密算法 - 采用 PKCS5 Padding 的加密算法。 当然，非对称加密中 OAEP 的填充方式也有可能会受到影响。 - 分组模式为 CBC 模式。 - 攻击者能力 - 攻击者可以拦截上述加密算法加密的消息。 - 攻击者可以和 padding oracle（即服务器） 进行交互：客户端向服务器端发送密文，服务器端会以某种返回信息告知客户端 padding 是否正常。 Padding Oracle Attack 攻
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Authlib Vulnerable to JWE RSA1_5 Bleichenbacher Padding Oracle

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-327`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Authlib Vulnerable to JWE RSA1_5 Bleichenbacher Padding Oracle - **OSV ID**: GHSA-7432-952r-cw78 - **CVE**: CVE-2026-28490 - **Published**: 2026-03-16T15:17:28Z - **Modified**: 2026-04-21T08:11:01.017143574Z - **Affected Packages**: authlib - **Ecosystem**: PyPI ## 1. Executive
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Microsoft ASP.NET - Padding Oracle File Download (MS10-070)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-327`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Trend Micro uCTF 2024 Writeups Greetings folks, I am kairo from the Polytechnic University of the Philippines — Santa Maria Bulacan Campus’ A1SBERG. Today’s writeup will be covering Trend Micro Careers Philippine’s University Capture the Flag challenges which includes both from
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Padding oracle attacks: in depth

- **Provenance:** Source: `CYBER_CPT/skullsecurity` | CWE: `CWE-327`
- **Context / Surface:** Source: skullsecurity (en)
- **Root Cause / Analysis:** This post is about padding oracle vulnerabilities and the tool for attacking them - “Poracle” I’m officially releasing right now. **You can grab the Poracle tool on [Github] (https://www.github.com/iagox86/Poracle)!** At my previous job — [Tenable Network Security] (http://www.tena
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Padding Oracle Attack

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-327`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **Padding Oracle Attack** exploits applications that reveal whether decrypted data has valid padding. By observing different error responses, attackers can decrypt ciphertext byte-by-byte without knowing the encryption key. ### How It Works Block ciphers in CBC mode require paddi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
