# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`symmetric-cipher-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Key Reinstallation Attacks: Breaking WPA2 by forcing nonce reuse

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2017-13077`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Full background information is at krackattacks.com and all detailed information can be found in our research paper. Key Reinstallation Attack: 4-way handshake example We use the 4-way handshake to illustrate the idea behind key reinstallation attacks (CVE-2017-13077).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Ruby OpenSSL Library - IV Reuse in GCM Mode

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, An IV reuse bug was discovered in Ruby's OpenSSL library when using aes-gcm. When encrypting data with aes-*-gcm, if the IV is set before setting the key, the cipher will default to using a static IV.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Carelessness versus craftsmanship in cryptography

- **Provenance:** Source: `CYBER_CPT/trail_of_bits`
- **Context / Surface:** Security Engineering (en)
- **Root Cause / Analysis:** Two popular AES libraries, aes-js and pyaes, “helpfully” provide a default IV in their AES-CTR API, leading to a large number of key/IV reuse bugs. These bugs potentially affect thousands of downstream projects.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: HackTheBox ‘Flippin Bank’ Walkthrough / Introduction to CBC Bit-flipping Attack

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-327`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # HackTheBox ‘Flippin Bank’ Walkthrough / Introduction to CBC Bit-flipping Attack ‘Flippin Bank’ is a crypto challenge on HackTheBox, and I loved it because it showcased a classic CBC bit flipping attack. I’ll be honest, I thought of a very different attack at first (which I will
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Fingerprint

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-327`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** For each step in Fingerprint, I’ll have to find multiple vulnerabilities and make them work together to accomplish some goal. To get a shell, I’ll abuse a execute after return (EAR) vulnerability, a directory traversal, HQL injection, cross site scripting, to collect the pieces n
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Secret Server Revenge

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-327`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** This challenge naturally follows from Secret Server, of which you can find a writeup [here] (http://toh.necst.it/hitconquals2017/crypto/Secret_Server/). We are given [another] (http://toh.necst.it/writeups_files/secretserverrevenge/secretserver.py) python script, which pretty m
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: CBC

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-327`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # CBC CBC全稱爲密碼分組鏈接（Cipher-block chaining） 模式，這裏 - IV 不要求保密 - IV 必須是不可預測的，而且要保證完整性。 ## 加密 ## 解密 ## 優缺點 ### 優點 1. 密文塊不僅和當前密文塊相關，而且和前一個密文塊或 IV 相關，隱藏了明文的統計特性。 2. 具有有限的兩步錯誤傳播特性，即密文塊中的一位變化只會影響當前密文塊和下一密文塊。 3. 具有自同步特性，即第 k 塊起密文正確，則第 k+1 塊就能正常解密。 ### 缺點 1. 加密不能並行，解密可以並行。 ## 應用 CBC 應用十分廣泛
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: TagSeries2

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-327`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Crypto: tag-series-2 **files (copy):** [chal.py] (https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/tag-series-2/files/chal.py) ## Solution ### Preview *It is recommended to read the first challenge in this series before reading this one.* This challenge is very si
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
