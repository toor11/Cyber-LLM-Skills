# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`rsa-attacks-small-and-low-exponent`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Coppersmith 相关攻击

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-326`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # Coppersmith 相关攻击 ## 基本原理 Coppersmith 相关攻击与[Don Coppersmith] (https://en.wikipedia.org/wiki/Don_Coppersmith) 紧密相关，他提出了一种针对于模多项式（单变量，二元变量，甚至多元变量）找所有小整数根的多项式时间的方法。 这里我们以单变量为主进行介绍，假设 - 模数为 N ，N 具有一个因子 $b\geq N^{\beta},0< \beta \leq 1$ - 多项式 F 的次数为 $\delta$ 那么该方法可以在$O(c\delta^5log^9(
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: RSA

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** ## Description of the challenge Good old RSA! ## Solution When connecting to the remote server, we are given a ciphertext, and the public key '(e, N)' for it. Presumably, this ciphertext is encrypted with textbook RSA and it's probably the flag. Knowing 'e = 17' for every con
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Coppersmith 相關攻擊

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-326`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # Coppersmith 相關攻擊 ## 基本原理 Coppersmith 相關攻擊與[Don Coppersmith] (https://en.wikipedia.org/wiki/Don_Coppersmith) 緊密相關，他提出了一種針對於模多項式（單變量，二元變量，甚至多元變量）找所有小整數根的多項式時間的方法。 這裏我們以單變量爲主進行介紹，假設 - 模數爲 N ，N 具有一個因子 $b\geq N^{\beta},0< \beta \leq 1$ - 多項式 F 的次數爲 $\delta$ 那麼該方法可以在$O(c\delta^5log^9(
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Old School

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # A Deep Drive on Proactive Threat Hunting We all know that the proactive threat hunting is need of the hour and as we have already discussed the basic requirement that highlights all generic step required for Threat Hunting Activity in our previous article "Threat Hunting – A pr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Multicast

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Multicast (misc, 175p) In the task we get a [sage script] (generate.sage) which generated the [data] (data.txt): 'python nbits = 1024 e = 5 flag = open("flag.txt").read().strip() assert len(flag) <= 64 m = Integer(int(flag.encode('hex'),16)) out = open("data.txt","w") for i in
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: BBBB

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Credential Stuffing . Web Exploitation . Day 4, Advent of Cyber 3 (2021) Explore Broken Authentication, API2:2023 vulnerability using Credential Stuffing technique and gaining unauthorized access to an application. Learn about Authentication, Fuzzing, Burp Suite and how you can
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
