# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`hash-attacks-and-length-extension-length-extension`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Length Extension Attack

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-328`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **Length Extension Attack** exploits the iterative structure of Merkle-Damgård hash functions (MD5, SHA-1, SHA-256). Given H(secret // message), an attacker can compute H(secret // message // padding // extension) without knowing the secret. ### Vulnerable Construction 'javascr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Everything you need to know about hash length extension attacks

- **Provenance:** Source: `CYBER_CPT/skullsecurity` | CWE: `CWE-328`
- **Context / Surface:** Source: skullsecurity (en)
- **Root Cause / Analysis:** **You can grab the hash\_extender tool on [Github] (https://github.com/iagox86/hash_extender)!** (Administrative note: I'm no longer at Tenable! I left on good terms, and now I'm a consultant at [Leviathan Security Group] (http://leviathansecurity.com/). Feel free to contact me if
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Length Extension Attack

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-328`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** # Length Extension Attack *Bookmarked!* This exercise covers how to use a length extension attack to exploit a directory traversal vulnerability PRO Hard 1-2 Hrs. 775 [Green Badge] (/badges/greenbadge) Course This course covers the exploitation of a length extension attack, which
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Modern Web Application Penetration Testing , Hash Length Extension Attacks

- **Provenance:** Source: `CYBER_CPT/secwiki` | CWE: `CWE-328`
- **Context / Surface:** Source: secwiki (en)
- **Root Cause / Analysis:** # [Internet Storm Center] (/) [Sign In] (/login.html) [Sign Up] (/register.html) Handler on Duty: [Guy Bruneau] (/handler_list.html#guy-bruneau "Guy Bruneau") Threat Level: [green] (/infocon.html) * [previous] (/diary/22788) * [next] (/diary/22796) Click HERE to learn more about classes
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
