# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`rsa-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Breaking RSA

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Breaking RSA > A brief overview of RSA Introduction In a recent analysis, it is found that an organization named JackFruit is using a deprecated cryptography library to generate their RSA keys. This library is known to implement RSA poorly.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: Applying Fermat’s Little Theorem in RSA challenge

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Applying Fermat’s Little Theorem in RSA challenge Hi all, few days ago I got stuck in some RSA CTF challenge which we need to apply fermat’s little theorem to solve.I’m going to explain with a custom challenge from Ashutosh Ahelleya. Thanks for usefull repo. More details here: link.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: CTF Crypto - RSA Attacks (Part 2: Specialized Techniques)

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-326`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CTF Crypto - RSA Attacks (Part 2: Specialized Techniques) See also: [rsa-attacks.md] (rsa-attacks.md) for foundational RSA attacks (small e, Wiener, Fermat, Pollard, Hastad, common modulus, Manger oracle, Coppersmith). --- ## RSA p=q Validation Bypass (BearCatCTF 2026) **Pattern
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: CTF Crypto - RSA Attacks

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-326`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CTF Crypto - RSA Attacks ## Small Public Exponent (Cube Root) **Pattern:** Small 'e' (typically 3) with small message. When 'm^e < n', the ciphertext is just 'm^e' without modular reduction — take the integer eth root. 'python import gmpy2 def small_e_attack(c, e): """Recover
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: RSA

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** ## Description of the challenge Good old RSA! ## Solution When connecting to the remote server, we are given a ciphertext, and the public key '(e, N)' for it. Presumably, this ciphertext is encrypted with textbook RSA and it's probably the flag. Knowing 'e = 17' for every con
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Unbreakable (crypto 200)

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Unbreakable (crypto 200) ###ENG In the task we get a list of ciphertexts: 4afa32e89fce5fb84c1307e727f117cc999bc443cb646149aecc45df146f50803ca153e101d9b31eee0ac0c3c017b963ef3b74abc528422d08149e2c61a2c83573989368467b3c0696a63686cf4dfd0e8fb7ca943769554f6ddeed6be47a3dbc8695a26f1486
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Breaking RSA

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-326`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Breaking RSA > A brief overview of RSA ## Introduction In a recent analysis, it is found that an organization named JackFruit is using a deprecated cryptography library to generate their RSA keys. This library is known to implement RSA poorly. The two randomly selected prime nu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: RSA-buffet

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # LFI to RCE, Web Exploitation - Watcher : TryHackMe Walkthrough Linux boot2root CTF! Explore Broken Object Level Authorization (BOLA), API3:2023 practicing Local File Inclusion (LFI), Remote Code Execution (RCE), Python Library Hijacking, and Privilege Escalation. Learn how you
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
