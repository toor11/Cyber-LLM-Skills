# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HackTheBox ‘Flippin Bank’ Walkthrough / Introduction to CBC Bit-flipping Attack

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=5)
- **Root Cause / Analysis:** HackTheBox ‘Flippin Bank’ Walkthrough / Introduction to CBC Bit-flipping Attack ‘Flippin Bank’ is a crypto challenge on HackTheBox, and I loved it because it showcased a classic CBC bit flipping attack.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: CBC Bit Flipping Attack

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-327`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **CBC Bit Flipping Attack** exploits the chaining property of CBC mode encryption. By flipping bits in one ciphertext block, an attacker can make predictable changes to the next decrypted plaintext block, potentially modifying data like user roles or amounts. ### How CBC Works '
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
