# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`prng-and-nonce-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Key Reinstallation Attacks: Breaking WPA2 by forcing nonce reuse

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2017-13077`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Full background information is at krackattacks.com and all detailed information can be found in our research paper. Key Reinstallation Attack: 4-way handshake example We use the 4-way handshake to illustrate the idea behind key reinstallation attacks (CVE-2017-13077).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: LEAST COMMON GENOMINATOR?

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-338`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Crypto - LEAST COMMON GENOMINATOR? Attached File : [generate.py, dump.txt, flag.txt, public.pem] 'python from secret import config from Crypto.PublicKey import RSA from Crypto.Util.number import bytes_to_long, isPrime class LCG: lcg_m = config.m lcg_c = config.c lcg_n = confi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: BBBB

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-338`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Credential Stuffing . Web Exploitation . Day 4, Advent of Cyber 3 (2021) Explore Broken Authentication, API2:2023 vulnerability using Credential Stuffing technique and gaining unauthorized access to an application. Learn about Authentication, Fuzzing, Burp Suite and how you can
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: IS_THIS_LCG?

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-338`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Pwntools: The Binary Exploitation Toolkit ![\\"Ria] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*G_3uq4Y9QFsnMZ7A_sm5LQ.jpeg\\") Ria Banerjee · Follow 9 min read · Jan 27, 2025 \-- Listen Share If you are learning binary analysis and exploitation, you are inevitably going
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: randompad

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-338`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # The Challenge The challenge consists of an RSA implementation. As with most RSA challenges we are given the public key: The exponent 'e' and the modulus 'n'. We are allowed to encrypt any data we want and the server will return with its encryption (Option 1). The server can als
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Reversing XOR Encryption Using LCG: Techniques and Tools for Decryption

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-338`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** 'python # Copie en Python du LCG def rand(state): return (1103515245*state + 12345) & 0x7fffffff # Décrypte une fois le state trouvé def decrypt(state): with open("flag_dec.pdf", "wb") as f: for i in range(0,len(encrypted),4): key = long_to_bytes(state).rjust(4, b'\x00') for j
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: tania

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-338`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # CyberTalents WPA Crack box Walkthrough ![\\"Joê- seph\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*WdFqwS1ypV61-oaHqmQseg.jpeg\\") Joê-seph · Follow 3 min read · Sep 30, 2024 \-- Listen Share WPA Crack box challenge (Youtube Thumbnail of my walkthough) In this Medium a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
