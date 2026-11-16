# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`prng-and-nonce-attacks-signature-nonce-reuse`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Slack DTLS uses a private key that is in the public domain, which may lead to SRTP stream hijack

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** - Affects: Janus DTLS certificate Description The Janus server in use by Slack is configured using a certificate and private key that were previously distributed by default.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: DiffieHellman doesn't generate keys after setting a key

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** DiffieHellman doesn't generate keys after setting a key Steps To Reproduce: 1. Instantiate: 'const dh = crypto.createDiffieHellman(1024);' 2. Set private key: //set private key to 2 dh.setPrivateKey(Buffer.from("02", 'hex'));
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Six mistakes in ERC-4337 smart accounts

- **Provenance:** Source: `CYBER_CPT/trail_of_bits`
- **Context / Surface:** Security Engineering (en)
- **Root Cause / Analysis:** Account abstraction transforms fixed “private key can do anything” models into programmable systems that enable batching, recovery and spending limits, and flexible gas payment. But that programmability introduces risks: a single bug can be as catastrophic as leaking a private key.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Private Keys

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Private Keys **ID**: T1552.004 **Type**: Technique **Tactics**: Credential Access **Platforms**: Linux, macOS, Network Devices, Windows Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: HTB: Timelapse (Walkthrough)

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HTB: Timelapse (Walkthrough) TLDR > Foothold: Pulled a file from a share. This file contained the private key > and public certificate of a user, which can be used with “evil-winrm” to > login to the target. > > Privesc (to “svc-deploy”): PowerShell history file contains creds.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: Nullcon hackim 2018 CTF writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Nullcon hackim 2018 CTF writeup 1. Crypto-1 nullcoin Question: To do : 1. reconstruct the transaction block, 2. sign it with the private key of Nullcon9 3. mine it (find the nonce) to get the signature : 9999990b707d6d10d3121eadc054a21d1e9855f679fe1b096c05beb0273c591d Solution : Given block...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: T1552.004 - Unsecured Credentials: Private Keys

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-338`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1552.004 - Unsecured Credentials: Private Keys ## Description from ATT&CK Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. > **Jargon: Private Keys** — A secret piece of cryptographic data used to decrypt messag
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Private Keys in Public Places

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-338`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** Private Keys in Public Places whoami • Tom Pohl @tompohl • Pentest Team Manager, LMG Security • Won CTF competitions at: • DEFCON • BSidesLV • THOTCON • 2 x Wild West Hackin’ Fest • 3 x Circle City Con • An Evil Twin (Hi, Andy!) Special Thanks! • Nick Starke – My partner in crime
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
