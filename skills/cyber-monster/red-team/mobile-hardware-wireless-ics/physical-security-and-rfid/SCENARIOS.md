# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`physical-security-and-rfid`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: [h1-2102] [Yaworski's Broskis] Low privilege user can read POS PINs via graphql and elevate his privilege

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: A low privilege user (both in the shop and in the POS) can read POS PINs via graphql and elevate his privilege with a physical access to the POS. Steps To Reproduce: 1. Log in to your shop and install the POS app https://apps.shopify.com/shopify-pos 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Pentesting Methodology

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Pentesting Methodology **0- Physical Attacks** Do you have **physical access** to the machine that you want to attack? You should read some [**tricks about physical attacks**] (../hardware-physical-access/physical-attacks.md) and others about [**escaping from GUI...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: RFID Proximity Cloning Attacks

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # RFID Proximity Cloning Attacks #### Introduction While packing up my KeyWe Smart Lock accessories, and after wrapping up my research and two previous blogs "Reverse Engineering a Smart Lock" and "Machine-in-the-Middle BLE Attack", I came across a couple of KeyWe RFID tags. Alth
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Miller-NFC-Attack-Surface

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-284`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** # Exploring the NFC Attack Surface Charlie Miller Managing Principal Accuvant Labs charlie.miller@accuvant.com July 13, 2012 ## Introduction Near Field Communication (NFC) has been used in mobile devices in some countries for a while, and is now emerging on mobile devices in use
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Breaking the NFC chips in tens of millions of smart phones, and a few PoS systems

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-284`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** **This second post is a companion to the DEF CON 29 video. Starts at 25:43 [here] (https://www.youtube.com/watch?v=z4gIxdFfJDg&t=1543s).** About a year ago I did some research into adding new capabilities to Samsung’s NFC chips in their smartphones, by bypassing their signature pr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Breaking Samsung firmware, or turning your S8/S9/S10 into a DIY “Proxmark”

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-284`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** **This post is a companion to the DEF CON 28 video available here https://www.youtube.com/watch?v=aLe-xW-Ws4c** ### Breaking the Firmware of Samsung’s NFC Chips Recently I have been looking into how to push the capabilities of my old smartphones beyond what you could traditiona
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: New Toy Alert: A Quick Review of Keysy

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # New Toy Alert: A Quick Review of Keysy Here at BHIS we are always on the lookout for new toys. Especially if we can use them during a pentest. > **Jargon: Pentest** — A simulated cyberattack on a computer system, network, or physical facility, performed to evaluate the security
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Pentesting RFID

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-284`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Pentesting RFID ## Introduction **Radio Frequency Identification (RFID)** is the most popular short-range radio solution. It's usually used to store and transmit information that identifies an entity. An RFID tag can rely on **its own power source (active)**, such as an embedde
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
