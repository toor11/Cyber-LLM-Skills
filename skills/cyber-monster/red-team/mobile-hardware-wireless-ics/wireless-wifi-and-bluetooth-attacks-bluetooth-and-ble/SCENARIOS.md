# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Machine-in-the-Middle (MitM) BLE Attack

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-327`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Machine-in-the-Middle (MitM) BLE Attack ## Introduction Continuing with my ongoing Smart Lock attack research (see blog Reverse Engineering a Smart Lock), I decided to move my focus to a different type of attack technique, namely a **relay attack**. The **relay** attack is a fo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Traefik has a Potential mTLS Bypass via Fragmented TLS ClientHello Causing Pre-SNI Sniff Fallback to

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-327`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary There is a potential vulnerability in Traefik's TLS SNI pre-sniffing logic related to fragmented ClientHello packets. When a TLS ClientHello is fragmented across multiple records, Traefik's SNI extraction may fail with an EOF and return an empty SNI. The TCP router the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Pentesting BLE - Bluetooth Low Energy

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-327`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Pentesting BLE - Bluetooth Low Energy ## Introduction Available since the Bluetooth 4.0 specification, BLE uses only 40 channels, covering the range of 2400 to 2483.5 MHz. In contrast, traditional Bluetooth uses 79 channels in that same range. BLE devices communicate is by send
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Reverse Engineering BLE from Android apps with Frida

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-327`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** One of the problems with looking at BLE devices is trying to work out what should be sent to the device. There are a few of ways of doing this: 1. Use a Bluetooth sniffer, such as [Ubertooth] (http://ubertooth.sourceforge.net/) to attempt to catch the transmissions. This is quite
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: DEFCON-26-Vincent-Tan-Hacking-BLE-Bicycle-Locks-Updated

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-327`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** # Hacking BLE Bicycle Locks for Fun & A Small Profit ## whoami - From Sunny Singapore - Senior Security Consultant @ MWR - Mobile and Wireless Geek - BlackHat USA 2016 – Bad for Enterprise: Attacking BYOD Enterprise Mobile Security Solutions ## Overview 1. Bike-Sharing Economy an
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Wireless Keystroke Injection (WKI) via Bluetooth Low Energy (BLE)

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-327`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** # Wireless Keystroke Injection (WKI) via Bluetooth Low Energy (BLE) JOSÉ PICÓ FERNANDO PERERA jose.pico@layakk.com fernando.perera@layakk.com ## What is this talk about? DON’T BELIEVE ME JUST WATCH ## The attack scenario ### What you just saw ### The attack scenario: initial situ
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
