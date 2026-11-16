# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: WiFiPhisher Attack Don’t Get Got

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** WiFiPhisher Attack In this beginner-friendly walkthrough, we will explore the ins and outs of the WiFiPhisher attack. The tools for wifi cracking are easily accessible by anyone in our interconnected world. This is a different type of attack as it involves social engineering, which adds another layer to the tool.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: WPA/WPA2 PMKID

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-327`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # WPA/WPA2 PMKID STEP 1: https://github.com/ZerBea/hcxdumptool https://github.com/aircrack-ng/aircrack-ng STEP 2: Find target BSSID: 'bash airodump-ng ' STEP 3: Add BSSID in ‘bssid.txt’ and use ‘hcxdumptool’: 'bash hcxdumptool -i --filterlist=bssid.txt --filermo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Pwning WPA/WPA2 Networks With Bettercap and the PMKID Client-Less Attack / evilsocket

- **Provenance:** Source: `CYBER_CPT/secwiki` | CWE: `CWE-327`
- **Context / Surface:** Source: secwiki (en)
- **Root Cause / Analysis:** [![evilsocket] (/images/glider.png) evilsocket Preoccupied with a single leaf, you won't see the tree. Preoccupied with a single tree... you'll miss the entire forest.] (/) [HOME] (/) [RSS] (/atom.xml) # Pwning WPA/WPA2 Networks With Bettercap and the PMKID Client-Less Attack BY Simo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
