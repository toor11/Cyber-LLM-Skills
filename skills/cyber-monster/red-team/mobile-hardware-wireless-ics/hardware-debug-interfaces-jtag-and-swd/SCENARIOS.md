# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`hardware-debug-interfaces-jtag-and-swd`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: A Deep Dive Into Samsung's TrustZone - "SWD, OpenOCD and Xbox One Controllers"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-284`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Hardware Debugging for Reverse Engineers Part 1: SWD, OpenOCD and Xbox One Controllers ## Background I was looking around my apartment for potential targets for my next post and was pleasantly surprised to find the following XBox One controller still in the packaging: I don’t r
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: A Deep Dive Into Samsung's TrustZone - "TAG, SSDs and Firmware Extraction"Manipulating AES Traffic

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-284`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Hardware Debugging for Reverse Engineers Part 2: JTAG, SSDs and Firmware Extraction # Background To follow up on my [last post] (https://wrongbaud.github.io/posts/stm-xbox-jtag/) about SWD and hardware debugging, I wanted to do a deep dive into JTAG from a reverse-engineering pe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB Sherlock: Campfire-1

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Campfire-1 is the first in a series of Sherlocks looking at identifying critical active directory vulnerabilities. This challenge requires looking at event log and prefetch data to see an attack run PowerView and the Rubeus to perform a Kerberoasting attack. ## Background ### Sce
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Freelancer

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Freelancer starts off by abusing the relationship between two Django websites, followed by abusing an insecure direct object reference in a QRcode login to get admin access. From there, I'll use impersonation in the MSSQL database to run commands as the sa account, enabling xp_cm
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Investigation

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Investigation starts with a website that accepts user uploaded images and runs Exiftool on them. This version has a command injection. I'll dig into that vulnerability, and then exploit it to get a foothold. Then I find a set of Windows event logs, and analyze them to extract a p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Vessel

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Vessel is a really clever box with some nice design. Several of the bugs are publicly disclosed, but at the time of release didn’t have public exploit, so they required digging into the tech to figure out how to abuse them. I’ll start by pulling a git repo from the website, and f
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
