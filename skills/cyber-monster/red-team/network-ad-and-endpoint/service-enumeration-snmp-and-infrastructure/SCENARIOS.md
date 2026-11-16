# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`service-enumeration-snmp-and-infrastructure`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Mentor

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Mentor is a medium difficulty Linux machine whose path includes pivoting through four different users before arriving at root. After scanning an 'SNMP' service with a community string that can be brute forced, plaintext credentials are discovered which are used for an 'API' endpoint, which proves to be vulnerable to...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: HTB: AirTouch

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** AirTouch simulates a wireless network environment. I’ll start by pulling a default password from SNMP to SSH as a consultant user inside a container with virtual wireless interfaces. From there, I’ll capture and crack a WPA2-PSK handshake to join the tablet network, then decrypt
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Mentor

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Mentor focuses on abusing a FastAPI API and SNMP enumeration. I’ll brute force a second community string that gives more access than the default “public” string. With that, I’ll get access to the running process command lines, and recover a password. With that password, I can get
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Pit

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Pit used SNMP in two different ways. First, I’ll enumerate it to leak the location of a webserver running SeedDMS, where I’ll abuse a webshell upload vulnerability to get RCE on the host. I’m not able to get a reverse shell because of SeLinux, but I can enumerate enough to find a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Sneaky

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Sneaky presented a website that after some basic SQL injection, leaked an SSH key. But SSH wasn’t listening. At least not on IPv4. I’ll show three ways to find the IPv6 address of Sneaky, and then SSH using that address to get user. For root, there’s a simple buffer overflow with
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Intense

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Intense presented some cool challenges. I'll start by finding a SQL injection vulnerability into an sqlite database. I'm able to leak the admin hash, but not crack it. Using the source code for the site, I'll see that if I can use a hash extension attack, I can use the hash trick
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Monitored

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Monitored is all about a Nagios XI monitoring system. I'll abuse it over and over to slowly escalate privileges ending up at root. I'll find initial creds from SNMP, but the account is disabled. I'll abuse the API to get a token that provides authentication to the site. From ther
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
