# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`waf-bypass-and-payload-obfuscation-parser-differentials`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Microsoft IIS 4.0/5.0 - Chunked Encoding Transfer Heap Overflow (3)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-693`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # HackTheBox Rebound Write-Up — Insane! Rebound is an incredible insane HackTheBox machine created by Geiseric. It’s a pure Active Directory box that feels more like a small multi-machine lab than just another singular machine. I completed it back during the first week that it wa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Netty: HTTP Request Smuggling via Chunked Extension Quoted-String Parsing

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-693`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary Netty incorrectly parses quoted strings in HTTP/1.1 chunked transfer encoding extension values, enabling request smuggling attacks. ## Background This vulnerability is a new variant discovered during research into the "Funky Chunks" HTTP request smuggling techniques: T
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Apache 1.x/2.0.x - Chunked-Encoding Memory Corruption (2)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-693`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Tabby (HTB) walkthrough This is my walk-through on retired machine "Tabby" on HacktheBox. IP: 10.10.10.194 Machine Type: Linux Release Date: 07/20/2020 Vuln/Exploits: LFI / CVE-2020–1938 / lxd (priv esc) Tools used: Nmap / Curl / OSINT / Netcat / John / Started with the usual n
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: H3: Unbounded Chunked Cookie Count in Session Cleanup Loop may Lead to Denial of Service

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-693`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The 'setChunkedCookie()' and 'deleteChunkedCookie()' functions in h3 trust the chunk count parsed from a user-controlled cookie value ('__chunked__N') without any upper bound validation. An unauthenticated attacker can send a single request with a crafted cookie header
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Netty: HTTP Request Smuggling via Chunked Extension Quoted-String Parsing

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-693`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Netty: HTTP Request Smuggling via Chunked Extension Quoted-String Parsing - **OSV ID**: GHSA-pwqr-wmgm-9rr8 - **CVE**: CVE-2026-33870 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N - **Published**: 2026-03-26T18:48:55Z - **Modified**: 2026-03-27T22:04:14.372867Z - **A
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Microsoft IIS 4.0/5.0 - Chunked Encoding Transfer Heap Overflow (2)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-693`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # How to exploit an XSS to Stealth Cookies (With python server) There are a few ways and techniques to get the XSS cookies of an administrator account. On this example PoC im gonna show a way to get the administrator cookies. This article was writen based on a Hackthebox machine
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
