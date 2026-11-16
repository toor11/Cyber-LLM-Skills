# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`http2-specific-attacks`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Upgrade Header Smuggling

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-444`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Upgrade Header Smuggling ### H2C Smuggling #### HTTP2 Over Cleartext (H2C) H2C, or **http2 over cleartext**, deviates from the norm of transient HTTP connections by upgrading a standard HTTP **connection to a persistent one**. This upgraded connection utilizes the http2 binary
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: io.netty:netty-codec-http2 vulnerable to HTTP/2 Rapid Reset Attack

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-444`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** A client might overload the server by issuing frequent RST frames. This can cause a massive amount of load on the remote system and so cause a DDOS attack. ### Impact This is a DDOS attack, any http2 server is affected and so you should update as soon as possible. ### Patches Thi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: github.com/nghttp2/nghttp2 has HTTP/2 Rapid Reset

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-444`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact Rapidly creating and cancelling streams (HEADERS frame immediately followed by RST_STREAM) without bound cause denial of service. See https://www.cve.org/CVERecord?id=CVE-2023-44487 for details. ### Patches nghttp2 v1.57.0 mitigates this vulnerability by default. ### W
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HPACK Denial of Service vulnerability (HPACK Bomb)

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-444`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** A HTTP/2 implementation built using any version of the Python HPACK library between v1.0.0 and v2.2.0 could be targeted for a denial of service attack, specifically a so-called "HPACK Bomb" attack. This attack occurs when an attacker inserts a header field that is exactly the siz
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: AdGuard Home: HTTP/2 Cleartext (h2c) Upgrade Authentication Bypass

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-444`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # AdGuard Home: HTTP/2 Cleartext (h2c) Upgrade Authentication Bypass AdGuard Home: HTTP/2 Cleartext (h2c) Upgrade Authentication Bypass - **OSV ID**: GHSA-5fg6-wrq4-w5gh - **CVE**: CVE-2026-32136 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - **Published**: 2026-03-12
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: AdGuard Home: HTTP/2 Cleartext (h2c) Upgrade Authentication Bypass

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-444`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** VULNERABILITY: HTTP/2 Cleartext (h2c) Upgrade Authentication Bypass ======================================================================== Severity: CRITICAL CVSS 3.1: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) CWE: CWE-287 (Improper Authentication) Component: internal/home/web.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
