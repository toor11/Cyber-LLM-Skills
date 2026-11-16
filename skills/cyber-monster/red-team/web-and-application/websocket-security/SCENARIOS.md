# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`websocket-security`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Can’t Stop, Won’t Stop Hijacking (CSWSH) WebSockets

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-1385`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Can’t Stop, Won’t Stop Hijacking (CSWSH) WebSockets The WebSocket Protocol, standardized in 2011 with [RFC 6455] (https://datatracker.ietf.org/doc/html/rfc6455), enables full-duplex communication between clients and web servers over a single, persistent connection, resolving a l
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: WebSocket Attacks

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-1385`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # WebSocket Attacks ## What are WebSockets WebSocket connections are established through an initial **HTTP** handshake and are designed to be **long-lived**, allowing for bidirectional messaging at any time without the need for a transactional system. This makes WebSockets partic
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: CrossFitTwo

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-1385`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Much like CrossFit, CrossFitTwo was just a monster of a box. The centerpiece is a crazy cross-site scripting attack through a password reset interface using DNS to redirect the admin to a site I control to then have them register an account for me. I'll then hijack some socket.io
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: WebSocket Security Cheat Sheet

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-1385`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # WebSocket Security Cheat Sheet ## Introduction WebSockets enable real-time, bidirectional communication between clients and servers, powering applications like chat systems, live trading platforms, and collaborative tools. Unlike traditional HTTP requests, WebSocket connections
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Nginx-UI: Cross-Site WebSocket Hijacking (CSWSH) via missing origin validation on all WebSocket endp

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-1385`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Nginx-UI: Cross-Site WebSocket Hijacking (CSWSH) via missing origin validation on all WebSocket endpoints - **OSV ID**: GHSA-78mf-482w-62qj - **CVE**: CVE-2026-34403 - **Published**: 2026-04-21T15:13:01Z - **Modified**: 2026-04-21T15:41:12.709513Z - **Affected Packages**: githu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Backfire

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-1385`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Backfire is all about exploiting red team infrastructure, first Havoc, and then HardHatC2. I’ll start with a Havoc server and leak the configuration from the website. I’ll exploit an SSRF vulnerability to get access to the admin port internally. There’s an authenticated RCE vulne
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
