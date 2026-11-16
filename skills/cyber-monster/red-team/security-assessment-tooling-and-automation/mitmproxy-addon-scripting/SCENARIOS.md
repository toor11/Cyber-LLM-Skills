# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`mitmproxy-addon-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Header Finding That Was the Proxy's Doing

- **Surface & Preconditions:** A capture shows no HSTS header on an endpoint that the server does send it on.
- **Root Cause & Impact:** The addon removed the header before logging, so the observation describes the proxy.
- **Verification & Fix:** Re-capture with a read-only addon, diff the header sets, and only then report the server's behaviour.

## Case 2: Pinning Failure Misread as Misconfiguration

- **Surface & Preconditions:** A mobile client rejects every proxied connection with a certificate error.
- **Root Cause & Impact:** The client pins its server certificate, which is a defensive property, not a TLS defect.
- **Verification & Fix:** Record the observed pin set from the client binary, confirm the rejection is consistent across hosts, and report pinning as a strength.
