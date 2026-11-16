# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`burp-montoya-and-jython-extension-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Extension That Rewrites Headers Globally

- **Surface & Preconditions:** A tester installs an extension that strips caching headers from every response to see fresh content.
- **Root Cause & Impact:** Because the handler is registered for all tools with no scope check, other testers on the same Burp instance see non-production behaviour and file false findings.
- **Verification & Fix:** Add an `api.scope().isInScope` guard, log every mutation with the host, and re-run the affected checks against an unmodified session.

## Case 2: Bulk Sweep That Never Stops

- **Surface & Preconditions:** An extension spawns a thread per candidate endpoint to test for a header reflection.
- **Root Cause & Impact:** Threads outside Burp's task engine cannot be cancelled from the dashboard, so the sweep continues after the tester stops it.
- **Verification & Fix:** Move the sweep onto `createRequestEngine()` with a named task and a resource pool, then verify cancellation from the dashboard.
