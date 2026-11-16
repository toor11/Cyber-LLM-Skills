# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`nmap-nse-audit-script-authoring`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Script Run by Default Without Opt-In

- **Surface & Preconditions:** A new script lands in `safe` and starts running during every `-sC` scan against production.
- **Root Cause & Impact:** The category made it default-eligible, and its request count per host was not bounded.
- **Verification & Fix:** Move it to `discovery` only, keep one request per port, and document the exact `--script` selector in the report.

## Case 2: Silent Script Read as Clean Target

- **Surface & Preconditions:** A script returns nothing against a host, and the report states the feature is absent.
- **Root Cause & Impact:** The port was filtered, so the script's portrule never fired.
- **Verification & Fix:** Show port state from the same scan, and treat a filtered port as an incomplete observation rather than a negative result.
