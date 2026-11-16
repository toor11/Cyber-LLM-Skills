# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`lab-and-tooling-setup`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Bridged Adapter Reaches Production

- **Surface & Preconditions:** A lab VM is created on the default bridged adapter and a misaddressed command hits a production host.
- **Root Cause & Impact:** The lab had a route to the corporate subnet, and no isolation test was run.
- **Verification & Fix:** Recreate the network as internal-only, run the route and connection test, and record it before resuming scenarios.

## Case 2: Results Differ Between Analysts

- **Surface & Preconditions:** Two analysts get different outputs from the same scenario.
- **Root Cause & Impact:** Their labs had different tool versions, and the manifest was not enforced.
- **Verification & Fix:** Pin versions in the lab image, verify against the manifest, and re-run both to confirm the difference disappears.
