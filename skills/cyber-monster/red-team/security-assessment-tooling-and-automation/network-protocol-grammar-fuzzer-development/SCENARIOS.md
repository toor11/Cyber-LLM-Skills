# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`network-protocol-grammar-fuzzer-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Campaign That Only Exercised the Framing Check

- **Surface & Preconditions:** A fuzzer runs for hours with no findings on a daemon known to have a parser bug.
- **Root Cause & Impact:** The mutation included the length field, so the framing check rejected every case before parsing.
- **Verification & Fix:** Hold the outer frame length and mutate only the payload, then confirm the daemon reaches the parser by observing its log line for parsed messages.

## Case 2: Crash Lost Because the Service Was Not Restarted

- **Surface & Preconditions:** The first crash stops the daemon and every later case fails to connect, so the campaign reports one failure and no detail.
- **Root Cause & Impact:** There was no health check between cases, and the crash message was not logged.
- **Verification & Fix:** Add a health check that restarts the service and log the full frame hex for each failure, then replay the logged frame to confirm reproducibility.
