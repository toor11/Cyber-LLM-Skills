# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`adversary-emulation-planning`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Emulation With No Scoring

- **Surface & Preconditions:** A team executes a realistic intrusion chain and delivers a narrative report.
- **Root Cause & Impact:** No step names the telemetry it should have produced, so the defenders cannot tell which detections were tested.
- **Verification & Fix:** Rewrite the plan with expected events per step, re-run the steps individually, and record a verdict per technique.

## Case 2: Coverage Gap Discovered After the Exercise

- **Surface & Preconditions:** A technique produced no telemetry because the source was never collected.
- **Root Cause & Impact:** The plan assumed a source that was not in scope, so the gap was invisible until results were compiled.
- **Verification & Fix:** Prove each claimed source produces events before the exercise, and record uncollected sources as pre-declared gaps.
