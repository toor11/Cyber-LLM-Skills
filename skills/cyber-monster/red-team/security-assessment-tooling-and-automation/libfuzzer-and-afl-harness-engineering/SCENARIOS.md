# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`libfuzzer-and-afl-harness-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Campaign With No Coverage Growth

- **Surface & Preconditions:** A harness runs for hours and finds nothing while the parser is known to be fragile.
- **Root Cause & Impact:** The harness copies input into a fixed buffer and truncates before the parser's state machine.
- **Verification & Fix:** Remove the truncation, cap input size instead, seed with real samples, and confirm new edges appear in the campaign statistics.

## Case 2: Crash That Only Reproduces Under the Fuzzer

- **Surface & Preconditions:** A reported crash does not reproduce when the input is fed through the product's CLI.
- **Root Cause & Impact:** The harness passes a length the CLI never produces, so the crash is outside the reachable domain.
- **Verification & Fix:** Replay through the CLI with the same length semantics, and if it does not reproduce, report the harness assumption as the defect.
