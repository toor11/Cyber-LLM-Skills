# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`python-atheris-and-hypothesis-security-fuzzing`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Property Green Because It Catches Everything

- **Surface & Preconditions:** A parser property passes for months while the parser has a crash on a specific header.
- **Root Cause & Impact:** The property caught every exception, so the crash counted as an expected rejection.
- **Verification & Fix:** Declare the expected exception types and assert a postcondition, then re-run to see the crash surface.

## Case 2: Fuzzer Crash That Is a Harness Bug

- **Surface & Preconditions:** Atheris reports a crash on a two-byte input.
- **Root Cause & Impact:** The harness indexes the input without a length check, so the crash is in the harness.
- **Verification & Fix:** Guard the length in the harness, re-run, and keep the crash file as a harness regression instead of a product bug.
