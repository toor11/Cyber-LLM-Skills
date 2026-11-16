# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`go-fuzz-and-cargo-fuzz-harness-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Harness That Rejects Almost Everything

- **Surface & Preconditions:** A JSON parser fuzz target requires a strict five-byte prefix before parsing, and the campaign reports no findings after hours.
- **Root Cause & Impact:** The conversion starves the corpus, so the parser's main loop is never entered and the green result is an artefact.
- **Verification & Fix:** Seed with real documents, relax the prefix to a length check, and confirm coverage of the parse function before trusting the run.

## Case 2: Panic Blamed on the Library

- **Surface & Preconditions:** A crasher reproduces only through the harness, and the fix is proposed in the dependency.
- **Root Cause & Impact:** The panic originates in the harness's slice conversion, not the library.
- **Verification & Fix:** Minimise the input, run it through the library's own test entry point, and move the fix into the harness boundary.
