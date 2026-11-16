# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`go-ssa-and-rust-clippy-security-lints`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Lint That Flags Generated Protobuf

- **Surface & Preconditions:** A new analyzer reports hundreds of findings, all in generated files.
- **Root Cause & Impact:** Generated code is not under review and cannot be changed, so the rule's value is negative until it excludes generated headers.
- **Verification & Fix:** Detect the generated marker in the file header, skip those files, and keep a fixture that asserts the exclusion.

## Case 2: Analyzer That Breaks the Build Clock

- **Surface & Preconditions:** A rule walks every function for every package, and full builds slow from seconds to minutes.
- **Root Cause & Impact:** The analyzer is correct but unaffordable, so it gets disabled and stops providing assurance.
- **Verification & Fix:** Cache per-function results, restrict the walk to functions containing the target callee, and re-measure before enabling.
