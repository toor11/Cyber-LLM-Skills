# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`capstone-and-lief-binary-inspector-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Missing DEP on One Shipped Build

- **Surface & Preconditions:** The reference build has NX and PIE, the shipped build has neither, and the difference is a single linker flag.
- **Root Cause & Impact:** The gap is invisible from behaviour until an exploit is attempted, so it must be found from headers across every build variant.
- **Verification & Fix:** Inventory `has_nx` and `is_pie` per artefact hash for every shipped variant, and report the variant that diverges with its linker configuration.

## Case 2: Dangerous Import Reintroduced by a Dependency

- **Surface & Preconditions:** A `strcpy` import appears in the shipped binary although the project removed direct calls.
- **Root Cause & Impact:** The import is reachable through a statically linked dependency, so source-level review misses it.
- **Verification & Fix:** List imported functions, locate the calling site by disassembling the importing function, and report the dependency and call site together.
