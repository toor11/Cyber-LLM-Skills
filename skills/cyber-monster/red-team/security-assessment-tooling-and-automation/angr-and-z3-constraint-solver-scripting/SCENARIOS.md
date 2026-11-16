# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`angr-and-z3-constraint-solver-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Licence Check That Reads a Fixed-Width Key

- **Surface & Preconditions:** A CLI validator reads 16 bytes from stdin, compares them byte-wise against a table, and only then enables the paid path.
- **Root Cause & Impact:** The comparison is guarded by a length check and a checksum byte, so a naive symbolic run without the checksum constraint returns unsat and the check is assumed safe.
- **Verification & Fix:** Model the checksum as an extra constraint, explore find=paid-path with the error handler in avoid, then replay the model bytes and confirm the paid path is entered.

## Case 2: Index Bound Inside a Parser Struct

- **Surface & Preconditions:** A file parser reads a 32-bit length from a header and uses it to index a fixed table without an upper bound.
- **Root Cause & Impact:** The missing bound is an arithmetic constraint, not a control-flow one, so fuzzing rarely trips it while the model is trivial.
- **Verification & Fix:** Write the constraint standalone in z3 against the same width and semantics, show a sat model above the table size, then confirm the read with the unmodified parser under a sanitizer build.
