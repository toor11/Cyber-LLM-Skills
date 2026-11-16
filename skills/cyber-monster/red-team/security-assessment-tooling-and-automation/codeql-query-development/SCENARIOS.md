# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`codeql-query-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Query That Reports Every Query Call

- **Surface & Preconditions:** A custom query selects all `execute` calls without taint, so the first run returns thousands of results.
- **Root Cause & Impact:** The query answers *where SQL is executed*, not *where untrusted data reaches SQL*, so reviewers stop reading the output.
- **Verification & Fix:** Declare a remote-flow source, mark the ORM's parameter binding as a barrier, and require the result to vanish on the fix commit.

## Case 2: Barrier Missing for a Project Sanitiser

- **Surface & Preconditions:** A helper validates and escapes input, but the query does not model it, so a patched path still reports.
- **Root Cause & Impact:** The finding is real at the query level and false at the code level, which erodes trust in the whole run.
- **Verification & Fix:** Add the helper to `isBarrier`, re-run, and confirm exactly the previously-escaped paths disappear.
