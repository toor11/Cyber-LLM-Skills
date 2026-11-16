# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`idapython-automation-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Missing Xrefs Because Analysis Had Not Finished

- **Surface & Preconditions:** A script reports a dangerous import with no call sites, and the analyst records it as dead code.
- **Root Cause & Impact:** The script ran before auto-analysis completed, so the call sites existed but had no xrefs yet.
- **Verification & Fix:** Add `ida_auto.auto_wait()`, re-run against the saved database, and compare the two xref sets before concluding anything about reachability.

## Case 2: Triage Lost Between Analysts

- **Surface & Preconditions:** A second analyst repeats the entire call-site review because the first pass left no annotations.
- **Root Cause & Impact:** The findings existed only in a console log, not in the database.
- **Verification & Fix:** Write renames and comments back with `idc.set_cmt`, save the database, and attach the address list to the report.
