# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`nuclei-template-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Template Firing on Every SPA Route

- **Surface & Preconditions:** A new template reports an exposed admin panel on forty hosts, all of which return 200 for `/admin`.
- **Root Cause & Impact:** The matcher keyed on status alone, and the SPA router answers 200 for every path.
- **Verification & Fix:** Add a body marker that only the panel emits and a DSL exclusion for the app shell, then re-run against the same hosts to confirm the count drops to the real exposures.

## Case 2: Version Range Boundary Written Backwards

- **Surface & Preconditions:** A template flags hosts running the patched release while missing vulnerable ones.
- **Root Cause & Impact:** The DSL comparison used the patched version as the upper bound, inverting the range.
- **Verification & Fix:** Rewrite the comparison against the advisory's boundary, test one vulnerable and one patched instance, and record both results in the template's validation notes.
