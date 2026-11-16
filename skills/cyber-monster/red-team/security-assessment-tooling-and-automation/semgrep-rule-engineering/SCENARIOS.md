# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`semgrep-rule-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Rule Reports Parameterised Queries

- **Surface & Preconditions:** A new taint rule flags every `execute` call in the repository, including bound-parameter calls.
- **Root Cause & Impact:** The sink matched the call rather than the query argument, and the sanitiser set was empty.
- **Verification & Fix:** Add `focus-metavariable` on the query argument, list the project's validators as sanitisers, and re-run the fixture pair before enabling `--error`.

## Case 2: Sanitiser Added After a False-Positive Report

- **Surface & Preconditions:** A finding is dismissed as a false positive because the value is int-cast, and the rule is disabled wholesale.
- **Root Cause & Impact:** The rule needed a sanitiser, not retirement; disabling it loses coverage for the real class.
- **Verification & Fix:** Add `int(...)` to `pattern-sanitizers`, add an `# ok:` fixture for the cast path, and keep the rule enabled.
