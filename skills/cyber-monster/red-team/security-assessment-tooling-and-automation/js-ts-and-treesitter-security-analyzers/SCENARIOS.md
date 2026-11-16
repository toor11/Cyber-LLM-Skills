# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`js-ts-and-treesitter-security-analyzers`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Rule That Flags Documentation Examples

- **Surface & Preconditions:** A new rule reports every `innerHTML` in the repository, most of them in Markdown examples and test fixtures.
- **Root Cause & Impact:** The capture was not filtered by file type or by argument shape, so documentation counts as code.
- **Verification & Fix:** Restrict the query to non-test source paths and require a non-literal right-hand side, then re-run to confirm only real sinks remain.

## Case 2: TypeScript Syntax Missed by the JavaScript Grammar

- **Surface & Preconditions:** A scan of a `.ts` codebase reports far fewer sinks than a manual review found.
- **Root Cause & Impact:** The parser produced error nodes on type annotations and stopped capturing inside those subtrees.
- **Verification & Fix:** Pin the TypeScript grammar for `.ts`/`.tsx`, re-parse, and compare the capture count with the manual list.
