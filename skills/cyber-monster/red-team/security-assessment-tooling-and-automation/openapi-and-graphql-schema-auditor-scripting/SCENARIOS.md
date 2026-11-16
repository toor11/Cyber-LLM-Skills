# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`openapi-and-graphql-schema-auditor-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: One Operation Opted Out of Global Auth

- **Surface & Preconditions:** A document declares bearer auth globally, and a single report operation sets `security: []`.
- **Root Cause & Impact:** The empty array removes the requirement for that operation only, so the document's global block hides it.
- **Verification & Fix:** Enumerate the effective security per operation, confirm with a credentialed and uncredentialed request, and report the operation id.

## Case 2: GraphQL List Field Without Pagination

- **Surface & Preconditions:** A list field returns every row and accepts no `limit` or `first` argument.
- **Root Cause & Impact:** The absence of a pagination argument is the resource surface, and the schema states it explicitly.
- **Verification & Fix:** Report the field path and its arguments from the introspection result, then confirm the response size with one bounded query.
