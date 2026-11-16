# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`llm-output-handling-and-sinks`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Markdown Renderer Passes Raw HTML

- **Surface & Preconditions:** A chat feature renders model output with a markdown library configured to allow HTML.
- **Root Cause & Impact:** A response containing a script tag executes in every viewer's browser, and the model can be induced to produce it.
- **Verification & Fix:** Disable raw HTML in the renderer or sanitise with an allowlist, add escaping at the sink, and test with the probe output.

## Case 2: Quoted Value in a Query

- **Surface & Preconditions:** A search feature interpolates the model's rewritten query into a SQL statement.
- **Root Cause & Impact:** A response containing a quote alters the statement, and the injection is reachable through ordinary user input.
- **Verification & Fix:** Bind the value as a parameter, remove interpolation, and test with an output containing a quote and a comment marker.
