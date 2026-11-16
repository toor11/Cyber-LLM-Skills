# Operational Triage and Response Playbook

> Sub-skill: [`secure-code-review`](SKILL.md) | Family: **Application Security**

Structured runbook for `secure-code-review`. Paired offensive/mechanics reference: [`codeql-query-development`](../../../red-team/security-assessment-tooling-and-automation/codeql-query-development/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `secure code review`.
- Alert, hunt outlier, or review request matching `code audit`.
- Alert, hunt outlier, or review request matching `source review`.
- Alert, hunt outlier, or review request matching `sast review`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Path-proven flow from request data to an interpreter sink | Confirmed finding | Quote the witness path, propose the parameterised or allowlisted form, add a negative test |
| Sink reachable only from a settings constant | Non-finding (note) | Record why it is inert; do not raise severity to look thorough |
| Flow blocked by a framework default you can name | Non-finding | Name the default and the version, and flag any config override that disables it |

## Containment and Recovery

1. **Fix forward, not around:** land the parameterised or allowlisted form and a negative test in the same change so the regression is caught by CI rather than by the next review.
2. **Check the sibling paths:** the same copy-pasted handler usually exists in three or four places; grep the sink shape across the repo before closing.
3. **Hunt for prior use:** if the sink handled authentication or tenant data, query request logs for the probe shape over the retention window before concluding it was never exercised.
