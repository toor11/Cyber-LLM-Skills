# Detection Queries and Telemetry Artifacts

> Sub-skill: [`flask-and-fastapi-security`](SKILL.md) | Family: **Application Security**

Flask/FastAPI review queries. Each row names the artefact and the pattern that indicates a framework guarantee was bypassed.

## Authorisation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Ownership predicate | queries in handlers that took a `Depends` principal | Predicate present in the WHERE clause, not only in the dependency |
| Tenant source | `tenant_id` read from body or query | Zero; derived from the principal |
| Admin gate | routes with `is_admin` checks inside the body | Gate is a dependency or decorator, not an `if` after the fetch |

## Input and Output

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Schema closure | Pydantic models without `extra='forbid'` on write endpoints | Closed on every write path |
| Template source | `render_template_string`, `Markup(`, the safe filter applied to a variable | Template source constant; values passed as context |
| SQL identifiers | `text(` with an interpolated column | Closed map, never a raw parameter |

## Parser and Platform

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Multipart limits | `request.form(max_fields=..., max_part_size=...)` | Starlette 1.3.1 or later, so the limits apply to urlencoded too |
| Werkzeug | resolved Werkzeug version | 3.1.9 or later on Windows file serving |
| Secret rotation | `SECRET_KEY_FALLBACKS` present during rotation | Old keys listed only for the overlap window |

## Telemetry Prerequisites

- The dependency graph as executed, since decorators and dependencies both authenticate and either can be missing.
- Two accounts for the substitution probe and a malformed profile update for the mass-assignment probe.
- The lockfile-resolved versions of Flask, Werkzeug, Starlette, and python-multipart.

## Deployment Gates

- No write endpoint ships without a closed schema; a route-level test asserts the extra field is ignored.
- Parser and framework versions are checked at build against the current advisories.
