# Detection Queries and Telemetry Artifacts

> Sub-skill: [`django-security-patterns`](SKILL.md) | Family: **Application Security**

Django/DRF review queries. Each row names the artefact and the pattern that shows the framework guarantee was overridden.

## Framework Overrides

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Raw SQL | `RawSQL(`, `.extra(`, `cursor.execute(` call sites | Interpolated fragment contains a request variable or an identifier |
| Unsafe markup | `mark_safe(`, `format_html(` with a non-constant format string | Caller-influenced markup reaches the template |
| Serializer surface | `fields = '__all__'` or `exclude =` on write serializers | Protected columns reachable from the body |

## DRF Actions

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Object fetch | `@action` bodies calling `objects.get(pk=` | Presence indicates permission checks are skipped |
| Permission classes | viewset `permission_classes` versus action overrides | No action loosens the default |
| Throttle scope | `throttle_scope` per action | Sensitive actions carry their own scope |

## Settings Switches

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Debug | `DEBUG` in the deployed settings module | False in production |
| Hosts | `ALLOWED_HOSTS` value | Explicit list, no wildcard |
| Cookies | `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY` | All True on TLS deployments |

## Telemetry Prerequisites

- The deployed settings module, since several guarantees are switched off there rather than in code.
- The DRF router output, so custom actions are enumerated rather than searched for.
- Two users in the same role and one in another tenant for the substitution probe.

## Deployment Gates

- Every custom action carries a probe; scaffolding does not generate them, so they are the recurring gap.
- The Django patch level is checked against the current security release before sign-off.
