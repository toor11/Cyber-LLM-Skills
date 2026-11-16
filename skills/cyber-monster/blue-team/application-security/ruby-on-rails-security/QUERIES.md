# Detection Queries and Telemetry Artifacts

> Sub-skill: [`ruby-on-rails-security`](SKILL.md) | Family: **Application Security**

Rails review checks answerable from controllers, routes and initialisers.

## Authorisation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Scoped lookup | `find`/`find_by` call sites | Reached through a scoped relation or `policy_scope` |
| Before-action coverage | `before_action :authenticate_user!` versus skipped actions | No security-relevant action skips it |
| Custom routes | member/collection routes in `config/routes.rb` | Each action authorises explicitly |

## Mass Assignment

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Permit lists | `params.permit!`, `permit(:all)`, `permit` on sensitive columns | Explicit allowlist excluding `role`, `tenant_id`, `admin` |
| Nested attributes | `accepts_nested_attributes_for` models | Only intended associations are permitted |

## Sinks and Loaders

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| SQL conditions | `where` with an interpolated string, `order` with params | Hash or placeholder form, allowlisted column |
| YAML | `YAML.load` versus `safe_load` | `safe_load` with permitted classes |
| Rendering | `render inline:`, `raw`, `html_safe` | No caller-controlled template source or markup |

## Telemetry Prerequisites

- The routes file, so non-RESTful actions are enumerated.
- The policy layer (Pundit or CanCanCan) configuration, since scope may live there.
- Two users in different tenants for the substitution probe.

## Deployment Gates

- `brakeman` runs in CI with a recorded baseline; new warnings fail the build.
- Every custom route has an authorisation probe before merge.
