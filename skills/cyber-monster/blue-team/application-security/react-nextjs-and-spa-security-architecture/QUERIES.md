# Detection Queries and Telemetry Artifacts

> Sub-skill: [`react-nextjs-and-spa-security-architecture`](SKILL.md) | Family: **Application Security**

App Router boundary checks. Each row names the artefact in the build and what its presence proves.

## Endpoint Inventory

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Server Actions | files with the `'use server'` directive | Each exported function has an in-body session and ownership check |
| Route handlers | `app/**/route.ts` exports | Same, plus a schema on the body |
| Middleware matchers | `config.matcher` in `middleware.ts` | Never the only authorisation control |

## Boundary

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Serialised props | props passed from server to client components | No field outside the caller's entitlement |
| Taint | `taintUniqueValue`/`taintObjectReference` usage | Present on secrets and tokens |
| Environment leakage | `NEXT_PUBLIC_` prefixed variables | No secret carries the prefix |

## Rendering Sinks

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Raw HTML | `dangerouslySetInnerHTML` call sites | Sanitised input only |
| Markdown | renderer configuration | Raw HTML disabled or sanitised |
| URL construction | `href`/`src` from user data | Scheme allowlist, no `javascript:` |

## Telemetry Prerequisites

- The build output or route manifest, because action ids are what an attacker replays.
- Two accounts with different entitlements for the replay probe.
- The framework version in the lockfile, since three of the 2026 findings are version-gated.

## Deployment Gates

- No Server Action ships without an in-body authorisation check; enforced by a lint over the directive.
- Framework version is pinned and checked against the current advisories at each release.
