# Detection Queries and Telemetry Artifacts

> Sub-skill: [`express-and-fastify-security`](SKILL.md) | Family: **Application Security**

Middleware and schema checks for Node services. Each row names the artefact and the pattern that changes the security property.

## Pipeline Order

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Guard placement | `app.use` sequence and router mount points | Auth runs before body parsers on every route |
| Error handler | final `(err, req, res, next)` handler | No stack or ORM message in the response |
| Catch-all path | requests to unknown routes | Not served by a route that skips the guard |

## Input Schema

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Body schema | Fastify `schema.body` or the Express validator | `additionalProperties: false` with primitive types |
| Query parsing | `qs` options or the query parser setting | `allowPrototypes: false`, bounded depth |
| Body size | `limit` on the parser | Explicit and appropriate to the route |

## Runtime Version

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| body-parser | resolved version in the lockfile | 2.4.0 or later, or 1.20.9 or later |
| Node | `node --version` on the host image | A release carrying the patched Brotli decoder |
| Decompression | `inflate` option at each parser call | `false` unless compressed bodies are required |

## Telemetry Prerequisites

- The lockfile-resolved versions of `body-parser`, `qs`, and the Node runtime, since several findings are version-gated.
- A staging deployment where a malformed body can be sent without affecting other tenants.
- The route registration module, to reconstruct middleware order as executed.

## Deployment Gates

- Every body-consuming route carries a schema with `additionalProperties: false`, enforced by a route-registration lint rather than review.
- Parser versions are checked at build, and `inflate` is explicit at every call site.
