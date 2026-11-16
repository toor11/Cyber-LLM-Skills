# Detection Queries and Telemetry Artifacts

> Sub-skill: [`dotnet-aspnet-core-security`](SKILL.md) | Family: **Application Security**

ASP.NET Core review checks, answerable from code, endpoint metadata and the runtime version.

## Authorisation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Endpoint metadata | `RequireAuthorization` or `[Authorize]` per endpoint | Present on every non-anonymous endpoint |
| Resource decision | `AuthorizeAsync` or a scoped query per resource fetch | Present on single-resource actions |
| Query filter | `HasQueryFilter` on tenant-owned entities | Enabled, with an explicit `IgnoreQueryFilters` allowlist |

## Input Handling

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Binding type | action parameters typed as entity classes | Zero; DTOs only |
| Model validation | `[ApiController]` present or `ModelState.IsValid` checked | Invalid models never reach the action |
| XML parsing | `DtdProcessing` value at every `XmlReader.Create` | `Prohibit` |

## SQL and Runtime

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Raw SQL | `FromSqlRaw` call sites | Constant strings only |
| Runtime patch | `dotnet --list-runtimes` on the host versus the target framework | At or above the current servicing release |
| Data Protection | key ring persistence and `SetApplicationName` | Persisted and shared across instances |

## Telemetry Prerequisites

- Endpoint metadata (`EndpointDataSource`) or the route table, so authorisation coverage is measured rather than sampled.
- The host's runtime list, because several 2026 fixes are runtime-level.
- Two accounts in different tenants for the overposting probe.

## Deployment Gates

- No action binds an entity type; the check runs in CI as an analyzer or a grep gate.
- Runtime patch level is verified per deployment, including self-contained builds.
