---
name: dotnet-aspnet-core-security
description: "Reviews and hardens C# / ASP.NET Core applications: `[Authorize]` + `IAuthorizationService` resource-based authz, `[Bind]`/DTO overposting defense, EF Core `FromSqlInterpolated` vs `FromSqlRaw`, Data Protection key-ring configuration, and safe `XmlReaderSettings` (`DtdProcessing.Prohibit`). Use when auditing .NET services."
family: application-security
tier: core
triggers: ["aspnet core security", "ef core fromsqlraw", "iauthorizationservice", "c# secure code review"]
cwe: [CWE-89, CWE-862]
owasp: [A01:2025]
attack: []
capec: []
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
corpus_sparse: true
---

# Dotnet Aspnet Core Security - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

ASP.NET Core security rests on three framework behaviours: `[Authorize]` runs an authorisation handler before the action, model binding materialises a type from the request, and EF Core parameterises interpolated SQL while `FromSqlRaw` does not. Findings cluster where a developer binds a domain entity instead of a DTO, composes a raw SQL string, resolves a resource by id and never asks the authorisation service, or leaves the XML reader's DTD protection enabled. The review checks those four boundaries plus the runtime patch level.

- **CWE-862 / CWE-89 / CWE-611:** missing resource authorisation, raw SQL composition, and DTD processing left enabled.
- The November 2026 servicing release (ASP.NET Core 10.0.15) carries the current fixes, including CVE-2026-114157 (Kestrel named-pipe namespace ownership) and CVE-2026-114154 (HttpSys chunked request resource retention); self-contained deployments need a rebuild, not a runtime update.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the endpoint accepts a complex type **THEN** confirm it is a `record` DTO with explicit properties, never an EF entity; entity binding is overposting by design.
2. **IF** SQL is composed anywhere **THEN** require `FromSqlInterpolated` or EF LINQ over `FromSqlRaw` with concatenation.
3. **IF** the app hosts Kestrel on named pipes or uses HttpSys **THEN** check the runtime version against the current servicing release before reviewing code.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map endpoints to authorisation requirements.** Minimal APIs need `.RequireAuthorization()` per group or endpoint; controllers need `[Authorize]` plus a resource check. Record which mechanism applies where, because both can coexist and the weaker one wins on the endpoint it covers.
2. **Check the binding type for every action.** A parameter typed as an entity, or a `[FromBody]` on a class with settable navigation properties, lets the caller set owned columns.
3. **Choose the branch on the resource decision.** Collection filters take a `Where` predicate from the authenticated principal; single-resource endpoints take `IAuthorizationService.AuthorizeAsync` with the resource instance; admin endpoints take a policy that names the role requirement.
4. **Define the baseline-vs-probe differential.** Baseline: the owner renames their resource. Probe: a second user posts the same body with the owner's id and an extra `ownerId` field. The hardened build returns 403/404 and leaves `ownerId` unchanged.
5. **State the stop condition and the proof.** Stop when every action has a recorded authorisation mechanism, every complex parameter is a DTO, and the probe has been replayed; proof is the request pair plus the policy or handler registration.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `[FromBody] Project model` where `Project` is an EF entity | Proves overposting: the caller can set `OwnerId` and `IsPublic` on any ASP.NET Core endpoint. |
| `FromSqlRaw` with an interpolated string | Proves string composition reaches SQL; `FromSqlInterpolated` binds and is the framework's own safe form. |
| `[Authorize]` on the controller with a resource fetched by id and no `AuthorizeAsync` | Proves authentication-only: any signed-in user reaches any resource id. |
| `XmlReaderSettings` with `DtdProcessing.Parse` | Proves XXE exposure (CWE-611) on any .NET service parsing uploaded XML. |
| Runtime below 10.0.15 on a Kestrel named-pipe listener | Proves the CVE-2026-114157 namespace-ownership path is unpatched on that host. |

## Worked Contrast

**Vulnerable ASP.NET Core Endpoint (`FromSqlRaw` + Entity Overposting + Missing Resource Authz):**

```csharp
[Authorize]
[HttpPost("/api/projects/{id}/rename")]
public async Task<IActionResult> Rename(int id, [FromBody] Project model, string filter) {
    // BUG 1: Binding domain entity Project lets caller set model.OwnerId / IsPublic (overposting)
    // BUG 2: String interpolation inside FromSqlRaw is NOT parameterized (unlike FromSqlInterpolated)!
    var rows = await _db.Projects.FromSqlRaw($"SELECT * FROM Projects WHERE Name = '{filter}'").ToListAsync();
    _db.Projects.Update(model); // BUG 3: Never verified User owns project `id`!
    await _db.SaveChangesAsync();
    return Ok(rows);
}
```

**Hardened ASP.NET Core Endpoint (Narrow DTO + `IAuthorizationService` + Parameterized LINQ):**

```csharp
public record RenameProjectDto([Required, MaxLength(80)] string Name);

[Authorize]
[HttpPost("/api/projects/{id}/rename")]
public async Task<IActionResult> Rename(int id, [FromBody] RenameProjectDto dto, string filter) {
    var project = await _db.Projects.FindAsync(id);
    if (project is null) return NotFound();
    var authz = await _authz.AuthorizeAsync(User, project, "ProjectOwnerPolicy");
    if (!authz.Succeeded) return Forbid();
    project.Name = dto.Name;
    var rows = await _db.Projects.Where(p => p.OwnerId == project.OwnerId && p.Name == filter).ToListAsync();
    await _db.SaveChangesAsync();
    return Ok(rows);
}
```

**Why this matters:** Bind narrow `record` DTOs instead of EF entities, enforce resource ownership via `IAuthorizationService.AuthorizeAsync`, and use LINQ or `FromSql` / `FromSqlInterpolated` (never interpolated `FromSqlRaw`).

## When It Is NOT This Issue

- **`FromSqlRaw` with a constant format string and `SqlParameter` arguments.** Parameters make it equivalent to the interpolated form; check the arguments rather than the method name.
- **Entity binding with `[Bind]` or `TryUpdateModelAsync` restricted to a property list.** That is an allowlist; the finding is the unrestricted bind.
- **Missing resource check behind a policy that already filters the query.** A global query filter on the DbContext scopes by tenant, which is a predicate even when the action looks bare.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `dotnet-aspnet-core-security` based solely on surface keywords (`FromSqlInterpolated`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `dotnet-aspnet-core-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: dotnet-aspnet-core-security
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-89, CWE-862`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `dotnet-aspnet-core-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, CWE-862`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
