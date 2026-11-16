# Application Security

> Tree: `blue-team/application-security` | **25 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`secure-code-review`](secure-code-review/SKILL.md) | **flagship** | Reviews source code for security defects: data flow tracing from source to sink, authentication and authorization checks, crypto misuse and injec |
| [`ai-and-llm-application-defense`](ai-and-llm-application-defense/SKILL.md) | **core** | Defends LLM applications: prompt injection mitigations, output handling, tool scoping and monitoring for abuse |
| [`api-security-review`](api-security-review/SKILL.md) | **core** | Reviews API security: authentication and authorization design, object-level access, rate limiting, schema validation and documentation exposure |
| [`authentication-and-session-design-review`](authentication-and-session-design-review/SKILL.md) | **core** | Reviews authentication and session design: credential handling, MFA design, session lifetime and token storage decisions |
| [`cryptography-design-review`](cryptography-design-review/SKILL.md) | **core** | Reviews cryptographic design decisions: algorithm and mode selection, key lifecycle, random sources and protocol construction |
| [`dependency-and-package-risk-review`](dependency-and-package-risk-review/SKILL.md) | **core** | Assesses third-party dependency risk: provenance verification, version pinning, transitive risk and response to advisories |
| [`django-security-patterns`](django-security-patterns/SKILL.md) | **core** | Audits and hardens Django and Django REST Framework (DRF) applications: `QuerySet.extra()`/`RawSQL` pitfalls, DRF `has_object_permission` gotchas |
| [`dotnet-aspnet-core-security`](dotnet-aspnet-core-security/SKILL.md) | **core** | Reviews and hardens C# / ASP.NET Core applications: `[Authorize]` + `IAuthorizationService` resource-based authz, `[Bind]`/DTO overposting defens |
| [`express-and-fastify-security`](express-and-fastify-security/SKILL.md) | **core** | Audits and hardens Node.js Express and Fastify services: middleware ordering bypasses, JSON-schema body validation (blocking prototype pollution |
| [`flask-and-fastapi-security`](flask-and-fastapi-security/SKILL.md) | **core** | Reviews and hardens Python Flask and FastAPI applications (grounded in securecode-web verified pairs): `Depends()` per-route object-ownership che |
| [`go-net-http-and-gin-security`](go-net-http-and-gin-security/SKILL.md) | **core** | Reviews and hardens Go `net/http`, Gin, Echo, and Chi services: `http.Server` ReadHeaderTimeout/MaxBytesReader Slowloris & OOM defenses, `html/te |
| [`java-spring-security-architecture`](java-spring-security-architecture/SKILL.md) | **core** | Reviews and hardens Java Spring Boot / Spring Security 6 applications: `SecurityFilterChain` matcher ordering (`requestMatchers` specificity), `@ |
| [`react-nextjs-and-spa-security-architecture`](react-nextjs-and-spa-security-architecture/SKILL.md) | **core** | Audits React, Next.js (App Router & Server Actions), and Vue/Angular SPAs: `'use server'` action authentication & Zod input validation, Server-Co |
| [`secrets-management-and-key-custody`](secrets-management-and-key-custody/SKILL.md) | **core** | Manages secrets and keys: secret stores, rotation, scoping and custody models including HSM and KMS usage |
| [`secure-design-patterns`](secure-design-patterns/SKILL.md) | **core** | Applies secure design patterns: authentication and authorization architecture, input handling boundaries, secret management and fail-safe default |
| [`secure-sdlc-and-security-requirements`](secure-sdlc-and-security-requirements/SKILL.md) | **core** | Embeds security in the SDLC: security requirements, design gates, code review criteria and release criteria |
| [`security-testing-in-ci-cd`](security-testing-in-ci-cd/SKILL.md) | **core** | Adds security testing to CI/CD: SAST, dependency scanning, secret scanning, DAST placement and build gate policy |
| [`threat-modeling`](threat-modeling/SKILL.md) | **core** | Produces threat models: system decomposition, trust boundaries, STRIDE or attack-tree analysis and prioritized mitigations |
| [`logging-and-monitoring-requirements`](logging-and-monitoring-requirements/SKILL.md) | **leaf** | Defines what an application must log for security: authentication events, authorization decisions, sensitive operations and log integrity |
| [`ruby-on-rails-security`](ruby-on-rails-security/SKILL.md) | **leaf** | Audits and hardens Ruby on Rails applications: Strong Parameters (`params.expect`/`permit`), `ActiveRecord` SQL fragments (`order`/`pluck`/`where |
| [`secure-code-review-access-control-review`](secure-code-review-access-control-review/SKILL.md) | **leaf** | Access control review |
| [`secure-code-review-injection-and-data-flow`](secure-code-review-injection-and-data-flow/SKILL.md) | **leaf** | Injection and data flow review |
| [`secure-code-review-language-specific-review`](secure-code-review-language-specific-review/SKILL.md) | **leaf** | Language specific secure review |
| [`threat-modeling-attack-tree-and-misuse-cases`](threat-modeling-attack-tree-and-misuse-cases/SKILL.md) | **leaf** | Attack trees and misuse cases |
| [`threat-modeling-stride-analysis`](threat-modeling-stride-analysis/SKILL.md) | **leaf** | STRIDE analysis |
