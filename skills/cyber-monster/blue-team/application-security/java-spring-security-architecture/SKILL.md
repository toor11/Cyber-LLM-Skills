---
name: java-spring-security-architecture
description: "Reviews and hardens Java Spring Boot / Spring Security 6 applications: `SecurityFilterChain` matcher ordering (`requestMatchers` specificity), `@PreAuthorize` method security, Jackson polymorphic `@JsonTypeInfo` deserialization safety, Spring Data JPA `@Query` SpEL traps, and Actuator endpoint lockdown. Use when auditing Java/Spring code."
family: application-security
tier: core
triggers: ["spring security 6 review", "securityfilterchain order", "preauthorize spel", "jackson jsontypeinfo"]
cwe: [CWE-862, CWE-502]
owasp: [A01:2025]
attack: []
capec: []
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
corpus_sparse: true
---

# Java Spring Security Architecture - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`insecure-deserialization`](../../../red-team/web-and-application/insecure-deserialization/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Spring Security is a filter chain, so every authorisation outcome is decided by matcher order and by which annotations the proxy actually intercepts. `requestMatchers` are evaluated top-down and the first match wins, so a `permitAll()` catch-all registered before a specific rule opens the route it was meant to protect. Above that, method security only applies where a proxy exists, and deserialisation settings decide whether a request body can instantiate arbitrary classes. The review reads the chain, then the annotations, then the runtime patch level.

- **CWE-862 / CWE-502 / CWE-284:** missing authorisation from chain ordering, polymorphic deserialisation, and exposed management endpoints.
- Spring Boot's 2026 advisories include CVE-2026-22731 and CVE-2026-22733 (Actuator authentication bypass on health-group and Cloud Foundry paths), CVE-2026-40976 (default web security ineffective when Actuator auto-configuration is present without spring-boot-health) and CVE-2026-40975 (`${random.value}` unsuitable for secrets); 4.0.8 and 3.5.16 carry the public fixes.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** Actuator is on the classpath **THEN** check both the management port binding and the chain rule for `/actuator/**`, and check the Boot version against the 2026 Actuator advisories.
2. **IF** the app deserialises JSON into a polymorphic hierarchy **THEN** require an explicit `PolymorphicTypeValidator` allowlist or a non-polymorphic DTO.
3. **IF** the finding is a role model rather than a matcher **THEN** route to `privileged-access-management`; this skill checks enforcement, not entitlement design.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the `SecurityFilterChain` bean as an ordered list.** For each `requestMatchers` line, record the pattern, the access rule, and its position. Any `permitAll` or `anonymous` that precedes a narrower rule is the finding, independent of what the narrower rule says.
2. **Confirm method security is proxied where it is used.** `@EnableMethodSecurity` plus `@PreAuthorize` covers beans reached through a proxy; self-invocation inside the same bean and `new`-constructed helpers bypass it.
3. **Choose the branch on the deserialisation surface.** Jackson with default typing takes the validator-allowlist branch; Java serialization takes the removal branch; anything else takes the DTO branch.
4. **Define the baseline-vs-probe differential.** Baseline: an authenticated user calls their own resource. Probe: the same call for another user's id, then an unauthenticated call to an actuator path. A correct chain returns 403/404 and 401 respectively, and never a body.
5. **State the stop condition and the proof.** Stop when the chain has no permissive rule ahead of a restrictive one, actuator paths are closed, and the probes are replayed; proof is the chain source plus the probe responses.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `requestMatchers("/**").permitAll()` placed before specific rules | Proves the specific rules never execute; the first match wins on Spring Security 6. |
| `securityMatcher` absent on a second `SecurityFilterChain` | Proves the two chains overlap and the more permissive one can win for a given request. |
| Jackson `activateDefaultTyping` or `@JsonTypeInfo` with `Id.NAME` on request bodies | Proves polymorphic instantiation from input on the JVM; gadget availability depends on the classpath. |
| `management.endpoints.web.exposure.include=*` on the application port | Proves Actuator is reachable on the same listener as the app; the 2026 bypass advisories make this worse on unpatched versions. |

## Worked Contrast

**Vulnerable Spring Security 6 Chain (Permissive Catch-All First + Polymorphic Jackson):**

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/**").permitAll()           // BUG 1: Broad matcher shadows /api/admin/**!
        .requestMatchers("/api/admin/**").hasRole("ADMIN")
    ).build();
}
// BUG 2: mapper.enableDefaultTyping() allows arbitrary gadget deserialization (CWE-502)!
```

**Hardened Specific-First Matcher Ordering + `@PreAuthorize` + Locked Actuator:**

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/healthz").permitAll()
        .requestMatchers("/actuator/**").hasRole("OPS_INTERNAL")
        .requestMatchers("/api/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated()                 // Default-authenticated fallback last
    ).build();
}
// Pair with @EnableMethodSecurity and @PreAuthorize("@authz.ownsAccount(#id, authentication)")
```

**Why this matters:** Spring `SecurityFilterChain` evaluates `requestMatchers` top-down (specific routes MUST precede catch-alls), Actuator endpoints must be locked down, and Jackson default typing must use `BasicPolymorphicTypeValidator` allowlists.

## When It Is NOT This Issue

- **`permitAll` on a path that only serves static assets or a health probe.** Public by design; check the path's content before filing.
- **`@PreAuthorize` on a method called through its own bean.** Self-invocation does bypass the proxy, but only if the caller is already inside an authorised method; check the entry point.
- **Actuator on a separate management port bound to localhost.** The exposure is contained; the finding would be the network policy, not the endpoint list.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `java-spring-security-architecture` based solely on surface keywords (`SecurityFilterChain`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `java-spring-security-architecture` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: java-spring-security-architecture
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-862, CWE-502`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`insecure-deserialization`](../../../red-team/web-and-application/insecure-deserialization/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `java-spring-security-architecture` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-862, CWE-502`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
