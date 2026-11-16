# Detection Queries and Telemetry Artifacts

> Sub-skill: [`java-spring-security-architecture`](SKILL.md) | Family: **Application Security**

Spring Security review checks. Each row is answerable from the configuration classes and the runtime version.

## Chain Ordering

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Matcher sequence | `requestMatchers` lines in registration order | No permissive rule before a restrictive one |
| Chain scoping | `securityMatcher` on each `SecurityFilterChain` | Chains are disjoint |
| Permit list | `permitAll` paths | Each maps to a public resource or a health probe |

## Method Security

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Enablement | `@EnableMethodSecurity` presence | Enabled where `@PreAuthorize` is used |
| Coverage | controllers and services without an annotation | Each has a chain rule covering it or an explicit annotation |
| Proxy gaps | self-invocation of annotated methods | Zero on security-relevant methods |

## Deserialisation and Actuator

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Polymorphic typing | `activateDefaultTyping`, `@JsonTypeInfo`, `enableDefaultTyping` | Allowlist validator or absent |
| Actuator exposure | `management.endpoints.web.exposure.include` | Named endpoints only, on a management port |
| Boot version | resolved Spring Boot version | At or above a release carrying the 2026 fixes |

## Telemetry Prerequisites

- The `SecurityFilterChain` bean source, since the chain is code rather than configuration.
- The dependency tree for Jackson and Spring Boot, because both are version-gated.
- Two authenticated users and an unauthenticated client for the probes.

## Deployment Gates

- Chain order is reviewed on every change to a security configuration class, not only at architecture review.
- Boot patch level is checked against the current advisories at each release.
