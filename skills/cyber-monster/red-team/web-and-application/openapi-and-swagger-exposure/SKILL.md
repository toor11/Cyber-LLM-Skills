---
name: openapi-and-swagger-exposure
description: Exploits exposed API documentation and schemas to enumerate hidden endpoints, parameters and internal hosts, including swagger-ui, OpenAPI JSON and GraphQL SDL discovery. Use when an API may publish its own specification.
family: web-and-application
tier: leaf
triggers: ["swagger exposure", "openapi discovery", "api documentation leak", "swagger ui"]
cwe: [CWE-200]
owasp: [API09:2023]
attack: []
capec: [CAPEC-116]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Openapi and Swagger Exposure - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

The service publishes its own machine-readable contract, an OpenAPI or Swagger document and often an interactive UI, at a predictable path with no authentication, so an unauthorized actor reads the full inventory of routes, parameters, auth schemes, and sometimes internal hostnames. The security decision is whether the specification endpoint and its UI should be reachable in the current environment and by the current principal. Nothing is injected; the disclosure is the vulnerability, and its value is reconnaissance that turns a blind API into a mapped one, surfacing undocumented, deprecated, or admin operations that other controls assumed were hidden. The attacker gains a precise target list that accelerates BOLA, BFLA, and parameter-level testing. Confirmation is that the spec or UI returns to an anonymous request and enumerates operations the public product never advertises.

- **Precondition chain:** A spec or UI endpoint such as /v3/api-docs or /swagger-ui is served, it is reachable without authentication in a sensitive environment, and it enumerates operations or hosts beyond what the public product exposes.
- **Readable differential:** The spec or UI requested anonymously versus the same path with an operator session; a finding exists when the anonymous request returns the full inventory, and it is closed when the endpoint is disabled or gated.
- **Empirical grounding:** CWE-200 Exposure of Sensitive Information; OWASP API Security Top 10:2023 classes this under API9 Improper Inventory Management, with enumerated endpoints frequently leading to API1 BOLA. SOURCES.md has no advisory specific to this slug, so grounding stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a common spec path such as /v3/api-docs or /openapi.json returns JSON anonymously **THEN** treat the disclosure as the primary finding and enumerate operations from the document
2. **IF** an interactive /swagger-ui is reachable without authentication **THEN** confirm it renders operations and whether it can issue live requests
3. **IF** the exposed schema is GraphQL SDL reachable through introspection **THEN** route to [`graphql-security-introspection-and-schema`](../graphql-security-introspection-and-schema/SKILL.md)
4. **IF** the spec reveals object-identifier parameters with no per-object check **THEN** route to [`authorization-and-idor`](../authorization-and-idor/SKILL.md) to test object-level authorization
5. **IF** the document lists admin or internal operations missing function-level checks **THEN** route to [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md) for broken function-level authorization
6. **IF** the spec leaks internal hostnames consumed by a server-side fetcher **THEN** consider [`ssrf`](../ssrf/SKILL.md) for the reachability those hosts imply
7. **IF** the swagger-ui config URL itself is parameter-controlled **THEN** test for spec-URL injection that loads a foreign definition into the UI
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the spec is intentionally public for a documented partner API and exposes no non-public routes **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Enumerated operations expose object identifiers with no per-object check | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | The spec reveals endpoints but the finding is object-level authorization |
| The exposed schema is GraphQL SDL reachable through introspection | [`graphql-security-introspection-and-schema`](../graphql-security-introspection-and-schema/SKILL.md) | The invariant is introspection exposure on a GraphQL endpoint |
| The documented API lacks function-level authorization on admin routes | [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md) | The finding is broken function-level authorization, not disclosure |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the specification surface.** Request the common spec and UI paths (/v3/api-docs, /openapi.json, /swagger.json, /swagger-ui, /swagger-resources) and record which return a document and which require a session. The reachable set is the surface.
2. **Classify the environment and principal.** Determine whether the responding host is production, staging, or internal, and whether the request was anonymous. A public developer portal is a different finding from an exposed production schema.
3. **Record an anonymous versus authenticated baseline.** Fetch the same spec path with no credentials and with an operator session and compare what each returns. The gap is the disclosure.
4. **Read the document as an inventory, not a payload.** Extract operations, parameters, auth schemes, server URLs, and any deprecated or admin paths the public product never links. This is where the real value sits.
5. **Cross-check the inventory against reachable controls.** For each enumerated operation decide whether it enforces object-level and function-level authorization; the spec only tells you where to look, not whether a route is broken.
6. **Stop condition.** Halt when the finding is either (a) a sensitive-environment spec or UI returning the full inventory to an anonymous request, (b) an intentionally public contract exposing only documented routes, or (c) a point where confirming impact would require abusing an enumerated operation against real data. Case (a) confirms, (b) is a non-finding, (c) is out of scope for this slug.
7. **State what counts as proof.** Proof is the anonymous response body containing the OpenAPI or Swagger document with operations beyond the public product, plus the served path and the environment, not merely the presence of a /swagger-ui route that may require auth.
8. **Close with the structural fix and verify it.** Disable the spec and UI in production or gate them behind authentication and network restrictions, remove internal hosts from server lists, pin the UI version, and re-request the paths anonymously to confirm they no longer disclose the inventory.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An anonymous GET to /v3/api-docs returning a JSON document with `openapi` or `swagger` keys | Proves the machine-readable contract is world-readable on Spring, FastAPI, or similar frameworks |
| A /swagger-ui page that renders and can issue live requests without a session | Proves an interactive attack console is exposed, amplifying enumeration into direct calls |
| Server URLs in the document naming internal or staging hostnames | Proves inventory leakage of non-public infrastructure that aids pivoting and SSRF scoping |
| Operations marked deprecated or tagged internal present in the document | Proves shadow and zombie endpoints are advertised, the core of API9 inventory risk |
| A /swagger-resources or grouping endpoint listing multiple API definitions | Proves a multi-service catalogue is reachable, widening the mapped surface in one request |
| A swagger-ui `url` or `configUrl` parameter that loads an arbitrary spec | Proves a spec-URL injection sink that can render a foreign definition in the trusted UI |

## Worked Contrast

**Vulnerable pattern:**

```python
from fastapi import FastAPI

# Interactive docs and the machine-readable schema are world-readable in every environment
app = FastAPI(docs_url="/swagger-ui", openapi_url="/v3/api-docs")
```

**Hardened pattern:**

```python
import os
from fastapi import FastAPI, HTTPException

PROD = os.getenv("ENV") == "production"

def require_operator(token: str = ""):
    if PROD and token != os.getenv("DOCS_TOKEN"):
        raise HTTPException(status_code=404)

# Schema and UI disabled by default; exposed only behind an explicit operator check
app = FastAPI(docs_url=None, openapi_url=None)
```

**Why this matters:** The vulnerable app ships the schema and UI to everyone in all environments; the fix disables both by default and makes any exposure a deliberate, authenticated choice, so an anonymous production request can no longer read the inventory.

## When It Is NOT This Issue

- **Intentional public API contract:** a documented partner or developer API that publishes its spec by design and lists only public routes is expected, not a leak.
- **Spec requires authentication:** the /swagger-ui route exists but returns 401/403 or an empty document without a valid session.
- **Non-production sandbox clearly isolated:** a throwaway demo environment with no real data and no path to production is a low-value artefact.
- **Document lists only already-public endpoints:** a spec that mirrors the public product with no hidden, admin, or deprecated routes adds no reconnaissance value.
- **Internal-only network exposure:** the spec is reachable solely from a trusted management network that an external actor cannot reach.
- **Stale cached UI with no live schema:** a swagger-ui shell loads but the backing openapi_url returns 404, so no inventory is disclosed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `openapi-and-swagger-exposure` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `openapi-and-swagger-exposure` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: openapi-and-swagger-exposure
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: API09:2023]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `openapi-and-swagger-exposure` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (10), CYBER_CPT/go_exploitdb (2), hackerone_disclosed_reports (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
