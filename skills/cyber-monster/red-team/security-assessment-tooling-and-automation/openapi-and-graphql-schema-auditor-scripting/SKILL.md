---
name: openapi-and-graphql-schema-auditor-scripting
description: "Develops automated OpenAPI v3 and GraphQL SDL schema security auditors: undocumented endpoint diffing, missing securitySchemes detection, object-ID parameter inventory for BOLA review, and query-depth/cost limit verification. Use when building API specification security linters or authz test harnesses."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["openapi security linter", "swagger auditor script", "graphql schema checker", "api spec diffing"]
cwe: [CWE-285]
owasp: [API01:2023, API09:2023]
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Openapi and Graphql Schema Auditor Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Auditing an API from its own machine-readable description: for OpenAPI, resolving `paths`, `security`, `securitySchemes`, and per-operation overrides to find operations with no auth requirement and parameters with no schema constraints; for GraphQL, fetching the schema by introspection and checking for unbounded list fields, missing depth or complexity limits, and mutations reachable without an auth directive.

- **Operation-level security overrides global security.** An empty `security: []` on one operation removes the global requirement; that is the unit to audit, not the document.
- **Absent constraints are the finding.** A parameter without `maxLength` or a list field without pagination arguments is where unbounded input becomes a resource problem.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the document is OpenAPI 3.2 **THEN** account for `additionalOperations` and `query:`, which older auditors do not enumerate and therefore miss operations.
2. **IF** introspection is disabled **THEN** fall back to schema extraction from a client bundle or a captured query set, and state that coverage is partial.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a resolvable schema document, the base URL it describes, and the authentication model — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python with `openapi-spec-validator` for document validity, `graphql-core` `build_client_schema` for introspection results, OpenAPI 3.2-aware field enumeration
- **Mandatory Self-Validation Command:** `python -c "import openapi_spec_validator, graphql; print('ok')"`

1. Confirm the target surface: fetch the document or introspection result, validate it, and record its version and hash.
2. Choose the branch: unauthenticated operation inventory, parameter-constraint audit, or GraphQL depth and complexity audit.
3. Define the differential: send one request to an operation with credentials and one without; the differential is a 2xx without credentials for an operation the document says is protected, or vice versa.
4. Name the stop condition: one request per operation, with state-changing methods excluded from probing and audited statically instead.
5. Prove it: pair each finding with the operation id, the security requirement in force, and the observed status, so the claim is checkable from the document and one request.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `paths[path][method].security == []` | Explicit empty security on an operation removes the global requirement; the highest-yield finding in an OpenAPI audit. |
| `components.securitySchemes[scheme].type` | Distinguishes apiKey, http, oauth2, and openIdConnect, which decides what a missing credential even means. |
| `build_client_schema(introspection_result)` | Turns a GraphQL introspection payload into a typed schema for field-level walking. |
| `Field.args for limit, first, after` | Absent pagination arguments on a list field are the resource-exhaustion surface. |

## Worked Contrast

**Reading Only the Global Security Block:**

```python
import yaml

spec = yaml.safe_load(open("openapi.yaml"))
print("auth required:", bool(spec.get("security")))  # BUG: ignores per-operation overrides
```

**Per-Operation Security Resolution:**

```python
import yaml

spec = yaml.safe_load(open("openapi.yaml"))
global_sec = spec.get("security", [])
exposed = []
for path, item in spec.get("paths", {}).items():
    for method, op in item.items():
        if method not in {"get", "put", "post", "delete", "patch", "head", "options", "trace", "query"}:
            continue
        sec = op["security"] if "security" in op else global_sec
        if not sec:
            exposed.append((method.upper(), path, op.get("operationId")))
print(len(exposed), exposed[:5])
```

**Why this matters:** A document with a global `security` block reads as fully authenticated, while a single operation carrying `security: []` is public. Resolving the effective requirement per operation is the only way the audit's answer matches what the server enforces, because the runtime applies the operation's own block when present.

## When It Is NOT This Issue

- **Document not matching the deployment.** A published spec can lag the running service; confirm the operation exists before reporting it as exposed.
- **Introspection disabled read as no schema.** Disabled introspection is a hardening measure; the schema may still be inferable from client traffic.
- **Empty security on a health endpoint.** Deliberate public endpoints are not findings; require the operation to expose data or state.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `securitySchemes` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `openapi-and-graphql-schema-auditor-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: openapi-and-graphql-schema-auditor-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `securitySchemes`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile openapi_and_graphql_schema.py; python openapi_and_graphql_schema.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`async-http-and-dns-audit-scripting`](../async-http-and-dns-audit-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `openapi-and-graphql-schema-auditor-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-285`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
