---
name: rest-and-grpc-api-security
description: Tests REST and gRPC APIs for broken object properties, mass assignment, excessive data exposure, HTTP verb and method override abuse, hidden fields, content-type confusion, and protobuf-level injection. Use when a service exposes JSON REST or gRPC endpoints.
family: web-and-application
tier: core
triggers: ["api security", "rest api", "grpc", "api testing", "bola", "excessive data exposure", "verb tampering", "route confusion"]
cwe: [CWE-20]
owasp: [API01:2023, API03:2023]
attack: []
capec: [CAPEC-122]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Rest and Grpc API Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

REST and gRPC services expose object- and function-level operations whose authorization and field shaping must be enforced per request on the server. The common defects are object-level access where an object id in the path or body is honored without an ownership check, function-level access where a privileged method is reachable by a lower role, mass assignment where the deserializer binds client fields such as role or isAdmin the client should not set, excessive data exposure where the serializer returns full objects and the client filters, and interface confusion through HTTP verb or method-override, content-type coercion, or gRPC reflection that lists methods. The security decision is server-side authorization and schema binding at the endpoint, and the attacker gains other users' objects, privileged functions, or hidden fields. A batch router adds a second boundary: each subrequest looks permission-checked, but the check can be the callback of a different route than the handler that runs. WordPress `serve_batch_request_v1` before 6.9.5 and 7.0.2 is the verified instance (CVE-2026-63030): a parse error was appended to the validation list and not to the match list, so the indexes diverged. The fix appends the error to both lists. Confirm that in source. Do not send a batch built to shift the indexes.

- **Precondition chain:** an endpoint trusts a client-supplied object id, field set, verb, content type, or batch index; the server omits a per-object or per-function authorization check, binds unlisted fields, or dispatches item i with handler j; the response serializer returns more than the caller is entitled to; and the interface lets the caller reach the operation.
- **Readable differential:** call the endpoint as the owner with the owner's id versus as a second account substituting the first account's id, or add an unlisted field; a finding exists when the cross-account id returns the victim's object or the extra field is bound, and it closes once the server enforces the ownership or field allowlist.
- **Empirical grounding:** This maps to CWE-20 with the OWASP API Security Top 10:2023, where broken object-level authorization is API1:2023 and broken function-level authorization is API5:2023; the GraphQLer context-aware testing paper demonstrates dependency-graph chaining of API operations that informs systematic REST and gRPC enumeration.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an object id in the path or body is honored without an ownership check **THEN** switch to [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) (1 hop)
2. **IF** a privileged function is reachable by a lower-privileged role **THEN** switch to [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) (1 hop)
3. **IF** the body binds fields the client should not set, such as role or price **THEN** switch to [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) (1 hop)
4. **IF** the endpoint honors X-HTTP-Method-Override or an unexpected verb **THEN** switch to [`http-method-and-verb-attacks`](../http-method-and-verb-attacks/SKILL.md) (1 hop)
5. **IF** the service is GraphQL rather than REST or gRPC **THEN** switch to [`graphql-security`](../graphql-security/SKILL.md) (1 hop)
6. **IF** content-type coercion changes how the body is parsed **THEN** test JSON versus form versus protobuf parsing of the same field set
7. **IF** gRPC server reflection lists methods to an unauthenticated caller **THEN** enumerate services via reflection and check per-method authorization
8. **IF** a batch endpoint validates subrequests in one list and executes them from another **THEN** patch-diff the index alignment and stop before a malformed item; the WordPress instance is [`cms-and-framework-exploitation-wordpress`](../cms-and-framework-exploitation-wordpress/SKILL.md)
9. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
10. **IF** every object is ownership-checked, functions are role-gated, batch item i uses handler i, and the serializer returns a field allowlist **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Cross-tenant object ids resolve across organizations | [`authorization-and-idor-tenant-isolation`](../authorization-and-idor-tenant-isolation/SKILL.md) | The invariant is the tenant boundary, not just per-user ownership |
| A writable field controls a single property like status or price | [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) | Property-level write authorization, distinct from object access |
| An exposed OpenAPI or gRPC reflection document reveals hidden methods | [`openapi-and-swagger-exposure`](../openapi-and-swagger-exposure/SKILL.md) | Information exposure of the interface, a different invariant |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Inventory endpoints and methods from the OpenAPI document, gRPC reflection, or proxy history, and classify each as object-read, object-write, function, or collection.
2. Establish two accounts and capture an owner baseline request for a chosen object.
3. Apply the cross-account differential by swapping the object id, and separately the mass-assignment differential by adding an unlisted field, and the verb and content-type differentials.
4. Choose the branch from which differential diverges: the victim object returned, an extra field bound, or a privileged method reached.
5. Confirm server-side enforcement by reading the handler, since a hidden field in the client proves nothing about the server check.
6. Hold the request shape constant across the differential so the only variable is the id, field, verb, or content type.
7. **Stop condition.** Stop when (a) a cross-account id returns another user's object, an unlisted field binds, or a privileged method is reached, (b) every such attempt is denied, or (c) proceeding would read a real user's data beyond what proof requires; (a) is confirmation, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a second account retrieving the first account's object by id, or an unlisted field persisting server-side, with the exact missing check named, reverting once enforced. Close with a per-object ownership check, a per-function role gate, an explicit input field allowlist, an output DTO allowlist, and gRPC reflection disabled in production, then replay the differential.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A sequential or UUID object id in the path accepted for any caller | Proves missing object-level authorization (API1:2023) on REST or gRPC |
| A role, isAdmin, or price field bound from the request body | Proves mass assignment at the deserializer |
| A response carrying fields the client interface never shows | Proves excessive data exposure at the serializer |
| An administrative RPC method reachable without role metadata | Proves broken function-level authorization (API5:2023) on the service |
| X-HTTP-Method-Override: DELETE honored on a POST route | Proves verb and method-override confusion at the API tier |
| gRPC server reflection answering an unauthenticated caller | Proves method enumeration exposure through the reflection service |
| A protobuf field parsed from a JSON transcoder path | Proves content-type coercion changes how the body is bound |
| Batch item i validated by one route's callback and executed by another route's handler | Proves route confusion: the two lists that should stay aligned have diverged |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, user=Depends(current_user)):
    # Object id trusted directly: any authenticated user reads any order.
    return db.query(Order).get(order_id)   # returns the full row, all fields

@app.patch("/api/orders/{order_id}")
def update_order(order_id: int, body: dict, user=Depends(current_user)):
    db.query(Order).filter_by(id=order_id).update(body)  # mass assignment
    return {"ok": True}
```

**Hardened pattern:**

```python
class OrderOut(BaseModel):
    id: int
    item: str
    total: float            # explicit output allowlist, no internal fields

@app.get("/api/orders/{order_id}", response_model=OrderOut)
def get_order(order_id: int, user=Depends(current_user)):
    order = db.query(Order).filter_by(id=order_id, owner_id=user.id).first()
    if order is None:
        raise HTTPException(status_code=404)
    return order

@app.patch("/api/orders/{order_id}")
def update_order(order_id: int, body: OrderUpdate, user=Depends(current_user)):
    order = db.query(Order).filter_by(id=order_id, owner_id=user.id).first()
    if order is None:
        raise HTTPException(status_code=404)
    order.item = body.item           # only allowlisted fields assigned
    db.commit()
    return {"ok": True}
```

**Why this matters:** The defect trusts the path id and binds the whole body, so any user reads or edits any order and can set internal fields. The fix scopes every query by owner_id, returns a response-model allowlist that omits internal columns, and binds only declared fields, enforcing object-level authorization and blocking mass assignment and excessive data exposure.

## When It Is NOT This Issue

- **Owner-scoped query:** an object id always filtered by owner or tenant in the query is not a BOLA finding.
- **Role-gated function:** a method guarded by a verified role claim is not broken function-level authorization.
- **DTO allowlist serializer:** an explicit output model that omits internal fields is not excessive data exposure.
- **Strict input schema:** a schema that rejects unknown keys blocks mass assignment regardless of the handler.
- **Reflection disabled and methods authorized:** gRPC with reflection off in production and per-method checks is not exposed.
- **Field public by design:** a value documented as public is not a disclosure even if it is in the response.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `rest-and-grpc-api-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `rest-and-grpc-api-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: rest-and-grpc-api-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: API01:2023, API03:2023]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `rest-and-grpc-api-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 60 |
| Distinct dataset sources | 12 |
| Top sources | OffsecCyber (27), CYBER_CPT/oxdf (12), hackerone_disclosed_reports (9), cyber-security/security-code (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 1 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
