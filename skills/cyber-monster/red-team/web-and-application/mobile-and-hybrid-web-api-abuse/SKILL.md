---
name: mobile-and-hybrid-web-api-abuse
description: "Tests the web APIs behind mobile and hybrid apps where client-side controls are absent: unauthenticated endpoints, hardcoded keys, logic implemented only in the app, and debug routes. Use when a mobile app's backend is in scope."
family: web-and-application
tier: leaf
triggers: ["mobile api testing", "hybrid app api", "backend api mobile", "app api abuse"]
cwe: [CWE-602]
owasp: [API01:2023]
attack: []
capec: [CAPEC-116]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Mobile and Hybrid Web API Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A mobile or hybrid app and its backend split responsibility, and the vulnerability is the backend trusting enforcement the app was supposed to perform. The API is the real attack surface: once a tester replays its requests outside the app, any check that lived in the client (hidden menus, disabled buttons, field validation, pricing, feature gating) is gone, and endpoints that assumed only the app calls them become reachable directly. Common shapes are unauthenticated or weakly authenticated endpoints, API keys hardcoded in the app bundle, debug or versioned routes left exposed, and object access that relied on the app never requesting another user's id. The gain is data or actions the UI never offered. Confirmation is a direct API call, with the app's own token but without the app, that returns data or performs an action the client would have blocked.

- **Precondition chain:** A server endpoint delegates a security decision to the mobile or hybrid client, the request can be reconstructed and replayed outside the app, and the server performs the sensitive action without re-checking authorisation, keys, or input server-side.
- **Readable differential:** The same operation performed through the app versus the same request replayed directly with client-side checks removed; a finding exists when the direct call still succeeds, and it closes once the server re-enforces the check independent of the client.
- **Empirical grounding:** CWE-602 (Client-Side Enforcement of Server-Side Security); OWASP API Security Top 10:2023 places broken object-level authorisation at API1 (BOLA) and broken function-level authorisation at API5 (BFLA). SOURCES.md lists no product-specific CVE for this slug, so it stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a request the app sends succeeds when replayed directly without the app's client-side checks **THEN** this is the primary case, so establish the direct-replay differential first
2. **IF** access to another user's object turns on an id in the request the app never varies **THEN** route the authorisation question to [`authorization-and-idor`](../authorization-and-idor/SKILL.md) (1 hop)
3. **IF** an admin or privileged function is reachable because only the UI hid it **THEN** model it as function-level access and read [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) (1 hop)
4. **IF** an API key, secret, or signing key is embedded in the app bundle **THEN** treat the key as exposed and read [`api-key-and-secret-exposure`](../api-key-and-secret-exposure/SKILL.md) (1 hop)
5. **IF** a debug, staging, or v1/internal route answers in production **THEN** enumerate versioned and debug paths and confirm they lack the production guards
6. **IF** the backend is a GraphQL or gRPC endpoint behind the app **THEN** pivot to [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md) for the transport-specific checks
7. **IF** certificate pinning is the only thing stopping request capture **THEN** note pinning is a client control, not a server authorisation control, and test the API on its own merits
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every replayed request is re-authorised and re-validated server-side with no client-only gate **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Replay reaches another principal's object via an id | [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) | Invariant is per-object ownership (BOLA), an access-control decision |
| A privileged function is exposed only because the client hid it | [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) | Invariant is function-level authorisation (BFLA), not client UI gating |
| A key or token is shipped inside the app binary | [`api-key-and-secret-exposure`](../api-key-and-secret-exposure/SKILL.md) | Invariant is secret custody, not request authorisation |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory the API surface the app uses.** Capture traffic through an intercepting proxy and list every host, path, method, and auth header, then pull strings and configs from the app bundle for keys and hidden base URLs, because the backend, not the app, is the scope.
2. **Classify each endpoint's intended gate.** Mark whether authorisation, input validation, pricing, or feature gating is enforced server-side or only implied by the client flow; the implied ones are candidates.
3. **Record an in-app baseline.** Perform the operation the way the app does and capture the exact authenticated request and its authoritative result (returned object, status, side effect).
4. **Replay the request outside the app with client checks removed.** Resend with the same token but altered ids, removed client validation, or a debug or versioned path, changing one variable at a time so the result is attributable.
5. **Separate the failure classes.** Object-level (another user's id works), function-level (an admin route works), secret exposure (a bundled key authenticates), and exposed debug routes are four distinct findings; test and report them individually.
6. **Stop condition.** Halt when a direct call either (a) returns data or performs an action the client would block and reverts when the server re-checks, (b) is refused identically to the in-app path, or (c) would read or mutate a real user's records. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a server response to a request issued without the app that crosses an authorisation or validation boundary, tied to one changed variable, plus the server code or route config that trusts the client. A request that only works because it reuses the tester's own token within the tester's own scope is not proof.
8. **Close with the structural fix.** Move every decision server-side: authorise each object and function against the caller's identity, validate inputs on the server, stop shipping privileged keys in the client, and gate or remove debug and versioned routes, then replay the direct call to confirm it is now refused.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An endpoint that returns another user's record when the id in the path is changed | Proves broken object-level authorisation (BOLA, API1) on the mobile backend, independent of the app UI |
| An admin or bulk function that answers a direct call but is hidden in the app | Proves broken function-level authorisation (BFLA, API5) relying on client-side gating |
| A static API key or signing secret extracted from the app bundle | Proves secret custody failure where the client is trusted to hold a credential, usable from any HTTP client |
| A `/debug`, `/internal`, or `/v1` route reachable in production | Proves a forgotten route lacking the production authorisation middleware |
| A price, role, or entitlement field accepted from the request body | Proves the server trusts a value the app was expected to fix, a CWE-602 client-enforcement defect |
| A request that succeeds with the app token but fails all client-side validation | Proves the validation lived only in the client and the server never re-checked |
| Certificate pinning present but no server-side authorisation | Proves a client hardening control standing in for an absent server control |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.get("/api/v1/orders/<order_id>")
def get_order(order_id):
    # Trusts that the mobile client only ever requests the user's own orders
    return jsonify(db.orders.find_one({"_id": order_id}))
```

**Hardened pattern:**

```python
@app.get("/api/v1/orders/<order_id>")
def get_order(order_id):
    caller = require_auth(request)  # server-side identity, not a client claim
    order = db.orders.find_one({"_id": order_id})
    if order is None or order["user_id"] != caller.id:
        abort(404)  # object-level authorisation on every request
    return jsonify(order)
```

**Why this matters:** The hardened version derives the caller identity on the server and authorises the object against it on every request, so replaying the call with another user's order_id outside the app returns 404 instead of the record. Server-side object-level authorisation is the structural control; certificate pinning or hiding the route in the app does not replace it.

## When It Is NOT This Issue

- **Self-scoped replay:** a direct API call that only returns the tester's own data proves the API works without the app, not that authorisation is broken; vary the id to a resource you should not reach.
- **Public-by-design endpoint:** a catalogue or config route meant to be unauthenticated is not a finding merely because it answers outside the app.
- **Key with no privilege:** a bundled API key that only identifies the app and grants no data access is low impact; confirm what the key actually authorises before reporting.
- **Pinning bypass alone:** defeating certificate pinning is a client exercise; without a server-side authorisation or validation gap there is no backend finding.
- **Staging host in a test build:** a debug base URL in a non-production build is a test artefact unless the production app or production API exposes it.
- **Rate-limited abuse:** an endpoint reachable directly but throttled and authorised per request is working as designed, not a BOLA or BFLA case.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `mobile-and-hybrid-web-api-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `mobile-and-hybrid-web-api-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: mobile-and-hybrid-web-api-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-602 | Mapping: API01:2023]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `mobile-and-hybrid-web-api-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-602`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 5 |
| Top sources | hackerone_disclosed_reports (9), bugbounty-hunter-v1 (3), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
