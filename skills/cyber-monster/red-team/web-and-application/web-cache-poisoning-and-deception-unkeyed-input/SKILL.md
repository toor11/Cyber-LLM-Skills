---
name: web-cache-poisoning-and-deception-unkeyed-input
description: Cache poisoning through unkeyed input. Covers poisoning via unkeyed headers and parameters, fat GET, and response splitting into cache, then confirming with cache-buster discipline. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["cache poisoning unkeyed", "cache deception unkeyed", "cache poisoning header"]
cwe: [CWE-525]
owasp: [A05:2021]
attack: []
capec: [CAPEC-141]
related: [web-cache-poisoning-and-deception, web-cache-poisoning-and-deception-deception-and-path, web-cache-poisoning-and-deception-cdn-specific-behaviour, sql-injection]
parent: web-cache-poisoning-and-deception
corpus_sparse: true
---

# Web Cache Poisoning and Deception Unkeyed Input - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Poisoning through unkeyed input works when the origin reflects a request element into the response but the shared cache leaves that element out of the cache key. The attacker sends a request whose unkeyed header or parameter (for example `X-Forwarded-Host`, `X-Forwarded-Scheme`, a duplicated query parameter, or an oversized fat-GET body on a cacheable GET) makes the origin build a harmful response, and the cache stores it under a key that ordinary victim requests match. Because the poisoning input is not in the key, every later request to that URL, carrying no such header, is served the poisoned copy. The security decision is which request elements the cache includes in its key versus which the origin trusts when rendering, and the attacker gains mass delivery of an attacker-shaped response. Proof is a clean request, without the unkeyed input, receiving the poisoned content from cache.

- **Precondition chain:** A shared cache keys on a subset of the request, the origin reflects an unkeyed element into the response, and that element can carry a value harmful enough to matter (redirect host, script, cache directive) that victims' keyed requests will then receive.
- **Readable differential:** A request carrying the unkeyed input, with a keyed cache-buster, versus a clean request for the same keyed URL; a finding exists when the clean request returns the reflected value, and it closes once the element is added to the key or no longer reflected.
- **Empirical grounding:** CWE-525 and OWASP A05 anchor the class; the 2025 host and header confusion CVEs in SOURCES, CVE-2025-31137, CVE-2025-41235, CVE-2025-1736, CVE-2025-0752, and CVE-2025-0178, document unkeyed header inputs reaching reflected responses. This leaf is corpus-sparse, so it is anchored at the taxonomy and these header-confusion advisories.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the poisoning is not confirmed to come from an unkeyed input **THEN** start at parent class [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) (1 hop) first
2. **IF** the issue is a private page cached because of a suffix, not a reflected input **THEN** switch to [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) (1 hop)
3. **IF** the keying behaviour is specific to one CDN product **THEN** switch to [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](../web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) (1 hop)
4. **IF** the unkeyed input is a `Host` or forwarded-host header the origin trusts **THEN** read [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md)
5. **IF** the reflected value is a redirect target that becomes persistent in cache **THEN** pivot to [`open-redirect`](../open-redirect/SKILL.md)
6. **IF** the reflected value executes as script once cached **THEN** pivot to [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md)
7. **IF** the unkeyed input splits the response into a second cached entry **THEN** read [`crlf-and-header-injection`](../crlf-and-header-injection/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the reflected element is already part of the cache key or not reflected at all **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Unkeyed input is a trusted host header | [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) | Different invariant: host trust upstream of the cache key |
| Reflected value is a redirect persisted by the cache | [`open-redirect`](../open-redirect/SKILL.md) | Routes to redirect allowlisting; the cache only amplifies it |
| Response is split into a second entry via header injection | [`crlf-and-header-injection`](../crlf-and-header-injection/SKILL.md) | Routes to the CRLF invariant rather than the cache key |
| Need parent class methodology | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate request elements the origin reflects.** Walk headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-For`), duplicated and extra query parameters, and fat-GET body fields, noting which appear in the response body or headers.
2. **Determine the cache key for the target URL.** Establish which of those reflected elements the cache includes in its key, because only the reflected-and-unkeyed intersection is exploitable.
3. **Tag each probe with a keyed cache-buster.** Add a query token the cache keys on so every verification lands on a private entry and never poisons the shared production key.
4. **Record the cache-state baseline.** Capture `X-Cache` and `Age` on a clean request to the busted URL so a later hit is unambiguous.
5. **Inject a benign unique marker through the unkeyed element, then request clean.** Send the reflected header or parameter with a harmless marker plus the buster, confirm it is reflected and stored, then request the busted URL without the header and look for the marker.
6. **Stop condition.** Halt when the clean request either (a) returns the injected marker from a cache hit, (b) returns the normal response proving the element was keyed or not reflected, or (c) can only be shown by injecting a harmful value on a shared production key. Outcome (a) confirms unkeyed-input poisoning, (b) is a non-finding, (c) stays on a busted key with a benign marker in scope.
7. **State what counts as proof.** Proof is the benign marker, injected only through the unkeyed element, returned to a clean request that never sent it, with a cache-hit header on the busted URL. Seeing your own marker on your own header-carrying request is not proof the key is shared.
8. **Close with the structural fix and verify it.** Stop reflecting untrusted request elements into shared responses, add any response-affecting element to the cache key or a matching `Vary`, and set `no-store` where per-request variation is unavoidable, then replay the inject-then-clean sequence to confirm the marker no longer persists.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `X-Forwarded-Host` reflected into an absolute link but absent from the cache key | Proves classic unkeyed-header poisoning on stacks that trust forwarded headers |
| A duplicated query parameter reflected while only the first copy is keyed | Proves an unkeyed duplicate channel the cache ignores |
| A fat-GET body influencing a cached GET response | Proves the cache keyed on the URL alone while the origin read the body |
| The injected benign marker returned to a clean request on the same URL | Proves the poisoned entry is served to requests that never carried the input |
| `X-Cache: HIT` with `Age` advancing on the clean follow-up | Proves the reflected response was stored and shared |
| A missing `Vary` for the reflected header at the origin | Proves the origin failed to instruct the cache to key on the element |
| `X-Forwarded-Scheme` or `X-Forwarded-Port` altering generated URLs in the body | Proves scheme or port reflection that cache poisoning can pin for all users |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.route('/go')
def go():
    # Unkeyed scheme header reflected into a cached redirect
    scheme = request.headers.get('X-Forwarded-Scheme', 'https')
    target = f'{scheme}://{request.host}/dashboard'
    resp = redirect(target, code=302)
    resp.headers['Cache-Control'] = 'public, max-age=300'   # redirect cached for all
    return resp
```

**Hardened pattern:**

```python
@app.route('/go')
def go():
    # Scheme is fixed server-side, never taken from an untrusted header
    target = f'https://{request.host}/dashboard'
    resp = redirect(target, code=302)
    # Per-request redirects are not shared-cacheable
    resp.headers['Cache-Control'] = 'no-store'
    return resp
```

**Why this matters:** The defect is that an unkeyed forwarded-scheme header was reflected into a cached redirect, so one request could pin an attacker-chosen scheme for every visitor. The fix derives the scheme server-side and marks the redirect `no-store`, so no unkeyed input reaches a shared cache entry.

## When It Is NOT This Issue

- **Element is keyed:** a reflected header the cache already includes in its key produces a separate entry per value and cannot be shared.
- **No reflection:** a header the cache ignores but the origin also ignores reaches no response and poisons nothing.
- **No shared cache:** reflection on an origin with no fronting cache affects only the single response.
- **Self-poisoning illusion:** observing the marker only on requests that themselves carry the header does not demonstrate a shared key.
- **Benign reflection:** an unkeyed value reflected into an inert context such as an escaped attribute is a hygiene note, not a poisoning primitive.
- **Cache-buster kept it private:** persistence proven only on a busted key is a safe mechanism check, not yet production impact until shown in scope.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-cache-poisoning-and-deception-unkeyed-input` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-cache-poisoning-and-deception-unkeyed-input` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-cache-poisoning-and-deception-unkeyed-input
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-525 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) - Web and Application (core)
- [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) - Web and Application (leaf)
- [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](../web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-cache-poisoning-and-deception-unkeyed-input` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-525`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
