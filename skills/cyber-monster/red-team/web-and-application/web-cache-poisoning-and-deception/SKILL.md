---
name: web-cache-poisoning-and-deception
description: "Exploits cache key confusion to store malicious responses or leak private data: unkeyed header and parameter poisoning, cache deception via path suffixes, cache key normalization, and CDN-specific behaviour. Use when a CDN or reverse proxy caches responses."
family: web-and-application
tier: core
triggers: ["cache poisoning", "web cache", "cache deception", "cache key", "unkeyed input", "cdn poisoning"]
cwe: [CWE-525]
owasp: [A05:2021]
attack: []
capec: [CAPEC-141]
related: [web-cache-poisoning-and-deception-unkeyed-input, web-cache-poisoning-and-deception-deception-and-path, web-cache-poisoning-and-deception-cdn-specific-behaviour, sql-injection]
---

# Web Cache Poisoning and Deception - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A shared cache stores a response under a key computed from part of the request and serves it to everyone whose request produces the same key. Two failure families follow from the gap between what the cache keys on and what the origin uses to build the response. In poisoning, an integrity failure, an input the origin reflects into the response is left out of the cache key, so an attacker stores a harmful response under a key that victims' benign requests will match. In deception, a confidentiality failure, the cache stores a response that should have stayed private because the key or the cacheability decision was driven by a path or extension the origin ignored, so one user's authenticated content is served to others. The security decision lives in the cache-key and cacheability policy shared between the CDN and the origin, and the attacker gains either mass delivery of a poisoned response or disclosure of private data. Proof is a cached artefact retrieved by a second, clean request.

- **Precondition chain:** A shared cache sits in front of the origin, some request element that influences the response body or the cacheability decision is excluded from the cache key, and either a harmful value is reflected (poisoning) or private content is stored (deception) under a key other requests will hit.
- **Readable differential:** A request carrying the suspect input, tagged with a unique cache-buster, versus a clean follow-up request for the same keyed URL; a finding exists when the clean request receives the attacker-influenced or private response, and it closes when the input is added to the key or the response is marked uncacheable.
- **Empirical grounding:** CWE-525 and OWASP A05 anchor the class; PortSwigger's 2025 'Gotta cache 'em all' research on URL-parser disagreement across CDNs, the path-confusion CVEs CVE-2025-52892, CVE-2024-53008, CVE-2024-27185, and CVE-2024-11234, and GHSA-hq75-xg7r-rx6c, where a routing split made a dynamic endpoint look static, document the modern variants.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the unkeyed element is a request header or query parameter reflected into the body **THEN** switch to [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) (1 hop)
2. **IF** the cache stores private pages because of a path or extension the origin ignores **THEN** switch to [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) (1 hop)
3. **IF** the behaviour depends on one CDN's specific cache-key and normalisation rules **THEN** switch to [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](../web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) (1 hop)
4. **IF** the poisoning vector is a `Host` or forwarded-host header the origin trusts **THEN** read [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) for the host-trust invariant
5. **IF** the reflected value is an open redirect that becomes persistent once cached **THEN** pivot to [`open-redirect`](../open-redirect/SKILL.md)
6. **IF** the cached response carries script and the real impact is stored XSS **THEN** pivot to [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md)
7. **IF** the split is between proxy and origin message framing, not the cache key **THEN** read [`http-request-smuggling`](../http-request-smuggling/SKILL.md), a different class of cache attack
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** no shared cache is in front of the origin, or every response for the route is private and uncacheable **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Poisoning vector is a trusted Host or forwarded-host header | [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) | Different invariant: host trust at the origin, upstream of the cache key |
| Reflected value is a redirect target persisted by the cache | [`open-redirect`](../open-redirect/SKILL.md) | Invariant is redirect allowlisting, with the cache only amplifying it |
| Cache entry is poisoned via an LFI-style log or include path | [`path-traversal-and-lfi-log-and-cache-poisoning`](../path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) | Routes to the file-inclusion invariant rather than the cache key |
| Target matches `web-cache-poisoning-and-deception-unkeyed-input` | [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `web-cache-poisoning-and-deception-deception-and-path` | [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `web-cache-poisoning-and-deception-cdn-specific-behaviour` | [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](../web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Separate the question into integrity or confidentiality first.** Decide whether you are trying to store a harmful response for others (poisoning) or retrieve someone's private response (deception); the two use different proofs and remediations, and conflating them produces a false report.
2. **Map the cache key against the response inputs.** Identify what the fronting cache keys on (method, host, path, selected query parameters, `Vary` headers) and what the origin actually reads to build the body; any response-affecting input absent from the key is a candidate.
3. **Tag every probe with a unique cache-buster.** Append a random keyed token so your tests land on a private key and never poison a real user's entry during verification.
4. **Record the cache-state baseline.** Capture `X-Cache`, `Age`, `cf-cache-status`, or an equivalent header on a clean request so a hit versus miss is unambiguous for the keyed URL.
5. **Store, then retrieve with a clean request.** For poisoning, send the unkeyed input with your buster, confirm the response is stored, then request the same keyed URL without the input and check the stored response is served. For deception, request a private page through the key-confusing path and retrieve it from an unauthenticated session.
6. **Stop condition.** Halt when the follow-up clean request either (a) returns the attacker-influenced body or the private content, (b) returns the normal uncached response showing the input was keyed or the page was private, or (c) can only be shown by poisoning a production key that real users share. Outcome (a) confirms, (b) is a non-finding, (c) must be demonstrated on a busted private key, never on the live key.
7. **State what counts as proof.** Proof is a second, independent request that receives the cached artefact: the poisoned marker reflected to a clean request on a keyed URL, or the victim's private field retrieved without their session, together with the cache-status header showing a hit. A single response to your own poisoning request is not proof of caching.
8. **Close with the structural fix and verify it.** Add every response-affecting input to the cache key or mark those responses uncacheable, and make the origin set `Cache-Control: private` or `no-store` on authenticated responses so the CDN never stores them; re-run the store-then-retrieve sequence to confirm the clean request no longer receives the artefact.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A request header reflected into the body but absent from the cache key | Proves unkeyed-input poisoning on any CDN that keys on URL only, the integrity variant |
| An authenticated page cached because its URL ended in `.css` or a static-looking suffix | Proves cache deception where the extension drove cacheability, the confidentiality variant |
| `X-Cache: hit` or `cf-cache-status: HIT` returned to a clean follow-up request | Proves the suspect response was stored and is being served to others |
| A `Vary` header missing the input that changes the body | Proves the origin did not instruct the cache to key on a response-affecting header |
| A CDN and origin disagreeing on where the path ends | Proves the URL-parser discrepancy behind path-confusion deception on specific CDNs |
| A cache-buster query token that is keyed and isolates test entries | Proves safe verification is possible without touching the shared production key |
| `Cache-Control: public` on a response containing per-user data | Proves a cacheability policy error that enables deception regardless of the key |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.route('/home')
def home():
    # Unkeyed header reflected into a cached, public response
    base = request.headers.get('X-Forwarded-Host', request.host)
    html = f'<link rel="canonical" href="https://{base}/home">'
    resp = make_response(html)
    resp.headers['Cache-Control'] = 'public, max-age=600'   # cached for everyone
    return resp
```

**Hardened pattern:**

```python
TRUSTED_HOSTS = {'www.example.com'}

@app.route('/home')
def home():
    host = request.host if request.host in TRUSTED_HOSTS else 'www.example.com'
    html = f'<link rel="canonical" href="https://{host}/home">'
    resp = make_response(html)
    # Do not reflect untrusted input into a shared response; key on host if cached
    resp.headers['Cache-Control'] = 'public, max-age=600'
    resp.headers['Vary'] = 'Host'
    return resp
```

**Why this matters:** The defect is that a header the origin reflected into the body was not part of the cache key and the response was public, so one request could store a poisoned canonical link served to every visitor. The fix stops reflecting the untrusted forwarded-host, pins a trusted host, and adds `Vary: Host` so any cached entry is keyed on the value that influences the body.

## When It Is NOT This Issue

- **No shared cache:** a `Cache-Control` header on an origin with no CDN or reverse-proxy cache in front means nothing is stored for other users.
- **Response varies correctly:** if the suspect input is already in the cache key or a matching `Vary`, a clean request gets its own entry and there is no cross-user effect.
- **Browser-only caching:** a response cached solely in the victim's private browser cache is a client-side concern, not shared poisoning or deception.
- **Self-poisoning:** seeing your own injected marker on your own repeated request, without a second clean client hitting it, does not prove the key is shared.
- **Already-private content:** a page already marked `no-store` or `private` that the CDN refuses to cache cannot be deceived into storage.
- **Cache-buster kept the test isolated:** a hit observed only on your busted key confirms the mechanism safely but is not yet impact until shown on a shared key in scope.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-cache-poisoning-and-deception` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-cache-poisoning-and-deception` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-cache-poisoning-and-deception
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-525 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) - Web and Application (leaf)
- [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) - Web and Application (leaf)
- [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](../web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-cache-poisoning-and-deception` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-525`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 47 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (30), hackerone_disclosed_reports (12), bugbounty-hunter-v1 (2), SecEval/owasp_wstg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
