---
name: web-cache-poisoning-and-deception-cdn-specific-behaviour
description: CDN-specific cache behaviour exploitation. Covers per-CDN cache key rules and normalization quirks for Cloudflare, Akamai, Fastly, CloudFront and Varnish. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["cdn cache poisoning", "cloudflare cache", "akamai cache", "fastly cache"]
cwe: [CWE-525]
owasp: [A05:2021]
attack: []
capec: [CAPEC-141]
related: [web-cache-poisoning-and-deception, web-cache-poisoning-and-deception-unkeyed-input, web-cache-poisoning-and-deception-deception-and-path, sql-injection]
parent: web-cache-poisoning-and-deception
---

# Web Cache Poisoning and Deception Cdn Specific Behaviour - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This leaf turns on the exact cache-key and URL-normalisation rules of one named CDN. Each product decides differently which query parameters, header values, path casings, and trailing segments belong to the key, and how it normalises a URL before forwarding it to the origin; when the CDN's parser and the origin's parser disagree about where the path ends or how a parameter is folded, a response built for one logical resource is stored under a key a different request will match. Cloudflare, Akamai, Fastly, CloudFront, and Varnish each expose distinct levers (surrogate keys, cache tags, default-keyed parameters, pragma handling), so a probe that proves a gap on one is inert on another. The security decision is the agreement between that CDN's key or parser and the origin's routing, and the attacker gains a stored response under a key victims share. Proof is a cache hit on a clean request routed through the same CDN edge.

- **Precondition chain:** A specific CDN product fronts the origin, that product normalises or keys the URL differently from how the origin routes it, and a response built for one resource is therefore stored under a key a victim's request will hit.
- **Readable differential:** The same logical URL expressed in two forms the CDN normalises identically but the origin routes differently, compared through the CDN's own cache-status header; a finding exists when the clean form returns the response built for the other form, and it closes when the CDN and origin agree on the normalised key.
- **Empirical grounding:** CWE-525 and OWASP A05 anchor the class; PortSwigger's 2025 'Gotta cache 'em all' research on URL-parser disagreement across CDNs plus the path-confusion CVEs CVE-2025-52892, CVE-2024-53008, CVE-2024-27185, and CVE-2024-11234 document the per-CDN parser gaps this leaf targets.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the CDN product is not yet identified or the gap is not CDN-specific **THEN** start at parent class [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) (1 hop) first
2. **IF** the vector is an unkeyed header or parameter rather than a CDN normalisation quirk **THEN** switch to [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) (1 hop)
3. **IF** the gap is a path or extension the origin ignores, producing deception **THEN** switch to [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) (1 hop)
4. **IF** the CDN and origin disagree on message framing, not on the key **THEN** read [`http-request-smuggling`](../http-request-smuggling/SKILL.md)
5. **IF** the normalisation quirk is really a Host header trust issue **THEN** read [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md)
6. **IF** the identified CDN or product version maps to a published advisory **THEN** confirm it via [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the CDN and origin normalise and key the URL identically **THEN** STOP and record a verified non-finding: there is no parser or key gap at this edge

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Vector is an unkeyed header, not a CDN quirk | [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) | Different invariant: unkeyed input versus edge normalisation |
| Gap is a static-suffix deception the origin ignores | [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) | Routes to the path-confusion invariant specifically |
| Edge version matches a path-confusion advisory | [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md) | Routes to advisory confirmation for the named product |
| Need parent class methodology | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the CDN and its key model first.** Read the response for `cf-cache-status`, `x-served-by` or `x-cache` (Fastly, Varnish), `x-amz-cf-id` (CloudFront), or Akamai pragma output, and note the product's default cache-key composition and URL-normalisation rules.
2. **List the levers that product exposes.** Default-keyed versus unkeyed query parameters, case and trailing-slash normalisation, surrogate keys or cache tags, and how it treats semicolons, encoded slashes, and dot segments before forwarding.
3. **Find a normalisation disagreement.** Express one logical resource in two URL forms and observe, through the CDN status header, whether the edge treats them as one key while the origin routes them to different handlers, or the reverse.
4. **Attach a keyed cache-buster for safety.** Add a token the CDN keys on so verification lands on a private entry and does not disturb the shared production key.
5. **Store under one form, retrieve under the other.** Request the resource in the form that builds the response you want cached, then request the colliding form a victim would send, reading the cache-status header to confirm a hit.
6. **Stop condition.** Halt when the colliding clean request either (a) returns the response built for the other form with a CDN hit, (b) returns its own correctly keyed response, or (c) can only be shown by colliding on a shared production key. Outcome (a) confirms the CDN-specific gap, (b) is a non-finding, (c) must stay on a busted key within scope.
7. **State what counts as proof.** Proof is a CDN cache hit, named in the status header, returning content keyed for a different URL form, reproduced through the same edge POP, with the two URL forms and the origin's routing of each shown. A hit alone without the cross-form collision is just normal caching.
8. **Close with the structural fix and verify it.** Align the CDN's normalisation and cache-key with the origin's routing (key on the full normalised path, stop stripping parameters the origin honours, or canonicalise at the origin), then replay the two URL forms to confirm they now resolve to distinct keys.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `cf-cache-status`, `x-served-by`, or `x-amz-cf-id` identifying the fronting product | Proves which CDN's key and normalisation rules apply, selecting the correct lever set |
| Two URL forms returning one cached body on the named CDN | Proves the edge normalised them to one key while the origin routed them apart |
| An encoded slash or dot segment normalised by the CDN but not the origin | Proves a URL-parser disagreement specific to that product, the path-confusion root cause |
| A query parameter the CDN strips from the key but the origin reads | Proves a default-keying gap on that product letting the parameter go unkeyed |
| Trailing-slash or case folding at the edge changing which origin handler runs | Proves normalisation-driven key collision unique to the CDN configuration |
| Surrogate-key or cache-tag headers exposed in the response | Proves the invalidation and keying model in use, which scopes the blast radius |
| `Age` incrementing identically for both URL forms | Proves the two forms share one stored entry at the edge |

## Worked Contrast

**Vulnerable pattern:**

```vcl
sub vcl_hash {
    # Key on path only; the origin varies the body on ?lang but the edge drops it
    hash_data(req.url.path);
    return(lookup);
}
sub vcl_backend_response {
    set beresp.ttl = 10m;   # cached for all; lang-specific body collides
}
```

**Hardened pattern:**

```vcl
sub vcl_hash {
    hash_data(req.url.path);
    # Include every response-affecting parameter the origin reads in the key
    if (req.url.qs ~ "(^|&)lang=") {
        hash_data(querystring.filter_except(req.url, "lang"));
    }
    return(lookup);
}
sub vcl_backend_response {
    set beresp.http.Vary = "X-Lang";   # declare the variance
    set beresp.ttl = 10m;
}
```

**Why this matters:** The defect is that the edge keyed only on the path while the origin varied the body on a query parameter the edge discarded, so a request in one language could be stored and served to speakers of another. The fix folds the response-affecting parameter back into the cache key and declares the variance, so each distinct body gets its own edge key.

## When It Is NOT This Issue

- **Unidentified CDN:** attributing a collision to a product's normalisation without confirming which CDN is in front is guesswork.
- **Normalisation agrees with origin:** if the edge and origin resolve both URL forms to the same handler, there is no cross-form collision.
- **Keyed parameter:** a parameter the CDN already includes in the key produces separate entries and no collision.
- **Edge error page:** a cached 403 or challenge from the CDN itself is not origin content and not a poisoning of the application.
- **POP-local observation:** a hit seen on one POP that does not reproduce for a victim on another POP may be a local artefact rather than a shared key.
- **Vendor default already aligned:** a product whose defaults key on the full normalised URL leaves no stripping gap to exploit.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-cache-poisoning-and-deception-cdn-specific-behaviour` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-cache-poisoning-and-deception-cdn-specific-behaviour` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-cache-poisoning-and-deception-cdn-specific-behaviour
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-525 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) - Web and Application (core)
- [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) - Web and Application (leaf)
- [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-cache-poisoning-and-deception-cdn-specific-behaviour` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-525`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/nuclei_templates (4), CYBER_CPT/blackhills (1), CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
