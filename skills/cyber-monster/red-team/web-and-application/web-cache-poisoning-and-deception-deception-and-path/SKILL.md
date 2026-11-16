---
name: web-cache-poisoning-and-deception-deception-and-path
description: Cache deception through path confusion. Covers tricking the cache into storing authenticated responses by appending static extensions or path segments that the origin ignores. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["cache deception", "path confusion cache", "web cache deception"]
cwe: [CWE-525]
owasp: [A05:2021]
attack: []
capec: [CAPEC-141]
related: [web-cache-poisoning-and-deception, web-cache-poisoning-and-deception-unkeyed-input, web-cache-poisoning-and-deception-cdn-specific-behaviour, sql-injection]
parent: web-cache-poisoning-and-deception
---

# Web Cache Poisoning and Deception Deception and Path - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Cache deception stores a victim's authenticated response in a shared cache because the caching decision was driven by a path or extension the origin ignored. The attacker crafts a URL the origin maps to a dynamic, per-user handler, so it renders the victim's private page, but that the cache treats as a static asset worth storing, typically by appending a `.css` or `.js` suffix, an extra path segment, or a path parameter the origin discards during routing. When the victim is lured to that URL while authenticated, their private response is cached; the attacker then retrieves it from an unauthenticated session under the same key. The security decision is the agreement between the origin's routing and the cache's cacheability rule, and the attacker gains disclosure of another user's data, not control of a shared response. Proof is retrieving the victim's private field from a clean, unauthenticated request.

- **Precondition chain:** The origin routes a static-looking URL to a dynamic per-user handler, a shared cache stores that response because the suffix or segment looks cacheable, and the key is reproducible by an unauthenticated attacker.
- **Readable differential:** A private page requested normally, uncached and per-user, versus the same page requested with a cacheable-looking suffix the origin ignores; a finding exists when the suffixed form is stored and then served to an unauthenticated request, and it closes when the origin marks the response private or the cache stops honouring the suffix.
- **Empirical grounding:** CWE-525 and OWASP A05 anchor the class; GHSA-hq75-xg7r-rx6c, where a routing split produced a static-looking path the origin still treated as a dynamic endpoint, plus PortSwigger's 2025 'Gotta cache 'em all' path-confusion research, anchor this leaf.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not confirmed to be path-based deception **THEN** start at parent class [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) (1 hop) first
2. **IF** the vector is an unkeyed header or parameter reflected into a shared response **THEN** switch to [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) (1 hop)
3. **IF** the behaviour depends on one CDN's normalisation of the suffix **THEN** switch to [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](../web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) (1 hop)
4. **IF** the suffix lets you reach an unlinked handler rather than cache it **THEN** read [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md)
5. **IF** the private data exposed includes session tokens usable elsewhere **THEN** pivot to [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md)
6. **IF** the routing split matches a published advisory for the stack **THEN** confirm via [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the origin marks the response private or the cache never stores the suffixed form **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Vector reflects an unkeyed input into a shared response | [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) | Different invariant: integrity poisoning versus confidentiality deception |
| Suffix handling is specific to one CDN | [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](../web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) | Routes to the per-CDN normalisation invariant |
| Exposed private data includes a reusable session token | [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) | Routes to the token-lifecycle invariant for the downstream impact |
| Need parent class methodology | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the response is genuinely per-user and private.** Pick a page that renders data unique to the logged-in user (profile, email, balance) so a cached copy would be a disclosure, and note the field you will look for later.
2. **Find a suffix or segment the origin discards during routing.** Try appending `/x.css`, `;x.js`, an encoded dot sequence, or an extra path segment and confirm the origin still returns the same private page, proving the router ignored the addition.
3. **Check whether the cache finds the suffixed URL cacheable.** Read the cache-status header on the suffixed request to see whether the edge treats it as a storable static asset.
4. **Store with a keyed cache-buster to stay safe.** Add a keyed token so verification uses a private entry and does not cache the real victim's data on a shared production key during testing.
5. **Retrieve from an unauthenticated session.** Request the suffixed URL, plus buster, with no cookies and check whether the victim's private field is served from cache.
6. **Stop condition.** Halt when the unauthenticated request either (a) returns the private field from a cache hit, (b) returns a login redirect or an empty static asset showing no private content was stored, or (c) can only be shown by caching a real user's live data. Outcome (a) confirms deception, (b) is a non-finding, (c) must be demonstrated with a test account on a busted key.
7. **State what counts as proof.** Proof is the victim's private field retrieved by a request carrying no authentication, served with a cache-hit header, where the same path without the suffix is correctly uncacheable and per-user. A cached generic page with no private data is not deception.
8. **Close with the structural fix and verify it.** Make the origin set `Cache-Control: private, no-store` on every authenticated response and have the cache key on the full path and content type rather than a trailing extension, then replay the suffixed unauthenticated request to confirm no private content is stored.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An authenticated page returned unchanged when `/x.css` is appended to its path | Proves the origin router ignores the suffix while still rendering private data |
| The suffixed URL returning a cache-hit status on a CDN | Proves the edge judged a dynamic response cacheable from its extension |
| The victim's private field present in a response to an unauthenticated request | Proves disclosure, the defining proof of cache deception |
| `Cache-Control` absent or `public` on a per-user response | Proves the origin never told the cache the response was private |
| A path parameter stripped by the origin but kept by the cache | Proves segment-level routing and keying disagreement |
| A login redirect for the bare path but cached content for the suffixed path | Proves the suffix changed only the caching decision, not the origin handler |
| Encoded dot segments that collapse at the origin but not the edge | Proves path-confusion normalisation underlying the deception |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.route('/account/profile')
@app.route('/account/profile/<path:ignored>')   # extra segments silently ignored
def profile(ignored=None):
    user = current_user()
    html = render_profile(user.email, user.balance)   # per-user private data
    return make_response(html)      # no Cache-Control: edge may store it
```

**Hardened pattern:**

```python
@app.route('/account/profile')
def profile():
    user = current_user()
    html = render_profile(user.email, user.balance)
    resp = make_response(html)
    # Authenticated, per-user content is never shared-cacheable
    resp.headers['Cache-Control'] = 'private, no-store, max-age=0'
    return resp
# Extra path segments now 404 instead of routing to the private handler
```

**Why this matters:** The defect is a per-user page that both accepted an ignored static-looking suffix and carried no cache directive, so the edge stored one user's profile under a key an attacker could replay. The fix removes the catch-all segment route and sets `private, no-store` on authenticated responses, so the suffixed URL no longer reaches the handler and nothing per-user is ever cached.

## When It Is NOT This Issue

- **Response is not private:** a cached page containing only public content is normal caching, not deception, even if a suffix reaches it.
- **Origin marks it private:** a `no-store` or `private` authenticated response the cache refuses to store cannot be deceived.
- **Suffix changes the handler:** if appending the extension returns a real static file or a 404 rather than the private page, the router did not ignore it.
- **Self-only retrieval:** retrieving your own cached page in your own session proves nothing about cross-user disclosure.
- **Per-session key:** a cache key bound to the victim's own session cookie is not reachable by an unauthenticated attacker.
- **Login wall on the suffixed path:** a redirect to authentication for the suffixed request means no private body was stored.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-cache-poisoning-and-deception-deception-and-path` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-cache-poisoning-and-deception-deception-and-path` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-cache-poisoning-and-deception-deception-and-path
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
- [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](../web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-cache-poisoning-and-deception-deception-and-path` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-525`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 28 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (7), bugbounty-hunter-v1 (7), hackerone_disclosed_reports (6), SecEval/owasp_wstg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
