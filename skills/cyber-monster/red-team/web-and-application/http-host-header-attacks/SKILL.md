---
name: http-host-header-attacks
description: Exploits trust in the Host and forwarded headers for password-reset poisoning, cache poisoning, routing bypass and SSRF. Use when an application builds absolute URLs, routes by host, or honours X-Forwarded-* headers.
family: web-and-application
tier: leaf
triggers: ["host header injection", "host header", "forwarded header", "x-forwarded-host", "host poisoning", "virtual host bypass"]
cwe: [CWE-644]
owasp: [A05:2021]
attack: []
capec: [CAPEC-274]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Http Host Header Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

The application reuses a client-supplied host identity, the `Host` header or an `X-Forwarded-Host` variant, as if it were the server's own trusted hostname. That value flows into absolute URL generation for password-reset and verification links, cache keys, routing decisions, or a server-side fetch target. Because the attacker sets the header while the victim or an intermediary trusts the resulting output, a poisoned host turns up in an email link the victim clicks, a cached response served to others, or a request the server issues to an attacker-chosen origin. The security decision is whether the application derives its own hostname from trusted configuration or from the inbound request. Confirmation is a response or side effect that carries the attacker's host where the application intended its own.

- **Precondition chain:** the application reads its hostname from the inbound `Host` or a forwarded header, that value reaches a link builder, cache key, router, or fetch without being checked against a configured allowlist, and the resulting output is delivered to a victim, a shared cache, or an internal target.
- **Readable differential:** a request with the legitimate `Host` versus one with an attacker host in `Host` or `X-Forwarded-Host`; a finding exists when the attacker host appears in a generated link, cached response, or outbound fetch, and it closes when the hostname is pinned to a configured base domain.
- **Empirical grounding:** CWE-644 Improper Neutralization of HTTP Headers. SOURCES.md anchors 2025 instances: CVE-2025-47424 (Retool, fixed by requiring a configured BASE_DOMAIN), CVE-2025-27913 (Passbolt host-header injection in account-recovery email links), and CVE-2025-36223 (IBM OpenPages host-header injection, CWE-644).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the poisoned host lands in a password-reset or verification link **THEN** treat the email-link sink as primary and confirm the victim receives the attacker host
2. **IF** the host value is reflected into a cached response **THEN** route the cache-key angle to [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md)
3. **IF** the application fetches a resource built from the host header **THEN** route the server-side fetch angle to [`ssrf`](../ssrf/SKILL.md)
4. **IF** routing or virtual-host selection is driven by `X-Forwarded-Host` **THEN** test whether a forwarded host reaches a different backend than `Host`
5. **IF** a reverse proxy rewrites `Host` while the origin trusts `X-Forwarded-Host` **THEN** record which hop sets the trusted value before claiming reach
6. **IF** the sink is an account-recovery flow specifically **THEN** assess the recovery-link poisoning impact via [`password-reset-and-account-recovery`](../password-reset-and-account-recovery/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the hostname is pinned to a configured base domain and no sink reflects the inbound host **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The host value is reflected into a shared cached response | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | Invariant is cache-key completeness, not link generation |
| The host header drives a server-side fetch target | [`ssrf`](../ssrf/SKILL.md) | Invariant is outbound destination control rather than URL building |
| The poisoned host lands in an account-recovery link | [`password-reset-and-account-recovery`](../password-reset-and-account-recovery/SKILL.md) | Invariant is recovery-flow integrity and link binding |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find where the application uses its own hostname.** Locate absolute URL construction, email-link templating, cache-key composition, virtual-host routing, and any server-side fetch, and record whether each reads the hostname from configuration or from the request.
2. **Classify the trusted header and the sink.** Determine whether the code trusts `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, or a `Forwarded` field, and which sink consumes it: link, cache, router, or fetch. The sink decides who the victim is.
3. **Record a legitimate-host baseline.** Send the normal `Host` and capture the generated link, the cache-key behaviour, the routed backend, and any outbound request, so a poisoned value has a reference.
4. **Send one poisoned-host probe to that sink.** Set an assessor-controlled host in the trusted header while keeping the path and method identical, and observe whether that host appears in the generated link, the cached body, the routing, or an outbound callback.
5. **Confirm delivery to a third party, not just reflection.** For a link sink, confirm the host reaches the email or token flow; for a cache sink, confirm another request retrieves the poisoned body; for routing, confirm a different backend answered.
6. **Stop condition.** Stop when the probe either (a) places the attacker host in a link delivered to a victim, a cached response served to others, or an outbound fetch, (b) is ignored because the hostname comes from configuration, or (c) would require sending a poisoned reset link to a real user to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is the attacker-controlled host appearing in a trusted output with a third-party victim, for example a reset link built with the assessor host or a cached entry returned to a different client, tied to the header the code trusted. A reflected host in the attacker's own response with no further consumer is not proof.
8. **Separate the sink responsibilities.** Note whether the fix is link-building hostname pinning, cache-key inclusion of the host, or routing hardening, because one application can be vulnerable at one sink and safe at another.
9. **Close with the structural fix and verify.** Derive the hostname from a configured base domain or an allowlist of valid hosts, reject or normalise `Host` and forwarded headers at the edge, include the host in the cache key, and never build links or fetches from the inbound header, then replay the poisoned-host probe to confirm the configured host is used.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A password-reset link whose host equals the inbound `Host` header | Proves the link builder trusts the request host, as in the Passbolt recovery-email case |
| `X-Forwarded-Host` reflected in an absolute URL or redirect | Proves a forwarded header reaches URL generation past the proxy |
| A cached response body containing the request's host value | Proves the host is unkeyed and a poisoned entry can be served to others |
| Virtual-host routing selected by `X-Forwarded-Host` | Proves backend selection is driven by a client-controlled header |
| A configured BASE_DOMAIN or host allowlist governing link building | Proves the hostname comes from configuration, as the Retool fix enforces |
| An edge proxy that overwrites `Host` and strips forwarded headers | Proves inbound host identity is normalised before the application reads it |
| An outbound fetch whose target host is taken from the request header | Proves a server-side request can be steered by the host header |

## Worked Contrast

**Vulnerable pattern:**

```python
def send_reset(request, user):
    # Builds the reset link from the inbound Host header the attacker controls
    host = request.headers.get("X-Forwarded-Host") or request.headers["Host"]
    link = "https://" + host + "/reset?token=" + issue_token(user)
    email(user.email, "Reset your password", link)
```

**Hardened pattern:**

```python
from urllib.parse import urljoin

BASE_URL = "https://app.example.com"          # configured, not request-derived

def send_reset(request, user):
    # Hostname comes from configuration; inbound Host and forwarded headers are ignored here
    link = urljoin(BASE_URL, "/reset?token=" + issue_token(user))
    email(user.email, "Reset your password", link)
```

**Why this matters:** The defective flow builds the reset link from the attacker-controlled `X-Forwarded-Host` or `Host`, so a victim receives a link pointing at the attacker's host and leaks the token on click; the fixed flow builds the link from a configured base URL, so the hostname no longer depends on the request and the token is always sent to the real application.

## When It Is NOT This Issue

- **Hostname from configuration:** an application that builds links and fetches from a configured base domain ignores the inbound host entirely.
- **Reflected host with no consumer:** a host echoed only in the attacker's own response, never reaching a victim, cache, or backend, has no impact.
- **Edge normalises Host:** a proxy that overwrites `Host` to the canonical value and strips `X-Forwarded-Host` closes the injection before the application sees it.
- **Host included in the cache key:** a cache that keys on the host cannot serve a poisoned entry to a different host.
- **Self-only reset link:** a reset-link poisoning that only affects the attacker's own account recovery is not cross-user impact.
- **Hardcoded absolute links:** templates that emit absolute URLs from a constant base are unaffected by the header.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http-host-header-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http-host-header-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http-host-header-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-644 | Mapping: A05:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http-host-header-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-644`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 52 |
| Distinct dataset sources | 10 |
| Top sources | OffsecCyber (18), hackerone_disclosed_reports (12), CYBER_CPT/nuclei_templates (5), CYBER_CPT/gh_advisories (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
