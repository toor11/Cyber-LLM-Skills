---
name: ssrf
description: Exploits server-side request forgery against internal services, cloud metadata endpoints, gopher and file handlers, and DNS rebinding, including allowlist bypass and blind SSRF via timing and OAST. Use when the server fetches a user-supplied URL, webhook, image, PDF or import source.
family: web-and-application
tier: flagship
triggers: ["ssrf", "server-side request forgery", "server side request", "internal request", "url fetch", "webhook abuse"]
cwe: [CWE-918]
owasp: [A10:2021]
attack: [T1190]
capec: [CAPEC-664]
related: [ssrf-cloud-metadata, ssrf-internal-service-pivot, ssrf-protocol-smuggling, sql-injection]
---

# SSRF - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **flagship** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

The server takes a destination from the request and performs the fetch itself, so the attacker borrows the server's network position. The security decision is made on the URL the attacker supplied, while the request is issued to whatever the resolver returns and whatever the client library accepts. Three layers can disagree: the parser that validates the string, the resolver that maps the host, and the HTTP client that follows redirects or switches schemes. Each disagreement is an allowlist bypass, and the observable impact depends on what the server can reach that the attacker cannot: loopback admin ports, link-local metadata, RFC1918 services, or internal DNS names.

- **Precondition chain:** a request-controlled destination reaches a server-side fetch primitive, the fetch follows at least one redirect or one scheme the validator did not anticipate, and the response or its side effect is observable to the attacker in some form.
- **Readable differential:** identical request with an allowed destination versus a destination that resolves inward; the difference is a distinct status, body, header, or callback timing, and it disappears when the validator resolves and pins the final address.
- **Empirical grounding:** CWE-918 covers this class; OWASP Top 10:2025 folds SSRF into A01:2025 Broken Access Control.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the fetch target is a URL the attacker controls end to end **THEN** switch to [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) (1 hop) and focus on parser, resolver, and redirect disagreements
2. **IF** the goal is link-local metadata or a cloud credential endpoint **THEN** switch to [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) (1 hop); confirm the client's method and header forwarding before assuming IMDSv2 blocks it
3. **IF** the goal is an internal service such as Redis, Elasticsearch, or an admin API **THEN** switch to [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) (1 hop)
4. **IF** the parameter accepts a scheme such as `gopher`, `file`, `dict`, or `ldap` **THEN** switch to [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) (1 hop)
5. **IF** no response body, status, or error is reflected back **THEN** switch to [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) (1 hop) and switch the oracle to DNS/HTTP callbacks or timing
6. **IF** the fetch is inside a PDF, screenshot, or HTML renderer **THEN** switch to [`pdf-and-headless-renderer-injection`](../pdf-and-headless-renderer-injection/SKILL.md) (1 hop)
7. **IF** the value is validated as a hostname but the response is cached or shared **THEN** also read [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) because the fetcher may be the cache
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
9. **IF** the destination is fixed by configuration and never request-derived **THEN** STOP and classify as a verified non-finding; record the fixed egress path as an inventory item instead

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Destination validated as a string but resolved separately | [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) | Validation and resolution disagree; only the resolved address matters |
| Fetch reaches link-local or cloud metadata | [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) | Impact is credential exposure through the instance role |
| Fetch reaches an internal TCP service | [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) | Impact is protocol interaction with a service that trusts its network |
| Target matches `ssrf-protocol-smuggling` | [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `ssrf-blind-ssrf` | [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the fetch primitive and who controls the destination.** Webhook test buttons, avatar importers, URL-to-PDF, feed readers, and link previewers are the usual carriers. Record whether the destination arrives whole, as a host only, or as a path appended to a fixed base.
2. **Classify the validator.** Is there a schema check, a hostname allowlist, an IP denylist, a redirect cap, or nothing? Read the code path for the exact order: parse, validate, resolve, connect. The gap between resolve and connect is where rebinding lives.
3. **Pick the oracle before probing.** Reflected body, distinct status, response size, error text, redirect target, and OAST callback are all usable. Choose the one that leaks the least information while still falsifying the hypothesis.
4. **Establish the outward baseline.** Fetch a host you control and confirm the request arrives with the method, headers, and body the server intends to send. This also captures the client's User-Agent and whether it follows redirects, which determines the whole branch set.
5. **Test the validation layer, not the payload.** Ask whether the validator and the connector agree on the same host. Try a host that is allowed as a string but resolves inward, an allowed host that redirects inward, and a numeric or encoded form of an inward address. Each answers a different question about where the disagreement sits.
6. **Stop condition.** Stop when the fetch either (a) reaches a destination the requester could not reach directly, demonstrated by a differential against the outward baseline, (b) is refused identically for every inward form, or (c) would require reading or writing real internal data to advance. Case (a) is the finding; (b) is a non-finding; (c) is out of scope.
7. **State what counts as proof.** Proof is a fetch that originates from the server, not the browser, and lands somewhere the requester cannot reach: a callback from the server's egress address, an internal response fragment in the reply, or a distinct error for a closed internal port versus an open one. A DNS lookup alone proves resolution, not that the request was issued.
8. **Close with the structural fix.** Resolve once, validate the resolved address against a deny-set of link-local, loopback, and RFC1918 ranges, pin that address for the connection, disable redirects or re-validate each hop, and restrict schemes to the one the feature needs. Verify by replaying the confirmation probe against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A destination parameter that accepts a full URL including scheme and host | Proves the attacker controls the connector, not just a path; present on any stack with a generic HTTP client wrapper |
| Validation performed on the hostname string while the client resolves it later | Proves a time-of-check gap that DNS rebinding or a short-TTL record can exploit; typical of Node, Python, and Go allowlist helpers |
| A fetch client configured to follow redirects with no per-hop re-validation | Proves the allowlist can be bypassed by an allowed host that 302s inward; affects most default HTTP client configurations |
| Decimal, octal, or hex-encoded IPv4 literals reaching the connector | Proves the validator normalises differently from the connector's resolver; a classic parser-differential indicator on Linux resolvers |
| Outbound request from the application host to a link-local address | Proves metadata reachability on AWS, GCP, or Azure; impact depends on whether the client can carry a token header |
| A webhook or import feature that echoes the fetched body or a transformed version of it | Proves a full-read SSRF where the response is returned to the requester, not just a blind callback |
| Distinct error classes for closed versus open internal ports | Proves port-level reachability even when the response body is suppressed; usable as a low-noise oracle on any backend |

## Worked Contrast

**Vulnerable pattern:**

```python
def fetch_preview(url: str) -> bytes:
    # Validates the hostname string, then lets the client resolve and redirect freely
    host = urllib.parse.urlsplit(url).hostname or ""
    if not host.endswith(".cdn.example"):
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5, allow_redirects=True).content
```

**Hardened pattern:**

```python
ALLOWED_PORTS = {80, 443}

def fetch_preview(url: str) -> bytes:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError("scheme not allowed")
    host = parts.hostname or ""
    if not host.endswith(".cdn.example"):
        raise ValueError("host not allowed")
    # Resolve once, reject every non-public answer, then connect to the pinned IP
    infos = socket.getaddrinfo(host, parts.port or 443, proto=socket.IPPROTO_TCP)
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise ValueError("destination resolves to a non-public address")
    pinned = infos[0][4][0]
    # No redirect following: each hop would need its own validation
    return requests.get(url, timeout=5, allow_redirects=False,
                        headers={"Host": host}).content
```

**Why this matters:** The hardened version validates the scheme, resolves exactly once, rejects every non-public answer including link-local and loopback, and refuses to follow redirects. That closes the resolve-versus-connect gap and the redirect bypass without relying on a string denylist.

## When It Is NOT This Issue

- **Destination fixed by configuration:** a connector that reads its base URL from environment variables and appends only a path is not SSRF even when the path is attacker-controlled. Path control is a different finding.
- **DNS-only callback without a request:** an OAST hit proves the resolver was asked, not that the server issued the request. Some resolvers pre-resolve for validation and never connect.
- **Browser-side fetch:** a URL that the victim's browser requests is client-side request forgery, which needs its own impact story and does not borrow server network position.
- **Fetch blocked at egress:** a host firewall or network policy that refuses the connection means the primitive exists but is not exploitable. Report the code defect at reduced severity, not as confirmed SSRF.
- **Metadata reachable but method-locked:** where the client can only issue GET without custom headers and the platform enforces a token-based metadata service, the fetch may reach the endpoint yet return no credential. Confirm the token flow before claiming impact.
- **Redirect to an external host only:** a fetch that follows a redirect to another public site is a validation gap, not internal access. Impact requires an inward destination.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssrf` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssrf` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssrf
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-918 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) - Web and Application (leaf)
- [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) - Web and Application (leaf)
- [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssrf` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-918, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 66 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (27), securecode-web (20), CYBER_CPT/nuclei_templates (8), cyber-security/security-code (5) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 13 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
