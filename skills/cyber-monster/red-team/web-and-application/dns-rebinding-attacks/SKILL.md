---
name: dns-rebinding-attacks
description: Uses DNS rebinding to bypass same-origin and IP-based allowlists, reaching internal services from a browser or an SSRF sink, including TTL manipulation and multiple A records. Use when origin trust or IP filtering is the only control.
family: web-and-application
tier: leaf
triggers: ["dns rebinding", "rebind attack", "dns rebind ssrf", "ttl rebinding"]
cwe: [CWE-350]
owasp: [A10:2021]
attack: []
capec: [CAPEC-275]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# DNS Rebinding Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

DNS rebinding abuses the gap between when a name is validated and when it is connected to. The attacker serves a hostname whose DNS answer flips from an external, allowlisted address (passing the origin or IP check) to an internal address such as 127.0.0.1 or an RFC1918 host after a short TTL; a browser tab or an SSRF fetcher that re-resolves the name then connects to the internal service while still treating it as the original origin. The security decision wrongly relies on the hostname or a prior resolution rather than on authentication of the local service and the Host header. The attacker gains the victim browser's or server's network position against services that assume network reachability equals authorisation. Confirmation observes the resolution flipping and the internal service answering a request bound to the attacker's hostname.

- **Precondition chain:** a target (browser or server-side fetcher) makes a security decision from a hostname or reverse DNS rather than a pinned address, the attacker controls an authoritative name with a short TTL that can rebind to an internal address, and the internal service answers requests without checking the Host header or authenticating the caller.
- **Readable differential:** a request to the attacker hostname while it resolves externally versus after it rebinds to an internal address; a finding exists when the second resolution reaches an internal service that answers, and it closes when the service enforces a Host-header allowlist and authentication, or the client pins the first resolved address.
- **Empirical grounding:** CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action covers this class, and OWASP maps the SSRF-adjacent impact under A01:2025 Broken Access Control. SOURCES has no rebinding-specific advisory, so the anchor stays at the CWE-350 taxonomy level rather than a named CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the only control on a local or internal service is origin trust or an IP allowlist **THEN** this is the primary case; drive the resolution-flip differential
2. **IF** a server-side fetcher validates a hostname then re-resolves on connect **THEN** route to [`ssrf`](../ssrf/SKILL.md) because the resolve-versus-connect gap is shared
3. **IF** the goal is cloud metadata reached through the flip **THEN** route to [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) for the token-flow caveats
4. **IF** the target is a browser reaching a localhost desktop agent **THEN** focus on the Host header and whether the agent authenticates, not just the IP
5. **IF** the client caches DNS or pins the first answer **THEN** rebinding is blunted; confirm the resolver TTL handling before claiming reachability
6. **IF** the service enforces a Host allowlist already **THEN** test whether an attacker Host value is accepted before concluding
7. **IF** the underlying read is really request forgery from the server **THEN** route to [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`network-detection-and-ids`](../../../blue-team/detection-and-monitoring/network-detection-and-ids/SKILL.md)
9. **IF** the internal service requires authentication and rejects foreign Host values, or the client pins the resolved address **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Server-side fetcher with a validate-then-connect gap | [`ssrf`](../ssrf/SKILL.md) | Shares the resolve-versus-connect window but the sink is a server fetch, not a browser origin |
| The flip targets link-local cloud metadata | [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) | Impact is instance-credential exposure, gated by the metadata token flow |
| The rebind reaches an internal TCP service | [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) | Invariant is the network-trust assumption of the internal service, not DNS itself |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the target that trusts a name and when it re-resolves.** Determine whether a browser page, a desktop agent on localhost, or a server-side fetcher makes the decision, and whether it resolves once or on every connection, because rebinding needs a re-resolve.
2. **Classify the control being bypassed.** Is it an Origin or Host check, an IP allowlist, a reverse-DNS decision, or nothing? Read whether the internal service authenticates at all, since an authenticated service is not rebindable into trust.
3. **Set up a controlled authoritative name with a short TTL.** Point it first at an external address you control to pass any initial check, recording the TTL and the resolver's caching behaviour.
4. **Record the external-resolution baseline.** Make the request while the name resolves outward and capture the response; this is the allowlisted state the target accepts.
5. **Rebind and re-request, changing only the resolved address to an internal target.** Observe whether the client re-resolves and connects inward while still labelling the connection with the attacker hostname; distinct responses for a closed versus open internal port are a low-noise oracle.
6. **Confirm the Host header reaches the internal service unchecked.** Verify the internal service answered a request carrying the attacker's hostname, which is what proves the trust decision was name-based.
7. **Stop condition.** Stop when the request either (a) reaches an internal service that answers after the resolution flip and is refused once the service checks Host and authenticates, (b) is blocked because the client pinned the first address or the service rejected the foreign Host, or (c) would require reading or altering real internal data to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is the name resolving externally then internally plus the internal service answering a request bound to the attacker hostname, evidenced by a response an outside requester could not obtain directly. A single DNS lookup, or a flip the client never acts on, is not proof.
9. **Close with the structural fix.** Authenticate local and internal services and enforce a Host-header allowlist so a request bound to an attacker name is rejected, and have clients pin the first resolved address for the connection's lifetime, then replay the rebind against the hardened service.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A short-TTL A record that returns an external address then an internal one | Proves a rebinding-capable name on any resolver that honours the low TTL |
| A local or internal service answering requests with no authentication | Proves network reachability is treated as authorisation, the trust assumption rebinding abuses |
| An internal service that does not validate the Host header | Proves a request bound to a foreign hostname is accepted, the core name-trust defect |
| A client that re-resolves the hostname on each connection | Proves the resolve-versus-connect window exists for the flip to land on this stack |
| Distinct responses for closed versus open internal ports after the flip | Proves internal reachability as a low-noise oracle without reading service data |
| An IP allowlist or Origin check used as the only gate on a local service | Proves the control is name or address based and bypassable by rebinding rather than authentication |

## Worked Contrast

**Vulnerable pattern:**

```python
from flask import request

ALLOWED_IPS = {"127.0.0.1"}

def admin_action():
    # Trusts the connecting IP only; a rebound hostname still connects from localhost
    if request.remote_addr in ALLOWED_IPS:
        return do_privileged_action()
    return ("forbidden", 403)
```

**Hardened pattern:**

```python
from flask import request
import hmac

ALLOWED_HOSTS = {"agent.localhost"}

def admin_action():
    # Reject foreign Host values and require an authenticated token, not just the source IP
    host = request.headers.get("Host", "").split(":")[0]
    token = request.headers.get("X-Agent-Token", "")
    if host not in ALLOWED_HOSTS:
        return ("bad host", 400)
    if not hmac.compare_digest(token, load_expected_token()):
        return ("unauthorised", 401)
    return do_privileged_action()
```

**Why this matters:** The defective service authorises on source IP alone, so a rebound hostname that resolves to 127.0.0.1 is trusted exactly like a legitimate local caller; the fixed service rejects any request whose Host is not on its allowlist and requires an authenticated token, so a browser pointing an attacker hostname at the service is refused. The control is Host-header allowlisting plus authentication, not network position.

## When It Is NOT This Issue

- **Service already authenticates:** a local service that requires a credential the attacker page cannot read is not rebindable into trust even if the IP check is weak.
- **Client pins the first resolution:** a fetcher or browser that connects to the initially resolved address for the connection lifetime gives the flip nothing to act on.
- **No re-resolution window:** a target that resolves once and caches for longer than the attack window will not rebind in time.
- **DNS flip without a reached service:** observing the TTL change and the second resolution proves the name rebinds, not that any internal service answered.
- **Host-header allowlist enforced:** the internal service rejects requests whose Host is the attacker name, so the trust decision is not name-based.
- **Egress or segmentation blocks the inward connect:** the internal address is unreachable from the client's network, so the primitive exists but is not exploitable here.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `dns-rebinding-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `dns-rebinding-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: dns-rebinding-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-350 | Mapping: A10:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `dns-rebinding-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-350`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (7), ctf-solver-dataset (2), CYBER_CPT/osv (2), CYBER_CPT/gh_advisories (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
