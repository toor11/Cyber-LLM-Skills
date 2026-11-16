---
name: http-request-smuggling-client-side-desync
description: Client-side desync. Covers browser-triggered desync where a victim's connection is poisoned, including CSD vectors and detection through connection reuse. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["client side desync", "csd", "browser desync"]
cwe: [CWE-444]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-33]
related: [http-request-smuggling, http-request-smuggling-cl-te-and-te-cl, http-request-smuggling-te-te-and-obfuscation, http-request-smuggling-http2-desync]
parent: http-request-smuggling
---

# Http Request Smuggling Client Side Desync - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Client-side desync moves the poisoned connection from between two servers to between a victim's browser and the front end. The attacker finds an endpoint that reads a request body the browser can be scripted to send but that the server either ignores or mishandles while keeping the keep-alive connection open, so leftover bytes remain buffered on that socket. A page under attacker control then makes the victim's browser issue a cross-origin request to the target over that same connection, and the stranded bytes prepend to the victim's next request, steering it to an attacker-chosen path or capturing its headers. The decision point is the server's handling of an unexpected or partially consumed body on a reusable connection, not any application logic, and the attacker gains browser-driven request hijack without a second server tier. Confirmation is that a connection the victim's browser opens behaves as if primed with attacker bytes, reproduced safely against the tester's own browser session.

- **Precondition chain:** An endpoint accepts or tolerates a request body on a method where none is expected and leaves the bytes unconsumed, the server keeps the connection alive after that response, the browser reuses the same connection for the next request, and the tester can observe the resulting prefix on their own session.
- **Readable differential:** A victim-style request on a fresh connection versus the same request on a connection the attacker page primed with an unconsumed body; a finding exists when the primed connection routes or captures the follow-up request differently and reverts once the server closes connections on unexpected bodies.
- **Empirical grounding:** CWE-444. PortSwigger's August 2025 research 'HTTP/1.1 must die: the desync endgame' documents client-side desync, where a browser-issued request poisons a reused connection; SOURCES.md lists no CSD-specific CVE, so the impact stays anchored to that research and CWE-444.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match browser-driven desync **THEN** start at parent class [`http-request-smuggling`](../http-request-smuggling/SKILL.md) first
2. **IF** an endpoint accepts a body on GET or a 404 and leaves it unconsumed **THEN** treat that endpoint as the CSD carrier and test connection reuse first
3. **IF** the server keeps the connection alive after responding to a malformed request **THEN** treat the keep-alive-on-anomaly behaviour as the primary finding
4. **IF** the follow-up request can be steered to an attacker-chosen path **THEN** measure the routing differential on your own browser session before anything else
5. **IF** the desync is actually between two server tiers, not the browser **THEN** switch to [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) for proxy-to-origin framing
6. **IF** the poisoned response is cached and served to others **THEN** also read [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) because the cache widens a single-victim desync
7. **IF** the capture lands as script in the victim's context **THEN** read [`cross-site-scripting`](../cross-site-scripting/SKILL.md) because the impact chains into stored or reflected script
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the server closes the connection on any unexpected body and never reuses it **THEN** STOP and classify as a verified non-finding because the reuse precondition is absent

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The desync is between two server tiers, not the browser | [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) | Invariant is proxy-to-origin framing, not a browser-held connection |
| The poisoned response is cached and served to others | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | Invariant is cache key integrity, which widens a single-victim desync |
| Need parent class methodology | [`http-request-smuggling`](../http-request-smuggling/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find a body-accepting endpoint on an unexpected method.** Look for routes that return a response to a GET or an error path yet still read or tolerate a request body, since the server's handling of those leftover bytes is the carrier.
2. **Confirm the connection survives the anomaly.** Verify the server keeps the keep-alive connection open after responding to the body-bearing request rather than closing it, because reuse is what strands the bytes for the next request.
3. **Confirm the browser will reuse the socket.** Establish that the target is reachable over HTTP/1.1 and that the browser pools and reuses the connection for a follow-up request to the same origin.
4. **Record a fresh-connection baseline.** Issue the victim-style follow-up request on a clean connection and capture its routing and response, so you can see what an unpoisoned request looks like.
5. **Prime the connection and re-issue the follow-up.** On your own browser session, send the body-bearing request so the leftover bytes remain, then make the follow-up request on the same connection and compare its routing or captured content against the baseline.
6. **Stop condition.** Halt when the follow-up either (a) is steered or captured in a way attributable to the stranded bytes and reverting when the server closes the connection, (b) behaves identically to the fresh-connection baseline across two runs, or (c) would require priming a connection held by a real victim rather than your own session. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a reproducible change to the follow-up request on a connection you primed from the browser, tied to the unconsumed body and the server's keep-alive behaviour. A single odd response or a server-to-server timing stall is not client-side desync.
8. **Close with the structural fix.** Make the server close the connection whenever a request carries an unexpected or unconsumed body, read and discard declared bodies fully before reuse, and prefer upgrading the path to HTTP/2 end to end. Verify by replaying the priming sequence against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A GET or 404 endpoint that returns 200 while a request body is present | Proves a body-accepting carrier for CSD on any HTTP/1.1 server that does not reject unexpected bodies |
| The connection staying open after a malformed or body-bearing request | Proves the keep-alive-on-anomaly behaviour that strands bytes for the next request on the same socket |
| A browser follow-up request routed to a path it never requested | Proves the stranded bytes prefixed the victim's request, the defining CSD effect |
| The target reachable only over HTTP/1.1 with connection pooling in the browser | Proves the reuse precondition that CSD needs, absent under HTTP/2 end to end |
| A captured follow-up request body or headers appearing in an attacker-visible response | Proves a credential or header capture rather than mere routing confusion |
| A redirect endpoint that reflects part of the request into the next response | Proves a reflection surface that turns the stranded prefix into stored or visible content |

## Worked Contrast

**Vulnerable pattern:**

```python
# Ignores an unexpected body but keeps the keep-alive connection open
def handle(conn, request):
    if request.method == "GET":
        send(conn, respond(request.path))   # a body, if present, is left unread in the buffer
        return keep_alive(conn)             # leftover bytes now prefix the next request
```

**Hardened pattern:**

```python
def handle(conn, request):
    declared = request.headers.get("Content-Length")
    # A body on a method that should not carry one is an anomaly: do not reuse the socket
    if request.method == "GET" and declared and int(declared) > 0:
        send(conn, respond(400))
        return conn.close()
    send(conn, respond(request.path))
    if request.body_fully_consumed():
        return keep_alive(conn)
    return conn.close()                      # never reuse a connection with unread bytes
```

**Why this matters:** The vulnerable handler leaves an unexpected body buffered and then reuses the socket, so the bytes become a prefix on the victim's next request. The fix closes the connection on any unexpected or partially consumed body, removing the stranded-bytes-plus-reuse combination that client-side desync depends on.

## When It Is NOT This Issue

- **Connection closed on unexpected body:** a server that returns `Connection: close` or drops the socket when a body is unexpected leaves nothing stranded to reuse.
- **HTTP/2 end to end:** when the browser and target negotiate HTTP/2 with no HTTP/1.1 fallback, there is no shared byte-stream connection to poison.
- **Body fully consumed before reuse:** an endpoint that reads and discards the declared body entirely cannot leave a prefix behind.
- **Server-to-server stall:** a timing differential between a proxy and an origin is classic desync, not a browser-held client-side desync.
- **No cross-origin trigger:** if no attacker page can cause the victim's browser to issue the follow-up over the same connection, the chain cannot complete.
- **Observed only with a custom client:** a prefix reproduced with a raw socket tool but never by a real browser connection pool does not demonstrate the client-side variant.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http-request-smuggling-client-side-desync` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http-request-smuggling-client-side-desync` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http-request-smuggling-client-side-desync
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-444 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`http-request-smuggling`](../http-request-smuggling/SKILL.md) - Web and Application (core)
- [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http-request-smuggling-client-side-desync` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-444, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (8), CYBER_CPT/go_exploitdb (2), hackerone_disclosed_reports (1), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
