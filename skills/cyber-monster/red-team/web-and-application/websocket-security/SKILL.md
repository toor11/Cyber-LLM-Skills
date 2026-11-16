---
name: websocket-security
description: "Tests WebSocket endpoints: missing origin checks, cross-site WebSocket hijacking, authorization applied only at handshake, message-level injection, and rate and size limits. Use when an application uses ws:// or wss:// channels."
family: web-and-application
tier: leaf
triggers: ["websocket", "ws security", "websocket hijacking", "ws origin check", "socket injection"]
cwe: [CWE-1385]
owasp: [API08:2023]
attack: []
capec: [CAPEC-441]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Websocket Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A WebSocket starts life as an HTTP Upgrade request, and the browser attaches the site's cookies to that handshake exactly as it would to any other request. The trust decision has to be made during the handshake: the server must read the Origin header and decide whether this calling site is allowed before it returns 101 Switching Protocols and binds the socket to the user's session. When the handshake accepts any Origin, or the CheckOrigin equivalent simply returns true, a page the attacker controls opens a cross-site socket that inherits the victim's authenticated channel, which is cross-site WebSocket hijacking. Related failures put authorization only at the handshake and never on individual messages, or build a backend query from frame content; proof is a cross-origin connection that succeeds where the control should have refused it.

- **Precondition chain:** The WebSocket authenticates from an ambient cookie, the handshake does not bind acceptance to a validated Origin, and the attacker can predict the connection and message shape so a cross-site page can open and drive the channel.
- **Readable differential:** The handshake is attempted from an allowed Origin versus a foreign Origin carrying the same cookie; a finding exists when the foreign Origin still reaches 101 Switching Protocols, and it closes once the server refuses Origins outside its allowlist.
- **Empirical grounding:** CWE-1385 Missing Origin Validation in WebSockets anchors this slug, evidenced in SOURCES.md by CVE-2025-24964 (Vitest), GHSA-q355-h244-969h (a CheckOrigin that always returned true), GHSA-vg6x-rcgg-rjx6 (Vite dev server), and GHSA-69x6-wcx2-vghp (Traccar), where the handshake upgraded without validating the Origin.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the handshake upgrades without checking Origin and auth is a cookie **THEN** this is the primary cross-site WebSocket hijacking case; establish the cross-origin handshake differential
2. **IF** the origin check or CheckOrigin equivalent always returns true **THEN** treat the always-true stub as the finding and confirm with a foreign Origin header
3. **IF** authorization is enforced only at the handshake and never per message **THEN** open a low-privilege socket then send a privileged message to test message-level authorization
4. **IF** the channel is a GraphQL subscription over WebSocket **THEN** check whether subscription events leak to a cross-site socket
5. **IF** the socket carries a bearer token in the first message rather than a cookie **THEN** a script-set token is not ambient, so re-scope away from cross-site hijacking
6. **IF** frame content is concatenated into a backend query or command **THEN** route the message-level sink to the matching injection skill and test it there
7. **IF** no size or rate cap exists on inbound frames **THEN** note the resource-exhaustion surface separately from the origin-trust finding
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** a foreign Origin is refused at the handshake for every endpoint **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The real sink is SQL built from a frame | [`sql-injection`](../sql-injection/SKILL.md) | Message-level injection is a different invariant than handshake origin trust |
| Auth state is forged cross-site like a form | [`csrf`](../csrf/SKILL.md) | Cross-site hijacking shares the ambient-credential root with CSRF but over a persistent channel |
| The server fetches a URL taken from a frame | [`ssrf`](../ssrf/SKILL.md) | A message-driven server fetch routes to the SSRF fetch-position invariant |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the upgrade handler and read its Origin decision.** Find where the HTTP Upgrade is accepted and whether the code reads the Origin header and compares it to an allowlist before returning 101; this handshake check is the decision point.
2. **Classify the credential model.** Confirm whether the socket is authenticated by an ambient cookie or by a token the client script sets in the first message, because only the ambient model is hijackable cross-site.
3. **Record a same-origin handshake baseline.** Capture the exact Upgrade request the legitimate client sends, including the Origin, cookies, Sec-WebSocket-Key, and any subprotocol, as the shape to reproduce.
4. **Apply the cross-origin differential.** Replay the handshake with a foreign Origin while keeping the session cookie; if the server still returns 101 and the socket receives session-scoped data, the Origin invariant is missing.
5. **Separate handshake trust from message authorization.** If the handshake is gated, open an authorised low-privilege socket and send a message that should require higher privilege to see whether per-message checks exist.
6. **Stop condition.** Halt when the connection either (a) succeeds from a foreign Origin and delivers the victim's session data, (b) is refused identically for every foreign Origin, or (c) would require reading or altering another real user's data to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a handshake from an Origin outside the allowlist that still reaches 101 and binds to the victim's session, evidenced by session-scoped frames arriving on the attacker-opened socket, plus the missing or always-true Origin check; a 101 to a same-origin page is not proof.
8. **Close with the structural fix.** Validate the Origin against an explicit allowlist in the upgrade handler and refuse non-matching Origins before accepting, prefer a per-connection token the page cannot read, and re-authorize sensitive messages. Verify by replaying the foreign-Origin handshake and seeing it refused.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A 101 Switching Protocols returned to a handshake whose Origin is not the app host | Proves the Origin invariant is missing, the defining cross-site WebSocket hijacking condition on any cookie-authenticated channel |
| A CheckOrigin or equivalent callback that unconditionally returns true | Proves the handshake trusts every caller, the exact defect seen in the SOURCES.md komari and Vite advisories |
| Session-scoped events delivered on a socket opened from a foreign page | Proves the hijacked channel inherited the victim's authenticated context, not merely a connection |
| A privileged message accepted on a socket authorized only at handshake | Proves authorization is missing per message on the application tier, a distinct failure from Origin trust |
| A GraphQL subscription frame returning another user's private data cross-site | Proves subscription events leak over the hijacked socket on an Apollo or similar server |
| No Sec-WebSocket-Protocol or token required beyond the session cookie | Proves the credential is purely ambient, which is what makes the handshake forgeable cross-site |
| Unbounded frame size or rate accepted by the server | Proves a resource-exhaustion surface on the socket tier independent of the origin finding |

## Worked Contrast

**Vulnerable pattern:**

```go
// The upgrader accepts the handshake from any site; the browser's session
// cookie rides along, so a cross-origin page inherits the authenticated socket.
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
}

func subscribe(w http.ResponseWriter, r *http.Request) {
    conn, _ := upgrader.Upgrade(w, r, nil)
    stream(conn, r.Context()) // delivers session-scoped events
}
```

**Hardened pattern:**

```go
// The handshake decides trust from the Origin against an allowlist before
// upgrading, so a cross-origin page is refused at 101.
var allowed = map[string]bool{"https://app.example": true}

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return allowed[r.Header.Get("Origin")]
    },
}

func subscribe(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        return // refused Origins never reach the stream
    }
    stream(conn, r.Context())
}
```

**Why this matters:** The defect is an always-true Origin check, so any site can complete the handshake and inherit the ambient cookie. The structural control reads the Origin and compares it to an explicit allowlist before upgrading, so a cross-origin handshake is refused before the socket binds to the session.

## When It Is NOT This Issue

- **Token-authenticated socket:** a channel whose first message carries a bearer token the page sets cannot be opened cross-site without that token, so a missing Origin check is not hijackable.
- **SameSite=Strict session cookie:** if the session cookie is withheld on cross-site requests, the foreign handshake is anonymous and inherits no victim context.
- **Foreign Origin refused at handshake:** a server that returns 403 or closes for an Origin outside its allowlist is enforcing the control, not exhibiting the bug.
- **Read-only public channel:** a socket that streams only public, non-session data to anyone has nothing to hijack even without an Origin check.
- **Local development server on loopback:** a dev server that permits any Origin while bound to localhost in the test scope is an environment artefact, not a production exposure.
- **101 to a same-origin page:** a successful upgrade whose Origin matches the application host is normal operation and is not evidence of cross-site hijacking.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `websocket-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `websocket-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: websocket-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1385 | Mapping: API08:2023]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `websocket-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1385`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 21 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (8), CYBER_CPT/oxdf (5), CYBER_CPT/hacktricks (2), SecEval/owasp_wstg (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
