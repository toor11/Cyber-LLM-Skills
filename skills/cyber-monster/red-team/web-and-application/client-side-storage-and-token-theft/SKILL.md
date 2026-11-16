---
name: client-side-storage-and-token-theft
description: Exploits tokens and sensitive data stored client-side in localStorage, sessionStorage, IndexedDB and non-HttpOnly cookies, and chains them with XSS or physical access. Use when reviewing how a SPA persists authentication state.
family: web-and-application
tier: leaf
triggers: ["localstorage token", "sessionstorage leak", "client storage", "token in javascript"]
cwe: [CWE-922]
owasp: [A02:2021]
attack: []
capec: [CAPEC-37]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Client Side Storage and Token Theft - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This skill reviews where a single-page app persists authentication state and whether that storage is reachable by script or an attacker with the device. Tokens in `localStorage`, `sessionStorage`, or `IndexedDB`, and session values in non-`HttpOnly` cookies, are all readable by any JavaScript running in the origin, so a single cross-site scripting foothold or a malicious bundled dependency exfiltrates them. Unlike an `HttpOnly` cookie, which the script cannot read, web-storage tokens have no browser-enforced boundary, and a long-lived bearer token lifted from storage grants off-device account takeover that survives the victim's logout. The security decision is where the credential lives and how long it is valid; the attacker gains a replayable credential, and confirmation is reading that credential from storage in the victim's origin.

- **Precondition chain:** An authentication token or sensitive value is kept in script-readable storage (web storage, IndexedDB, or a non-HttpOnly cookie), a script-execution or device-access path can read that origin's storage, and the token is accepted elsewhere without binding that defeats replay.
- **Readable differential:** A token held in `HttpOnly`, same-site, short-lived cookies versus the same token placed in `localStorage` or a readable cookie; a finding exists when script in the origin can read and replay it, and it closes once the credential moves to an HttpOnly cookie or is bound against replay.
- **Empirical grounding:** CWE-922 Insecure Storage of Sensitive Information, an OWASP Top 10:2025 A04:2025 Cryptographic Failures concern for credential handling. The 2025 anchor is Intruder's JavaScript-bundle scan of roughly five million applications, which found over 42,000 tokens across 334 secret types (including active code-repository tokens), with a root cause of a build step reading `process.env` wholesale instead of an allowlist.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an authentication token is stored in `localStorage`, `sessionStorage`, or `IndexedDB` **THEN** treat script-readability as the finding surface and plan the HttpOnly-cookie fix
2. **IF** the session cookie lacks `HttpOnly` so script can read `document.cookie` **THEN** record the cookie attributes; the token is exposed to any origin script
3. **IF** reading the stored token requires a script-execution foothold **THEN** chain through [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) to show the realistic read path
4. **IF** the stored credential is a JWT whose claims or signature can be abused once lifted **THEN** route to [`jwt-attacks`](../jwt-attacks/SKILL.md)
5. **IF** the issue is really the cookie's attribute policy (SameSite, Secure, HttpOnly) **THEN** route to [`session-and-token-lifecycle-cookie-attribute-flaws`](../session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md)
6. **IF** a bundled build artifact leaks an API key or token in the shipped JavaScript **THEN** inspect the bundle for secrets baked in from a wholesale `process.env` import
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the token lives only in an HttpOnly, Secure, same-site cookie and is bound against replay **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Reading the token needs script execution in the origin | [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) | Invariant is DOM script injection, the delivery of the read |
| The stored credential is a JWT abusable after theft | [`jwt-attacks`](../jwt-attacks/SKILL.md) | Invariant is token verification, not storage |
| The exposure is a missing HttpOnly or SameSite attribute | [`session-and-token-lifecycle-cookie-attribute-flaws`](../session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md) | Invariant is cookie attribute policy |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory every place the app persists auth state.** Check `localStorage`, `sessionStorage`, `IndexedDB`, cookies (and their `HttpOnly` flag), and the shipped JavaScript bundle for embedded keys. Record what credential each holds and its lifetime.
2. **Classify the exposure.** Script-readable web storage, a non-HttpOnly cookie, an IndexedDB record, or a secret baked into the bundle. Each has a different read path and a different fix.
3. **Establish whether a read path exists.** A storage location is only exploitable if script can run in the origin (a DOM XSS sink, a compromised dependency) or an attacker can reach the device. Note the realistic path rather than assuming one.
4. **Read the credential as an origin script would, in your own session.** Use the console to read the token from storage or `document.cookie` and confirm it is the live bearer credential, not an opaque handle.
5. **Test replayability.** Take the credential from your own session and present it from a separate client; if it authenticates without device, IP, or freshness binding, the stored token is directly replayable.
6. **Stop condition.** Stop when the token either (a) is readable by origin script and replays successfully until it expires, closing once it moves to an HttpOnly cookie or gains replay binding, (b) is unreadable by script because it is HttpOnly and bound, or (c) would require stealing a real user's live token to demonstrate. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is reading the live credential from script-accessible storage in your own origin and replaying it to authenticate, plus the storage location and missing HttpOnly or replay binding. The theoretical presence of XSS elsewhere, without a stored readable credential, is not proof for this skill.
8. **Close with the structural fix and verify.** Move session tokens to `HttpOnly`, `Secure`, `SameSite` cookies, keep access tokens short-lived with server-side revocation, strip secrets from the bundle via an env allowlist, then confirm `localStorage` and `document.cookie` no longer expose a replayable credential.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A bearer or session token present in `localStorage` or `sessionStorage` | Proves the credential is readable by any script in the origin, with no browser boundary |
| A session cookie set without `HttpOnly` | Proves `document.cookie` exposes the session value to injected script |
| A long-lived access token in storage that still works after logout | Proves the token is replayable and outlives the session, raising takeover impact |
| An API key or repository token embedded in the shipped JavaScript bundle | Proves a build-time secret leak, matching the wholesale `process.env` root cause |
| A refresh token in `IndexedDB` reachable from the page origin | Proves durable credential storage exposed to origin script |
| A JWT in storage whose expiry is days away | Proves a wide replay window if the token is lifted |
| Tokens persisted while a DOM XSS sink remains unfixed | Proves storage and injection together form a single takeover chain |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Login stores a long-lived JWT where any origin script can read it
async function onLogin(resp) {
  const { token } = await resp.json();
  localStorage.setItem('access_token', token); // readable by any XSS
}
```

**Hardened pattern:**

```javascript
// Server sets the session as an HttpOnly, Secure, SameSite cookie;
// the browser never exposes it to script
app.post('/login', (req, res) => {
  const token = issueSessionToken(req.user, { ttlSeconds: 900 });
  res.cookie('session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 900000,
  });
  res.json({ ok: true });
});
```

**Why this matters:** The defective client keeps a long-lived bearer token in localStorage, so a single script foothold lifts a replayable credential; the fixed server issues a short-lived session in an HttpOnly cookie the script cannot read, removing both the read path and the long replay window.

## When It Is NOT This Issue

- **HttpOnly cookie:** a session value the script cannot read via `document.cookie` is not exposed by this class even if XSS exists.
- **Opaque handle, not a credential:** a storage value that is a reference the server must resolve, and that does not itself authenticate, is not a stealable token.
- **Replay-bound token:** a token bound to device, IP, or a one-time nonce that fails when presented from another client limits the theft impact.
- **Self-session demonstration only:** reading your own token proves exposure but not cross-user theft; scope the impact honestly.
- **Non-sensitive storage:** UI preferences or feature flags in `localStorage` are not credentials.
- **Bundle string that is a public identifier:** a publishable key or client id designed to be public is not a secret leak.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `client-side-storage-and-token-theft` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `client-side-storage-and-token-theft` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: client-side-storage-and-token-theft
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-922 | Mapping: A02:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `client-side-storage-and-token-theft` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-922`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/go_exploitdb (4), CYBER_CPT/govuln (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
