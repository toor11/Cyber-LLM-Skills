---
name: clickjacking-and-ui-redressing
description: "Tests framing protections and UI redressing: missing X-Frame-Options and frame-ancestors, double and triple framing, drag-and-drop and cursorjacking variants. Use when assessing whether sensitive actions can be embedded."
family: web-and-application
tier: leaf
triggers: ["clickjacking", "ui redressing", "framing", "x-frame-options", "frame ancestor", "cursorjacking"]
cwe: [CWE-1021]
owasp: [A04:2021]
attack: []
capec: [CAPEC-103]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Clickjacking and Ui Redressing - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Framing attacks exploit the browser's willingness to render one origin's authenticated page inside another origin's document and composite them visually. The victim interacts with what looks like the attacker's page while their click, drag, or keystroke actually lands on the framed target, which carries the victim's ambient session. The defence is a server-sent instruction the browser enforces: `X-Frame-Options` or, in modern terms, a CSP `frame-ancestors` directive restricting who may embed the page. The 2025 fork is DoubleClickjacking: instead of a hidden iframe it uses a rapid double-click sequence against a top-level window it opened, so the sensitive control is clicked after a window swap, which sidesteps `X-Frame-Options`, `frame-ancestors`, and even `SameSite` cookies because nothing is framed and the final click is a genuine top-level same-site action.

- **Precondition chain:** A sensitive state-changing control is reachable in an authenticated session, the page can be embedded (no `frame-ancestors` or `X-Frame-Options`) or driven as a top-level window, and the action completes on a single gesture without a confirmation that re-reads intent.
- **Readable differential:** Loading the target in a cross-origin frame (or a double-click window-swap sequence) versus loading it top-level; a finding exists when the sensitive action can be triggered through the framed or swapped context, and it closes once framing is denied and the control is gesture-gated.
- **Empirical grounding:** CWE-1021 Improper Restriction of Rendered UI Layers or Frames. The 2025 anchor is DoubleClickjacking (Paulos Yibelo, Dec 2024 / Jan 2025), which bypasses `X-Frame-Options`, CSP `frame-ancestors`, and `SameSite` by acting on a top-level window; its mitigation is disabling sensitive controls until an explicit user gesture.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target page sets no `X-Frame-Options` and no CSP `frame-ancestors`, and a sensitive control sits on it **THEN** this is the classic case; build the cross-origin frame differential before anything else
2. **IF** framing headers are present but the sensitive action completes on a single click of a top-level window **THEN** test the DoubleClickjacking fork: a double-click window-swap bypasses `frame-ancestors` and `SameSite`
3. **IF** the action is drag-initiated or relies on cursor position **THEN** assess the drag-and-drop and cursorjacking variants separately from a plain overlay
4. **IF** the framing protection lives only in a meta tag or a client-side frame-buster script **THEN** treat it as bypassable; only a server-sent header or `frame-ancestors` counts
5. **IF** the same sensitive action is also reachable by a scripted cross-site request without any frame **THEN** compare against request forgery via [`csrf`](../csrf/SKILL.md) to pick the real invariant
6. **IF** the missing control is a broader security-header gap across responses **THEN** route to [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md)
7. **IF** the cross-origin interaction is really a WebSocket handshake without Origin checks **THEN** route to [`websocket-security`](../websocket-security/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the page denies framing and every sensitive control requires an explicit gesture or confirmation **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Framing headers missing as part of a broader header policy gap | [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) | Invariant is the response security-header policy, broader than framing alone |
| The cross-origin interaction is a WebSocket with no Origin check | [`websocket-security`](../websocket-security/SKILL.md) | Invariant is server-side Origin validation on the handshake |
| A cross-origin page reads responses via permissive CORS | [`cors-misconfiguration`](../cors-misconfiguration/SKILL.md) | Invariant is credentialed cross-origin read policy, not UI layering |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the sensitive control and the framing policy on its response.** Read the actual response headers for the page hosting the control: is there `X-Frame-Options`, a CSP `frame-ancestors`, and does the control change state on one gesture? The decision lives in those headers, not the page HTML.
2. **Classify the framing exposure.** Fully framable (no headers), header-protected but single-gesture (a DoubleClickjacking candidate), drag or cursor dependent, or protected only by a client-side frame-buster. Each branch has a different test.
3. **Confirm the headers are browser-enforced, not cosmetic.** A meta frame directive or a JavaScript top-versus-self buster is not a real control; verify whether a real browser renders the page inside a cross-origin frame.
4. **Record the top-level baseline.** Perform the sensitive action normally and capture the resulting state change, so you know what a successful hijack must reproduce through the framed or swapped context.
5. **Build the framing differential.** For the classic case, load the target in a cross-origin iframe and confirm it renders and receives a click; for the DoubleClickjacking fork, use a double-click sequence that swaps focus to a top-level target window just before the second click lands on the control.
6. **Stop condition.** Stop when the attempt either (a) drives the sensitive action through the framed or window-swapped context against your own session and is prevented once framing is denied and the control is gesture-gated, (b) is blocked because the browser refuses to frame and no top-level swap reaches the control, or (c) would require tricking a real user into clicking. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is the sensitive state change occurring from a cross-origin frame or a double-click window-swap in your own authenticated session, plus the missing `frame-ancestors` or `X-Frame-Options` header or the absent gesture gate. A page that merely renders in a frame but exposes no state-changing control is not proof.
8. **Rule out the non-framing path.** Confirm the action genuinely needs the UI-redress trick and is not simply forgeable by a cross-site request, which would make it a request-forgery finding instead.
9. **Close with the structural fix and verify.** Send `frame-ancestors 'none'` (or an explicit allowlist) plus `X-Frame-Options: DENY`, and gesture-gate sensitive controls so they require an explicit confirmation the DoubleClickjacking sequence cannot satisfy, then re-run the frame and double-click probes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A response lacking both `X-Frame-Options` and CSP `frame-ancestors` | Proves the page is embeddable cross-origin, the precondition for an overlay hijack |
| Framing denied by headers yet a sensitive control fires on a single top-level click | Proves a DoubleClickjacking window-swap can reach it despite framing and `SameSite` |
| A client-side top-versus-self frame-buster with no server header | Proves the protection is script-level and can be neutralised by sandboxing the frame |
| A meta http-equiv framing directive instead of a real response header | Proves the control is cosmetic because browsers enforce framing only from headers |
| A state-changing action with no confirmation or gesture gate | Proves the control is hijack-completable in one composited interaction |
| `frame-ancestors` present but set to a permissive wildcard or a stale origin | Proves the embed allowlist is ineffective for the current threat |
| Drag-to-confirm or cursor-position-dependent controls | Proves a drag-and-drop or cursorjacking variant rather than a plain click overlay |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Sensitive action served framable and completed on a single click
app.post('/account/delete', requireSession, (req, res) => {
  deleteAccount(req.session.userId);
  res.json({ deleted: true });
});
// No frame-ancestors, no X-Frame-Options, no gesture gate
```

**Hardened pattern:**

```javascript
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// Gesture-gate the action with a fresh, server-issued confirmation token
// that a double-click window-swap cannot pre-supply
app.post('/account/delete', requireSession, (req, res) => {
  if (!consumeConfirmToken(req.session, req.body.confirm_token)) {
    return res.status(428).json({ error: 'explicit confirmation required' });
  }
  deleteAccount(req.session.userId);
  res.json({ deleted: true });
});
```

**Why this matters:** The defective route can be framed and fires on one click, so an overlay or a DoubleClickjacking window-swap triggers deletion; the fixed route denies framing and gates the action behind a fresh confirmation token the attacker cannot pre-supply, which is the mitigation for the top-level double-click fork that defeats framing headers alone.

## When It Is NOT This Issue

- **No state-changing control on the framable page:** a read-only page that frames is not clickjackable; impact needs a sensitive action.
- **Gesture-gated control:** an action requiring an explicit confirmation the overlay cannot pre-supply (re-type, drag-to-slot) defeats the hijack even if the page frames.
- **SameSite=Strict with no top-level swap path:** a framed POST that carries no cookie and cannot be reached by a window-swap has no victim context.
- **Header present and enforced:** `frame-ancestors 'none'` or `X-Frame-Options: DENY` a real browser honours closes the classic case.
- **Self-framing only:** demonstrating the page in your own frame without a victim-driven action is a rendering note, not a finding.
- **Login or public form with no privileged effect:** framing a page whose only action is anonymous has no cross-user consequence.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `clickjacking-and-ui-redressing` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `clickjacking-and-ui-redressing` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: clickjacking-and-ui-redressing
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1021 | Mapping: A04:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `clickjacking-and-ui-redressing` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1021`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 56 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (30), securecode-web (17), SecEval/mozilla_security (4), SecEval/owasp_wstg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
