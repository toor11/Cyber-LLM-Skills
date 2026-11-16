---
name: business-logic-flaws-quota-and-rate
description: Quota, limit and rate logic abuse. Covers bypassing per-user or per-account limits through parallel requests, resets and account multiplication, and exploiting counter resets. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["rate limit bypass", "quota bypass", "limit abuse", "counter reset"]
cwe: [CWE-840]
owasp: [A04:2021]
attack: []
capec: [CAPEC-74]
related: [business-logic-flaws, business-logic-flaws-payment-and-pricing, business-logic-flaws-workflow-and-state, sql-injection]
parent: business-logic-flaws
---

# Business Logic Flaws Quota and Rate - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This variant targets counters and windows: per-user limits, free-tier quotas, invite or referral caps, and sign-up or OTP attempt ceilings. The enforcing code reads a counter, decides, then increments, and the flaw is that the read-decide-increment sequence is not atomic, the counter keys on something the attacker can multiply (a fresh account, a normalised-away email alias, a resettable client id), or the window resets in a way the attacker triggers. An attacker fires a burst of concurrent requests through the validation window, or multiplies the keying principal, so the effective count far exceeds the intended ceiling. The gain is unmetered resource use, free-tier abuse at scale, or brute-force head-room; confirmation is a server-side counter or granted-resource total that exceeds the configured limit.

- **Precondition chain:** A limit is enforced by a non-atomic read-decide-increment or a client-influenced counter key, the attacker can issue requests concurrently or mint fresh keying principals, and the granted total measurably exceeds the configured ceiling.
- **Readable differential:** The limit tested with strictly serial requests versus the same limit tested with a concurrent burst or a multiplied key; a finding exists when the burst grants more than the ceiling and serial requests do not, and it closes once the counter is made atomic or keyed server-side.
- **Empirical grounding:** CWE-840 Business Logic Errors under OWASP Top 10:2025 A06:2025 Insecure Design, overlapping CWE-367 where the check and increment race. The single-packet attack (PortSwigger 'Smashing the state machine' and GMO Flatt 'Beyond the Limit', extending it past 65,535 bytes) is the 2025 technique that lands a burst inside the window; CVE-2025-6015 (HashiCorp Vault login MFA rate-limit bypass, TOTP codes not normalised before the once-per-window check, CWE-307) is a 2025 counter-keying instance.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match quota or rate logic **THEN** start at parent class [`business-logic-flaws`](../business-logic-flaws/SKILL.md) first
2. **IF** a per-user limit is enforced by reading a counter then incrementing it without a lock **THEN** treat the read-decide-increment gap as the sink and verify atomicity
3. **IF** concurrent requests in one burst each pass the same check **THEN** route to [`race-conditions-and-concurrency-single-packet-attack`](../race-conditions-and-concurrency-single-packet-attack/SKILL.md) to land the burst inside the window
4. **IF** the limit being bypassed is an OTP, login, or MFA attempt ceiling **THEN** reclassify toward [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) because the invariant is attempt throttling
5. **IF** the counter key is a client id, email alias, or device token the attacker can mint **THEN** focus on the keying principal: the fix is a server-derived, normalised key
6. **IF** a generic concurrency limit bypass is in scope beyond rate limits **THEN** read [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the counter is atomic and keyed to a server-derived identity and the burst grants no extra **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A burst of concurrent requests each passes the limit check | [`race-conditions-and-concurrency-single-packet-attack`](../race-conditions-and-concurrency-single-packet-attack/SKILL.md) | Invariant is atomic count under a single-packet burst, not per-request validation |
| The bypassed ceiling is an authentication attempt counter | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | Invariant is attempt throttling on a credential, a different impact story |
| Any once-per-window action is multiplied under load | [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md) | Invariant is the lock around the limited action generally |
| Need parent class methodology | [`business-logic-flaws`](../business-logic-flaws/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find the limiter and its counter store.** Identify where the ceiling lives: an in-memory token bucket, a Redis counter, a per-row attempt column, or a database unique constraint. Note what key it increments on and where the read, the decision, and the increment happen.
2. **Classify the bypass class.** Non-atomic read-decide-increment (racey), client-influenced counter key (multipliable), triggerable window reset, or per-node counters behind a load balancer. Each needs a different probe.
3. **Record the serial baseline.** Consume the limit one request at a time and confirm exactly where it refuses: the Nth request returns the limit error and the granted count equals the ceiling.
4. **Fire the concurrency probe inside the window.** Release a small group of identical requests together (single-packet or synchronized) and count how many succeed. More successes than the ceiling implicates the read-decide-increment gap.
5. **Test the keying principal.** Repeat the action under a normalised-equivalent email, a reset client id, or a fresh free-tier account and see whether the counter restarts, which implicates a client-controlled key.
6. **Stop condition.** Stop when the probe either (a) grants more than the configured ceiling and reverts to the ceiling once the counter is made atomic and server-keyed, (b) refuses every request past the limit under both burst and multiplied keys, or (c) would exhaust a shared resource or lock out a real user. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a server-side granted total above the ceiling tied to a specific burst or key, for example twelve successful redemptions of a ten-use quota, plus the code path where the increment trails the decision. A client-side 429 the server never enforced is not proof.
8. **Close with the structural fix and verify.** Make the counter atomic (a single increment-and-compare, a conditional update, or a unique constraint), derive and normalise the key server-side, centralise the limiter across nodes, then replay the burst and the multiplied-key runs to confirm the ceiling holds.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| More successful actions than the ceiling when requests arrive concurrently | Proves a non-atomic read-decide-increment on the limiter under a single-packet burst |
| A counter resetting when an email alias or client id is varied | Proves the limit keys on a client-controlled principal rather than a server identity |
| Per-node 429 behaviour differing across a load-balanced pool | Proves counters are local to each node instead of a shared store |
| A free-tier quota renewed by deleting and recreating an account | Proves account multiplication defeats the quota key |
| An OTP or login attempt count not advancing when codes are replayed unnormalised | Proves the attempt ceiling is bypassable, overlapping the Vault-style CWE-307 defect |
| A window-reset parameter or timestamp accepted from the client | Proves the rate window is attacker-triggerable |
| Token-bucket refill tied to a wall-clock value sent in the request | Proves the refill clock is client-influenced on the throttling layer |

## Worked Contrast

**Vulnerable pattern:**

```python
def redeem_voucher(db, user, code):
    # Read, decide, then increment: two concurrent calls both pass
    used = db.count_redemptions(code)
    if used >= VOUCHER_LIMIT:
        return {'ok': False, 'reason': 'limit reached'}
    grant_credit(db, user, code)
    db.record_redemption(code, user)
    return {'ok': True}
```

**Hardened pattern:**

```python
def redeem_voucher(db, user, code):
    # Atomic conditional update: the database enforces the ceiling once
    rows = db.execute(
        'UPDATE vouchers SET used = used + 1 '
        'WHERE code = %s AND used < %s',
        (code, VOUCHER_LIMIT),
    )
    if rows != 1:
        return {'ok': False, 'reason': 'limit reached'}
    grant_credit(db, user, code)
    return {'ok': True}
```

**Why this matters:** The defective version reads the count, decides, then increments, so a concurrent burst passes the check before any increment lands; the fixed version folds the check and increment into one atomic conditional update, so the database admits exactly the configured number of redemptions under any concurrency.

## When It Is NOT This Issue

- **Atomic counter under load:** if a conditional update or unique constraint collapses the burst to the ceiling, extra concurrent requests fail and there is no bypass.
- **Server-derived key:** a limit keyed to an authenticated server-side identity that ignores client-supplied aliases cannot be multiplied.
- **Soft advisory limit by design:** a rate header the product documents as best-effort, with a hard limit enforced downstream, is not the finding.
- **Self-inflicted throttling:** consuming your own quota faster affects only your account and grants nothing beyond the ceiling.
- **Single-node test artefact:** a counter that looks local in a one-node test environment but is shared in production is not exploitable as deployed.
- **Window reset that still nets zero:** a resettable window that re-locks before any extra action completes grants no additional resource.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `business-logic-flaws-quota-and-rate` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `business-logic-flaws-quota-and-rate` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: business-logic-flaws-quota-and-rate
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-840 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`business-logic-flaws`](../business-logic-flaws/SKILL.md) - Web and Application (core)
- [`business-logic-flaws-payment-and-pricing`](../business-logic-flaws-payment-and-pricing/SKILL.md) - Web and Application (leaf)
- [`business-logic-flaws-workflow-and-state`](../business-logic-flaws-workflow-and-state/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `business-logic-flaws-quota-and-rate` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-840`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/osv (3), CYBER_CPT/gh_advisories (2), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
