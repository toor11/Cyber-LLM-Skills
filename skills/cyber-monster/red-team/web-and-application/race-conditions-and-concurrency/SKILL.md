---
name: race-conditions-and-concurrency
description: Exploits time-of-check to time-of-use and concurrency flaws with single-packet attacks, parallel request bursts, partial-construction windows and idempotency gaps. Use when a limit, balance or uniqueness check could be applied after the effect.
family: web-and-application
tier: core
triggers: ["race condition", "toctou", "concurrency", "parallel requests", "single packet attack", "double spend"]
cwe: [CWE-362]
owasp: [A04:2021]
attack: []
capec: [CAPEC-26]
related: [race-conditions-and-concurrency-single-packet-attack, race-conditions-and-concurrency-limit-bypass, sql-injection, cross-site-scripting]
---

# Race Conditions and Concurrency - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A race condition exists when a security decision, such as balance is at least the amount, a coupon is unused, quota remains, or a token is unredeemed, is evaluated and then acted on in separate steps without holding a lock, so overlapping requests all pass the check against the same pre-update state before any commits. Attackers force the window by landing many requests inside the server's processing jitter, using the HTTP/2 single-packet attack to carry many streams in one packet or HTTP/1.1 last-byte synchronization to release withheld bytes together. The security decision is the check-then-act over shared state, and the attacker gains more effect than the limit allows: a double spend, an over-redemption, duplicate accounts, or a limit-one bypass.

- **Precondition chain:** a check and its state mutation are non-atomic over shared storage, the endpoint is reachable concurrently without per-principal serialization, the attacker can align requests inside one processing window, and the committed state can reach an inconsistent value a sequential run could never produce.
- **Readable differential:** run the operation once sequentially versus the same operation fired as a synchronized burst; the finding holds when the stored total after the burst exceeds what one-at-a-time execution allows and returns to the correct ceiling once an atomic datastore guard is added.
- **Empirical grounding:** This maps to CWE-362 and the related CWE-367 time-of-check to time-of-use under OWASP Top 10:2025 A06 Insecure Design; the Shopware voucher race CVE-2025-7954 (non-atomic validation) and the Magento TOCTOU CVE-2025-49558 are current exemplars, with the PortSwigger single-packet attack and the GMO Flatt first-sequence-sync extension as the delivery techniques.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the delivery must land inside one packet window **THEN** switch to [`race-conditions-and-concurrency-single-packet-attack`](../race-conditions-and-concurrency-single-packet-attack/SKILL.md) (1 hop)
2. **IF** the target is a balance, coupon, or quota ceiling **THEN** switch to [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md) (1 hop)
3. **IF** the check-then-act runs over a database row without a lock **THEN** treat SELECT-then-UPDATE as the window and test a synchronized burst against a disposable record
4. **IF** the shared state is a cache counter rather than a database row **THEN** confirm whether the increment is atomic at the cache before assuming a race
5. **IF** the endpoint exposes an idempotency key but does not enforce it **THEN** test whether duplicate keys under concurrency are deduplicated or all processed
6. **IF** a uniqueness rule has no backing unique constraint **THEN** fire concurrent inserts and check for duplicate rows sharing the business key
7. **IF** a multi-step workflow leaves a partially constructed object readable **THEN** race the window between construction and finalization
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the operation already commits under an atomic guard or row lock **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The window is a multi-step workflow partially constructed | [`business-logic-flaws-workflow-and-state`](../business-logic-flaws-workflow-and-state/SKILL.md) | The invariant is state-machine ordering, not a concurrent counter |
| Concurrent requests reuse a one-time OTP or second factor | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | The failure is OTP single-use enforcement under concurrency |
| A limit is accounted per time window rather than per transaction | [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md) | The control is rate accounting, distinct from an atomic commit |
| Target matches `race-conditions-and-concurrency-single-packet-attack` | [`race-conditions-and-concurrency-single-packet-attack`](../race-conditions-and-concurrency-single-packet-attack/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `race-conditions-and-concurrency-limit-bypass` | [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Locate the check-then-act over shared state and classify the target: balance, coupon, quota, uniqueness, or token status.
2. Confirm the two steps are non-atomic by reading the handler for a SELECT-then-UPDATE, a find-then-save, or an exists-then-insert pattern.
3. Record a sequential baseline: run the operation once and note the committed total and status.
4. Fire a synchronized burst of the minimal N using the single-packet attack or last-byte synchronization against a disposable resource.
5. Define the baseline-versus-probe differential: compare the committed total after the burst against the sequential ceiling, looking for an impossible value.
6. Choose the branch from evidence: an overshoot magnitude, duplicate rows, or a negative balance each point at a different broken guard.
7. **Stop condition.** Stop when (a) the committed total reaches an impossible value only under the burst, (b) the exact ceiling holds regardless of alignment, or (c) proceeding would move real money or corrupt production data; (a) is confirmation, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a stored total that ends in a value unreachable by sequential execution, such as a negative balance or more grants than the limit, reverting once an atomic conditional update or unique constraint is added. Close the fix at the datastore, not the application, and re-run the burst to confirm the ceiling holds.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| SELECT-then-UPDATE on a balance without FOR UPDATE | Proves a non-atomic decrement on any relational backend where the read and write are separate statements |
| A find-then-save sequence in an ORM | Proves a time-of-check to time-of-use window on Mongoose, ActiveRecord, or Sequelize |
| An exists() check before insert() with no unique index | Proves missing uniqueness enforcement at the datastore |
| A stored balance going negative after a burst | Proves the ceiling was evaluated against stale state |
| Duplicate rows sharing one business-unique key | Proves the insert race committed more than once |
| Identical success responses for N concurrent redemptions | Proves all requests passed the same pre-update check |

## Worked Contrast

**Vulnerable pattern:**

```python
def redeem_voucher(db, user_id, code):
    voucher = db.execute("SELECT id, uses_left FROM vouchers WHERE code=%s", (code,)).fetchone()
    if voucher and voucher["uses_left"] > 0:
        # Gap: concurrent requests all read uses_left > 0 before any UPDATE lands.
        db.execute("UPDATE vouchers SET uses_left = uses_left - 1 WHERE id=%s", (voucher["id"],))
        grant_discount(db, user_id, code)
        return True
    return False
```

**Hardened pattern:**

```python
def redeem_voucher(db, user_id, code):
    # Single atomic statement: the guard and the decrement commit together.
    row = db.execute(
        "UPDATE vouchers SET uses_left = uses_left - 1 "
        "WHERE code=%s AND uses_left > 0 RETURNING id", (code,)).fetchone()
    if row is None:
        return False
    grant_discount(db, user_id, code)
    return True
```

**Why this matters:** The defect reads uses_left, then updates in a second statement, so overlapping redemptions all see a positive count before any decrement commits. The fix folds the guard into one atomic UPDATE WHERE uses_left > 0 RETURNING, so the database serializes the decrement and only the first request past zero succeeds.

## When It Is NOT This Issue

- **Already atomic:** an operation wrapped in a transaction with a row lock or a single conditional update has no exploitable window.
- **Per-principal serialization:** a queue or lock that serializes a user's requests removes the concurrency.
- **Idempotency key enforced:** a route that deduplicates retries by key will not double-apply under a burst.
- **Self-only effect with no shared total:** a race that changes only the caller's isolated state has no cross-principal impact.
- **Two distinct legitimate resources:** an apparent overshoot that is actually two separate valid grants is not a double.
- **Display lag, not a committed double:** an eventual-consistency read that briefly shows a stale total is not a committed inconsistency.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `race-conditions-and-concurrency` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `race-conditions-and-concurrency` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: race-conditions-and-concurrency
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-362 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`race-conditions-and-concurrency-single-packet-attack`](../race-conditions-and-concurrency-single-packet-attack/SKILL.md) - Web and Application (leaf)
- [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `race-conditions-and-concurrency` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-362`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 47 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (24), hackerone_disclosed_reports (11), cyber-security/security-code (8), SecEval/cwe (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
