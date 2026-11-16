---
name: race-conditions-and-concurrency-limit-bypass
description: Race-based limit and balance bypass. Covers double spending, coupon and gift-card reuse, vote and follow inflation, and one-time-token reuse through concurrency. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["race limit bypass", "double spend", "token reuse race"]
cwe: [CWE-362]
owasp: [A04:2021]
attack: []
capec: [CAPEC-26]
related: [race-conditions-and-concurrency, race-conditions-and-concurrency-single-packet-attack, sql-injection, cross-site-scripting]
parent: race-conditions-and-concurrency
corpus_sparse: true
---

# Race Conditions and Concurrency Limit Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

The business-target variant races a time-of-check to time-of-use window around a limited-resource ceiling: a wallet balance, a gift-card or coupon redemption count, a one-vote or one-follow rule, a referral bonus, or a one-time token. The server validates the remaining quota and applies the effect in two steps, so concurrent requests each read the same remaining count and all commit, pushing the ledger past its ceiling. The security decision is the uniqueness or balance guard that runs before, not within, the mutating write. The attacker gains free value: duplicate discounts, double-spent balance, inflated counts, or a reused single-use token.

- **Precondition chain:** a limited resource is guarded by a read-then-write that is not atomic, the same principal can submit overlapping requests, the ledger stores a cumulative total that can be pushed past its ceiling, and no unique constraint or conditional update enforces the limit at commit.
- **Readable differential:** redeem once sequentially versus firing the redemption as a synchronized burst against a test credit; the bypass is proven when the balance or count exceeds the allowed ceiling or a one-use token redeems twice, and it is blocked once an atomic conditional update or unique index is enforced.
- **Empirical grounding:** This maps to CWE-362 under OWASP Top 10:2025 A06; the Shopware voucher race CVE-2025-7954 (non-atomic voucher validation, fixed 6.6.10.4) is the direct exemplar, and OTP-reuse races appear in the Vault MFA CVE-2025-6015 (TOTP not normalized before the once-per-window check) and the Weblate second-factor race GHSA-57jg-m997-cx3q.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to be a limited-resource ceiling **THEN** start at parent class [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) (1 hop) to confirm a non-atomic guard
2. **IF** the ceiling is a wallet or account balance **THEN** race a withdrawal or transfer against a small test balance and check for a negative committed value
3. **IF** the ceiling is a coupon or gift-card redemption count **THEN** fire concurrent claims of one test code and count the grants committed
4. **IF** the rule is one vote, follow, or like per user **THEN** race concurrent actions and check for multiple counted events from one principal
5. **IF** the guard is a one-time OTP or token status flip **THEN** switch to [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) (1 hop) for the single-use enforcement angle
6. **IF** the ceiling is a per-account referral or signup bonus **THEN** race the bonus grant against a disposable account to test duplicate payouts
7. **IF** uniqueness is enforced only by an application exists() check **THEN** fire concurrent inserts and look for duplicate rows sharing the key
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the ceiling holds under a burst because the commit is atomic **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The raced guard is a one-time OTP or second factor | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | The invariant is single-use authentication enforcement, not a balance ledger |
| The bypass changes the price or payment amount | [`business-logic-flaws-payment-and-pricing`](../business-logic-flaws-payment-and-pricing/SKILL.md) | The control is pricing integrity rather than concurrency on a counter |
| The limit is accounted per time window | [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md) | Rate accounting is a different control than an atomic per-transaction commit |
| Need parent class methodology | [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Identify the limited resource and its declared ceiling, and set up a disposable test credit, coupon, or token within scope.
2. Locate the guard, a balance check, a uses_left read, a missing UNIQUE, or a token status, and confirm the write is a separate statement.
3. Record a sequential baseline redemption and note the committed ledger value and the remaining count.
4. Fire a synchronized burst of the minimal N against the test asset using the single-packet attack or last-byte synchronization.
5. Define the baseline-versus-probe differential: compare the committed ledger after the burst against the ceiling, looking for an overshoot or a double redeem.
6. Choose the branch from evidence: a balance below zero, a count above the ceiling, or a token redeemed twice each name a distinct broken guard.
7. **Stop condition.** Stop when (a) the ledger on the test asset exceeds its ceiling under the burst, (b) the ceiling holds regardless of alignment, or (c) proceeding would spend real funds or real stock; (a) is confirmation, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a committed total past the ceiling on a test resource, such as a negative test balance or more credits than the coupon allows, reverting under an atomic conditional update or unique index. Close the fix with an atomic UPDATE WHERE remaining > 0, a unique redemption index, or a status compare-and-set, then re-run the burst.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| uses_left > 0 checked before a separate decrement UPDATE | Proves a non-atomic coupon guard where concurrent redemptions read the same positive count |
| A balance read then debited in two statements | Proves a double-spend window on the wallet ledger |
| Absence of a UNIQUE on (token, status) or (user, code) | Proves missing datastore uniqueness that a race can violate |
| A vote or follow counter incremented without a per-user unique row | Proves count inflation under concurrency on any shared counter |
| An OTP compared before a status flip | Proves a reuse window on the authentication path |
| A test credit ending above its cap after a burst | Proves the ceiling bypass on a disposable resource |

## Worked Contrast

**Vulnerable pattern:**

```python
def claim_gift_card(card_code, user):
    card = GiftCard.objects.get(code=card_code)
    if not card.redeemed:                 # check
        apply_credit(user, card.amount)
        card.redeemed = True              # act, as a separate write
        card.save()
        return "credited"
    return "already used"
```

**Hardened pattern:**

```python
from django.db import transaction

def claim_gift_card(card_code, user):
    with transaction.atomic():
        # Atomic conditional flip: only one request transitions redeemed False to True.
        updated = GiftCard.objects.filter(code=card_code, redeemed=False).update(redeemed=True)
        if updated == 0:
            return "already used"
        apply_credit(user, GiftCard.objects.get(code=card_code).amount)
        return "credited"
```

**Why this matters:** The defect reads redeemed, then saves True in a later statement, so concurrent claims all see redeemed False and each credits the account. The fix performs a single conditional UPDATE WHERE redeemed False, so the database admits exactly one winner and every other concurrent claim sees zero rows updated.

## When It Is NOT This Issue

- **Atomic conditional update present:** a single UPDATE WHERE remaining > 0 admits one winner and is not raceable.
- **Unique constraint rejects the duplicate:** a backing unique index turns the second concurrent insert into an error.
- **Per-user queue serializes claims:** serialized processing removes the concurrency the bypass needs.
- **Idempotency key dedupes:** a route that keys redemptions will not double-credit under a burst.
- **Two distinct valid cards:** apparent duplicate credits that are really two separate codes are not a bypass.
- **Display lag, not a committed balance:** a briefly stale balance read is not a committed overshoot.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `race-conditions-and-concurrency-limit-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `race-conditions-and-concurrency-limit-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: race-conditions-and-concurrency-limit-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-362 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) - Web and Application (core)
- [`race-conditions-and-concurrency-single-packet-attack`](../race-conditions-and-concurrency-single-packet-attack/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `race-conditions-and-concurrency-limit-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-362`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
