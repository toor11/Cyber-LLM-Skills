---
name: business-logic-flaws-payment-and-pricing
description: Payment and pricing logic flaws. Covers price and currency tampering, negative and fractional amounts, coupon and discount stacking, refund abuse and gateway callback trust. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["price manipulation", "payment bypass", "discount abuse", "refund abuse"]
cwe: [CWE-840]
owasp: [A04:2021]
attack: []
capec: [CAPEC-74]
related: [business-logic-flaws, business-logic-flaws-workflow-and-state, business-logic-flaws-quota-and-rate, sql-injection]
parent: business-logic-flaws
---

# Business Logic Flaws Payment and Pricing - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This variant targets the invariants that keep a charge correct: the price comes from the catalogue not the request, the currency and its minor-unit scaling are fixed server-side, discounts and store credit cannot exceed the subtotal, and a refund can never return more than was captured. The decision point is the quote-and-settle code, where a value that should be derived (unit price, tax, currency multiplier) is instead read from a client field or a gateway callback the attacker can replay or forge. The attacker gains free or discounted goods, negative totals that become store credit, or refunds of money never paid. Confirmation is a persisted change in the authoritative amount on the invoice, wallet, or ledger, not a cosmetic total in the cart preview.

- **Precondition chain:** A price, currency, discount, or refund amount is taken from the request or an unverified gateway callback rather than derived server-side, the settlement path trusts that value, and the resulting charge or credit moves real money in the attacker's favour.
- **Readable differential:** The quote or settlement produced with catalogue-derived amounts versus the same operation with a client-forced price, extra coupon, or oversized refund; a finding exists when the authoritative charge or credit changes and reverts once the server recomputes the amount itself.
- **Empirical grounding:** CWE-840 Business Logic Errors under OWASP Top 10:2025 A06:2025 Insecure Design. CVE-2025-7954 (Shopware voucher redemption with non-atomic validation) is a 2025 payment-logic instance where discount validation held per request but broke under concurrent redemption.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match payment and pricing logic **THEN** start at parent class [`business-logic-flaws`](../business-logic-flaws/SKILL.md) first
2. **IF** a price, tax, or total is submitted in the request body and the server does not recompute it **THEN** treat the price field as the sink and drive the recompute-server-side fix
3. **IF** a coupon or store-credit redemption can be issued concurrently past its per-code limit **THEN** route to [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md) because the invariant is atomic redemption
4. **IF** a hidden price or discount field is accepted by the model binder **THEN** model it as mass assignment and read [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md)
5. **IF** a refund or order can be acted on by referencing another buyer's order id **THEN** reclassify as object-level access and read [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md)
6. **IF** the amount manipulation only changes a currency minor-unit or rounding edge **THEN** confirm the scaling invariant server-side before claiming revenue impact
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the catalogue price is recomputed and the gateway callback signature is verified server-side **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Coupon redeemed concurrently beyond its issued count | [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md) | Invariant is atomic redemption under load, not the discount value itself |
| Price or discount arrives as an extra bound field | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Invariant is field authority: price must not be client-writable |
| Refund targets an order id owned by another buyer | [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) | Invariant is per-object ownership, an access-control check |
| Need parent class methodology | [`business-logic-flaws`](../business-logic-flaws/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the quote-and-settle boundary and label every amount.** For each of unit price, line total, tax, shipping, currency multiplier, discount, and refund, decide whether the server derives it from the catalogue or reads it from the request or a gateway callback. Request-sourced amounts are the sinks.
2. **Classify the money defect.** Price substitution, negative or fractional amount, currency or minor-unit confusion, coupon or credit over-application, or refund exceeding capture. Each breaks a different accounting invariant.
3. **Record a catalogue-derived baseline.** Build a quote the normal way and capture the authoritative amount, currency, and any applied discount from the server response, not the cart display.
4. **Force one amount and re-read the authoritative quote.** Substitute a lower unit price, a negative amount, a duplicated coupon, or a mismatched currency, and compare the server's computed charge. Use a disposable cart so nothing settles.
5. **Test the gateway callback trust separately.** Check whether the paid or authorised status is accepted from a client-reachable webhook without verifying the provider signature or the captured amount against the order.
6. **Stop condition.** Stop when the forced amount either (a) changes the authoritative charge, credit, or paid status and reverts once the server recomputes from the catalogue and verifies the callback, (b) is overwritten by server recomputation in every form, or (c) would require capturing a real card or issuing a real refund. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a persisted change in an authoritative amount: a settled order total below the catalogue price, a wallet credit from a negative line, or a refund larger than the capture, tied to the exact client field or unsigned callback that produced it. A discounted cart preview the invoice corrects is not proof.
8. **Close with the structural fix and verify.** Derive every price and tax server-side from the catalogue, cap discounts and credits at the subtotal, bind currency and minor-unit scaling server-side, verify the gateway signature and captured amount before marking paid, then replay the baseline and the forced-amount run.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `unitPrice`, `amount`, or `total` present in the checkout request body | Proves the charge is client-authoritative on the settle endpoint rather than catalogue-derived |
| A negative line amount producing a positive wallet or store-credit balance | Proves a missing lower bound on the ledger posting, converting a purchase into a credit |
| Currency code or minor-unit multiplier taken from the request | Proves a scaling-confusion path where an amount settles in the wrong currency scale |
| The same coupon code reducing the total more than once | Proves the discount set-uniqueness invariant is unenforced on the cart aggregate |
| Order status set to paid without a verified gateway signature | Proves the callback is trusted, so payment can be asserted without a capture |
| A refund amount not reconciled against the original captured amount | Proves the refund-to-capture invariant is missing on the payment record |
| Rounding that favours the buyer repeated across many line items | Proves a cumulative minor-unit rounding gap in the pricing engine |

## Worked Contrast

**Vulnerable pattern:**

```python
def settle_order(req, catalog):
    # Trusts the client-sent price and total instead of deriving them
    unit = int(req.form['unit_price_cents'])
    qty = int(req.form['quantity'])
    total = int(req.form['total_cents'])
    charge(card=req.form['card_token'], amount_cents=total)
    return {'status': 'paid', 'unit': unit, 'qty': qty, 'total': total}
```

**Hardened pattern:**

```python
def settle_order(req, catalog):
    # Derive every amount server-side from the catalogue; cap discount at subtotal
    item = catalog.get(req.form['sku'])
    if item is None:
        raise ValueError('unknown sku')
    qty = max(1, int(req.form['quantity']))
    subtotal = item.unit_price_cents * qty
    discount = min(resolve_discount(req.form.get('coupon')), subtotal)
    total = subtotal - discount
    charge(card=req.form['card_token'], amount_cents=total)
    return {'status': 'paid', 'total': total}
```

**Why this matters:** The defective handler charges a client-supplied total, so any buyer can set the price; the fixed handler derives the unit price from the catalogue, bounds quantity and discount, and charges the recomputed total, making price a server-authoritative value.

## When It Is NOT This Issue

- **Invoice recomputes from catalogue:** a forced price the settlement step overwrites before capture never reaches the ledger and is not a finding.
- **Signed and amount-checked callback:** if the gateway webhook signature and captured amount are verified server-side, a replayed callback changes nothing.
- **Discount within promotion rules:** stacking the business deliberately permits, or a credit capped at subtotal, is intended behaviour.
- **Self-only draft cart:** amount changes visible only in your own unsettled cart preview, with no capture or credit, are cosmetic.
- **Rounding neutral at settlement:** a minor-unit rounding difference the accounting posting reconciles to zero has no revenue impact.
- **Negative amount clamped by ledger constraint:** an API that accepts a negative line but is blocked by a non-negative accounting rule is not exploitable.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `business-logic-flaws-payment-and-pricing` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `business-logic-flaws-payment-and-pricing` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: business-logic-flaws-payment-and-pricing
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-840 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`business-logic-flaws`](../business-logic-flaws/SKILL.md) - Web and Application (core)
- [`business-logic-flaws-workflow-and-state`](../business-logic-flaws-workflow-and-state/SKILL.md) - Web and Application (leaf)
- [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `business-logic-flaws-payment-and-pricing` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-840`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/go_exploitdb (3), OffsecCyber (2), SecEval/owasp_wstg (1), bug-bounty-pentest-en (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
