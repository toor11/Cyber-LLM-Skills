---
name: business-logic-flaws
description: "Exploits flawed application rules: negative quantities and price manipulation, coupon and discount abuse, workflow and state-machine bypass, currency or rounding tricks, and rate and quota gaps. Use when testing commerce, booking, billing or multi-step processes."
family: web-and-application
tier: core
triggers: ["business logic", "logic flaw", "price manipulation", "coupon abuse", "workflow bypass", "business logic vulnerability"]
cwe: [CWE-840]
owasp: [A04:2021]
attack: []
capec: [CAPEC-74]
related: [business-logic-flaws-payment-and-pricing, business-logic-flaws-workflow-and-state, business-logic-flaws-quota-and-rate, sql-injection]
---

# Business Logic Flaws - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Business logic flaws arise when the application faithfully executes each individual request yet never enforces the invariant that ties a sequence of requests to an intended economic or access outcome; the server trusts a value, an ordering, or a count that only the happy-path UI would ever produce. The security decision lives in application code, not in a parser or a framework filter, so no amount of input escaping detects it. An attacker supplies values the interface cannot generate (a negative quantity, a coupon applied twice, a step reached out of order) or issues requests at a tempo the rule assumed was impossible. The gain is money, free goods, elevated entitlement, or a state the business considered unreachable, and confirmation is always a before-and-after change in a server-side total, balance, or status rather than a reflected string.

- **Precondition chain:** A rule that spans more than one field or request is enforced only in the client or implicitly, the server re-accepts a value or ordering it should have derived itself, and the resulting change moves money, entitlement, or state in the attacker's favour.
- **Readable differential:** The same operation performed the way the UI intends versus the same operation with one rule-breaking value or ordering; a finding exists when the rule-breaking run changes the server-side total or status, and the change disappears once the server derives that value itself.
- **Empirical grounding:** CWE-840 Business Logic Errors, filed under OWASP Top 10:2025 A06:2025 Insecure Design. CVE-2025-7954 (Shopware voucher redemption, non-atomic validation) and CVE-2025-49558 (Magento TOCTOU, CWE-367) are 2025 instances where a business rule held for a single request but broke under concurrency or re-validation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves payment, pricing, currency, or refund logic **THEN** switch to [`business-logic-flaws-payment-and-pricing`](../business-logic-flaws-payment-and-pricing/SKILL.md) (1 hop)
2. **IF** the target specifically involves workflow ordering or state-machine transitions **THEN** switch to [`business-logic-flaws-workflow-and-state`](../business-logic-flaws-workflow-and-state/SKILL.md) (1 hop)
3. **IF** the target specifically involves per-user limits, quotas, or counter resets **THEN** switch to [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md) (1 hop)
4. **IF** the rule depends on timing and two concurrent requests both pass a check that should admit one **THEN** treat it as a concurrency defect and route to [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md)
5. **IF** a hidden or extra field such as role, price, or status is accepted by a mass-assignment binder **THEN** model it as parameter tampering and read [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md)
6. **IF** the abuse is really reaching another principal's object by changing an identifier **THEN** reclassify as access control and read [`authorization-and-idor`](../authorization-and-idor/SKILL.md)
7. **IF** the broken rule is enforced only in client-side JavaScript or a disabled form control **THEN** confirm server-side first; the fix is server authority, not stricter UI
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** no server-side total, balance, entitlement, or status changes when the rule is broken **THEN** STOP and record a verified non-finding rather than reporting an odd-but-harmless response

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Rule holds for one request but two concurrent requests both pass | [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) | Invariant is atomicity under concurrency, not input value validation |
| Client submits a field the server should have derived (price, role, status) | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Invariant is which fields are server-authoritative, a binding problem |
| Breaking the rule only reaches the caller's own resource until an id is swapped | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Invariant is per-object ownership, an access-control decision |
| Target matches `business-logic-flaws-payment-and-pricing` | [`business-logic-flaws-payment-and-pricing`](../business-logic-flaws-payment-and-pricing/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `business-logic-flaws-workflow-and-state` | [`business-logic-flaws-workflow-and-state`](../business-logic-flaws-workflow-and-state/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `business-logic-flaws-quota-and-rate` | [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Draw the intended state and money flow before touching any field.** List every server-side invariant the feature assumes: totals equal price times quantity, a coupon applies once, a status only advances, a balance never goes negative. The finding is a broken invariant, so you must name it first.
2. **Locate where each invariant is actually enforced.** Separate values the server derives (should be trustworthy) from values the client submits and the server re-accepts (candidate sinks). A rule enforced only in the browser or implied by UI flow is already a candidate.
3. **Classify the break class from the feature shape.** Numeric manipulation (negative, fractional, overflow), set abuse (coupon or credit reused), ordering (a step reached without its precondition), or tempo (two requests racing one check). This routing decides the child skill.
4. **Capture an intended-path baseline.** Run the operation exactly as the UI would and record the authoritative outcome: order total, wallet balance, entitlement flag, or workflow status. This is the value a probe must move.
5. **Apply one rule-breaking change and compare the authoritative outcome.** Change a single field, count, or ordering the interface could never produce, and read the same server-side total or status. A changed reflected message with an unchanged balance is not the finding.
6. **Stop condition.** Halt when the rule-breaking run either (a) moves a server-side total, balance, entitlement, or status in your favour and reverts when the server derives the value itself, (b) leaves every authoritative value unchanged across two baselines, or (c) would require consuming real inventory, charging a real card, or altering another user's records. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a persisted before-and-after difference in an authoritative value tied to one changed variable, plus the server code line that accepted the client value or skipped the ordering check. A 200 response, a UI glitch, or a discount that the final invoice recomputes away is not proof.
8. **Prove impact is beyond your own scope.** Show the change affects revenue, another principal, or a state the business treats as terminal, not just your own throwaway session.
9. **Close with the structural fix and verify it.** Make the server derive the value or enforce the ordering and count authoritatively (recompute price server-side, make redemption atomic, guard transitions by current state), then replay the intended-path baseline and the rule-breaking run to confirm only the first still succeeds.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A total, tax, or discount accepted from the request body instead of recomputed | Proves the price invariant is client-authoritative on the checkout endpoint, so the server trusts a value it should derive |
| A negative, zero, or fractional quantity accepted without a floor | Proves missing domain bounds on the order or transfer handler, turning a purchase into a credit |
| A workflow status field or step token submitted by the client | Proves the state machine trusts caller-supplied state rather than the current server record |
| Two concurrent redemptions of a once-only coupon both succeeding | Proves non-atomic validation of the redemption count, a TOCTOU window at the business layer |
| A coupon or credit field that stacks when sent more than once | Proves the set-uniqueness rule is not enforced server-side on the cart aggregate |
| A refund or cancellation that credits more than the captured amount | Proves the refund invariant is unbound to the original payment record |
| A read-only entitlement or role flag the client can echo back on a write | Proves a derived field is treated as writable, a mass-assignment style trust gap |

## Worked Contrast

**Vulnerable Pattern (express - checkout input validation):**

```javascript
app.post('/orders', (req, res) => {
  const { productId, quantity, unitPriceCents } = req.body || {};
  const product = catalog.get(productId);
  if (!product || !product.active) return res.status(404).json({ error: 'product unavailable' });

  // Vulnerable: caller-controlled price and JavaScript numeric coercion.
  const price = unitPriceCents ?? product.unitPriceCents;
  const totalCents = quantity * price;
  return res.status(201).json({ productId, quantity, unitPriceCents: price, totalCents });
});

app.use((err, req, res, next) => {
```

**Fixed / Hardened Pattern (express - checkout input validation):**

```javascript
app.post('/orders', (req, res) => {
  const result = quoteOrder(req.body);
  if (result.error) return res.status(result.status).json({ error: result.error });
  return res.status(201).json(result.order);
});

app.use((err, req, res, next) => {
```

**Why this matters:** A caller can set an order total below the catalog price or create a negative total, risking direct revenue loss if downstream checkout trusts it.

## When It Is NOT This Issue

- **Final invoice recomputes the value:** a tampered price or total that the server overwrites before settlement is cosmetic; only a persisted authoritative change counts.
- **Self-only sandbox effect:** a manipulation that alters only your own cart preview or draft, with no charge, inventory, or cross-user impact, is a UI quirk, not a logic flaw.
- **Rule enforced server-side, blocked only in UI as convenience:** if the server already rejects the out-of-bounds value, the missing client check is a usability note, not a finding.
- **Discount within an authorised promotion:** a stackable coupon the business intentionally allows to stack is expected behaviour; confirm the intended rule before reporting.
- **Apparent race with idempotency key:** if the endpoint deduplicates by key or row lock, concurrent submits collapse to one effect and there is no over-redemption.
- **Negative value rejected at the ledger:** a negative quantity accepted at the API but clamped by a database constraint or accounting posting never reaches an exploitable balance.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `business-logic-flaws` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `business-logic-flaws` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: business-logic-flaws
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-840 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`business-logic-flaws-payment-and-pricing`](../business-logic-flaws-payment-and-pricing/SKILL.md) - Web and Application (leaf)
- [`business-logic-flaws-workflow-and-state`](../business-logic-flaws-workflow-and-state/SKILL.md) - Web and Application (leaf)
- [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `business-logic-flaws` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-840`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 50 |
| Distinct dataset sources | 12 |
| Top sources | OffsecCyber (30), hackerone_disclosed_reports (6), SecEval/owasp_wstg (3), securecode-web (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 1 code / 1 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
