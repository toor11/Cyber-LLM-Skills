# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`business-logic-flaws-payment-and-pricing`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `business-logic-flaws-payment-and-pricing`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Price substitution (read-only quote)

**Expected differential:** the server-computed amount drops when a lower price is forced and matches catalogue when omitted; cart only, nothing captured

```text
price_cents=1999  (omit to get catalogue baseline)
price_cents=1  (forced low price, read quote)
```

### Negative and fractional amount

**Expected differential:** a negative line yields a positive credit or a below-zero total in the quote response, versus a normal positive line

```text
line_amount_cents=500  (baseline)
line_amount_cents=-500  (negative, read credit field)
line_amount_cents=0.5  (sub-unit, read rounding)
```

### Coupon over-application

**Expected differential:** repeating the discount code multiplies the reduction in the server quote versus a single application

```text
discount_code=WELCOME  (single, read quote)
discount_code=WELCOME&discount_code=WELCOME  (repeated, read quote)
```

### Currency and minor-unit confusion

**Expected differential:** a mismatched currency or scale changes the settled-equivalent amount while the numeric total looks unchanged

```text
currency=USD&amount_minor=1000  (baseline)
currency=JPY&amount_minor=1000  (scale mismatch, read settled equivalent)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
