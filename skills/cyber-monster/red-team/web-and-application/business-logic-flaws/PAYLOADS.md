# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`business-logic-flaws`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `business-logic-flaws`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Numeric boundary differential (read-only quote)

**Expected differential:** the authoritative order total or balance changes for the out-of-range value and matches baseline for the in-range value; non-destructive because no order is settled

```text
quantity=1  (intended-path baseline, read total only)
quantity=-1  (negative boundary, read total only)
quantity=0.0001  (fractional boundary, read total only)
```

### Coupon set-uniqueness probe

**Expected differential:** applying the same coupon token twice lowers the quoted total twice versus a single application; read the quote, do not place the order

```text
coupon=SAVE10  (applied once, read quote)
coupon=SAVE10&coupon=SAVE10  (applied twice, read quote)
```

### Client-supplied authoritative field

**Expected differential:** submitting a status or price field the UI never sends changes the quoted outcome, proving the server re-accepts a value it should derive

```text
status=pending  (intended, read record)
status=paid  (client-forced, read record)
unitPriceCents=1  (client-forced price, read quote)
```

### Concurrency window probe (disposable account)

**Expected differential:** a once-only action requested twice within the validation window both return success, versus serial requests where the second is refused

```text
redeem once, read remaining count
two redeem requests released together, read remaining count
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
