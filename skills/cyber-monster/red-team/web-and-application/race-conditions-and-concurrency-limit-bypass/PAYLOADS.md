# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`race-conditions-and-concurrency-limit-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `race-conditions-and-concurrency-limit-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Coupon claim burst

**Expected differential:** a one-use test code commits more than one credit only under the synchronized burst

```text
fire 15 concurrent POST /gift-card/claim with one test code
```

### Balance debit burst

**Expected differential:** a test balance of one unit is debited more than once, committing a negative value

```text
concurrent POST /wallet/withdraw for a test balance of one unit
```

### Token reuse

**Expected differential:** a single-use test token redeems twice when two requests land together

```text
two concurrent redemptions of a single-use test token
```

### Overshoot verification

**Expected differential:** the committed ledger on the test asset exceeds its ceiling, confirming the bypass

```text
verify credited_count > 1 or test balance < 0
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
