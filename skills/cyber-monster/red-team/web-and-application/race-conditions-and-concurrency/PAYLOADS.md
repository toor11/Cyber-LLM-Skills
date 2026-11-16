# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`race-conditions-and-concurrency`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `race-conditions-and-concurrency`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Single-packet concurrent burst

**Expected differential:** the committed total overshoots the ceiling only when requests land together in one packet

```text
send 20 identical POST /redeem in one HTTP/2 packet (single-packet attack)
```

### Last-byte synchronization (HTTP/1.1)

**Expected differential:** withholding the final byte and releasing together produces the overshoot where spaced requests do not

```text
HTTP/1.1 last-byte sync: withhold the final byte, then release together
```

### Sequential baseline

**Expected differential:** one-at-a-time execution holds the ceiling, establishing the value the burst must exceed

```text
baseline: one sequential POST /redeem, record uses_left
```

### Impossible-total verification

**Expected differential:** the stored counter reaches a value a sequential run cannot, confirming the race

```text
verify stored uses_left < 0 or grants > 1 for a one-use code
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
