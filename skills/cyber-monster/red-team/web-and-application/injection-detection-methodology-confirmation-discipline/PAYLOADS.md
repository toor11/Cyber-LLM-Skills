# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`injection-detection-methodology-confirmation-discipline`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `injection-detection-methodology-confirmation-discipline`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Noise-band measurement

**Expected differential:** two benign values repeated establish the natural variation; any later probe must exceed this band to count

```text
value=benign-control-a repeated five times (record length and timing spread)
value=benign-control-b repeated five times (record length and timing spread)
```

### Escaped-probe revert check

**Expected differential:** the probe and its server-escaped twin are compared; a true injection shows the probe diverging and the escaped probe reverting to baseline

```text
value=probe-with-active-structural-character (expect divergence)
value=probe-with-structural-character-neutralised (expect revert to baseline)
```

### Cache-isolation control

**Expected differential:** adding a unique cache buster distinguishes an application differential from a cache-served one

```text
value=probe plus a unique cache-buster token (effect should survive if real)
value=probe with no cache-buster token (effect may be cache-served)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
