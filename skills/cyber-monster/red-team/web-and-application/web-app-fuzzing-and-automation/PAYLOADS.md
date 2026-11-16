# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-app-fuzzing-and-automation`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-app-fuzzing-and-automation`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Baseline calibration

**Expected differential:** several benign controls establish the normal status and length band for the position

```text
code=FUZZBASE01 (benign control, record status and length)
code=FUZZBASE02 (second control for the noise floor)
```

### Enumeration oracle probe

**Expected differential:** a valid-shaped value diverges in length or status from an invalid-shaped control

```text
code=AAAAAAAA (valid shape, unknown value)
code=zzzz (invalid shape control)
```

### Rate envelope probe

**Expected differential:** the response stays normal under paced requests and switches to 429 or Retry-After when the rate climbs

```text
X-Fuzz-Rate: 5rps (paced control burst)
X-Fuzz-Rate: 100rps (observe rate-limit onset)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
