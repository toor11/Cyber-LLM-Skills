# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`injection-detection-methodology`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `injection-detection-methodology`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Reflection channel probe

**Expected differential:** a single structural character changes the surrounding markup or breaks out of the reflected context, and the change reverts when the character is encoded

```text
field=probe<marker   (does the renderer alter surrounding markup)
field=probe&marker=plain   (benign reflection baseline)
```

### Boolean result-set differential

**Expected differential:** logically opposite conditions return different result-set sizes with an otherwise identical request, and collapse to equal when the structure is neutralised

```text
q=open AND truthy-condition-holds   (expect full result set)
q=open AND falsy-condition-holds   (expect empty or reduced result set)
```

### Arithmetic evaluation probe

**Expected differential:** an input that encodes a computation is evaluated rather than echoed, shown by the response reflecting the computed value

```text
value=seven-times-seven-as-expression   (expect computed 49 if evaluated)
value=seven-times-seven-as-literal-text   (expect the literal echoed)
```

### Bounded timing channel (last resort)

**Expected differential:** elapsed time rises only for the delay-keyed input and matches the benign baseline otherwise, confirmed across repeats to clear jitter

```text
token=probe-with-bounded-delay-keyed-to-input   (expect added latency)
token=probe-with-no-delay   (expect baseline latency)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
