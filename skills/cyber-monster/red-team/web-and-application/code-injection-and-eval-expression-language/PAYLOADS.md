# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`code-injection-and-eval-expression-language`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `code-injection-and-eval-expression-language`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Dialect delimiter differential

**Expected differential:** the computed value returns for the dialect whose delimiter is active and not for the others, naming the engine without any type reference

```text
name=${7*7} (Jakarta/JSP EL delimiter, expect 49 if active)
name=#{7*7} (SpEL delimiter, expect 49 if active)
name=%{7*7} (OGNL value-stack delimiter, expect 49 if active)
```

### Engine confirmation by type error

**Expected differential:** a benign type-reference token raises a dialect-specific evaluation exception rather than a generic 400, confirming compilation

```text
name=T(java.lang.String).valueOf(49) (SpEL type probe, expect '49' or an EvaluationException)
name=@java.lang.Math@max(2,3) (OGNL static probe, expect 3 or a parse error)
```

### Read-only context verification

**Expected differential:** the same probe returns no computed value after the context is switched to read-only data binding, confirming the fix

```text
name=#{2*21} (re-run against the patched build, expect the literal echoed)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
