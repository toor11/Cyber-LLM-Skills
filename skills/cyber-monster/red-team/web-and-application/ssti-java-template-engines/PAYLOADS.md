# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssti-java-template-engines`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssti-java-template-engines`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Freemarker evaluation probe

**Expected differential:** the Freemarker expression computes while the neutralised control renders literally

```text
name=<#assign zz=7*7>${zz}
name=${'7*7'}
```

### Velocity evaluation probe

**Expected differential:** the Velocity directive assigns and prints 49 while the control stays literal

```text
q=#set($zz=7*7)$zz
q=no-set-7*7
```

### Thymeleaf SpEL probe

**Expected differential:** the SpEL expression evaluates while the control is inert, and #ctx reach is checked separately

```text
expr=${7*7}
expr=__${7*7}__
```

### Class-reach check (read-only)

**Expected differential:** a class constant resolves in the expression context, proving object-graph reach without invoking a command

```text
expr=${T(java.lang.Integer).MAX_VALUE}
expr=${6*6}
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
