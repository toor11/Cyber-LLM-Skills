# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`type-juggling-javascript-other-languages`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `type-juggling-javascript-other-languages`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### JSON type substitution

**Expected differential:** a JSON boolean or number is accepted where a string of the same text is rejected

```text
{"isAdmin": 1}
{"role": true}
```

### JavaScript abstract-equality edge values

**Expected differential:** an edge value that is loosely equal to the expected scalar passes while a plainly different string does not

```text
code=0e1
code=
```

### Numeric coercion of request strings

**Expected differential:** a string with trailing non-numeric characters is coerced to a valid number, bypassing a numeric validation

```text
qty=10abc
qty=0x10
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
