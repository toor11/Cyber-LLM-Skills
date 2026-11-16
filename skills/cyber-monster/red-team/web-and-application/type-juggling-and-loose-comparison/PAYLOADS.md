# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`type-juggling-and-loose-comparison`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `type-juggling-and-loose-comparison`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Strict-versus-loose equality differential

**Expected differential:** the magic-hash value is rejected by a strict check and accepted by the loose one at the same endpoint

```text
token=0e1137126905
token=240610708
```

### Type-channel submission

**Expected differential:** submitting the parameter as a non-string type changes the comparison outcome where a string would not

```text
flag[]=1
verified=true
```

### JSON type confusion

**Expected differential:** a JSON boolean or number passes a check that a string of the same text would fail

```text
{"isAdmin": true}
{"otp": 0}
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
