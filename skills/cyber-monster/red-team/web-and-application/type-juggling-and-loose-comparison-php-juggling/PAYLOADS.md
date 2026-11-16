# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`type-juggling-and-loose-comparison-php-juggling`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `type-juggling-and-loose-comparison-php-juggling`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### strcmp array-null bypass

**Expected differential:** submitting the field as an array makes strcmp return null so the equal-zero test passes, while a scalar wrong value is rejected

```text
pw[]=
pw[]=anything
```

### magic-hash numeric coercion (PHP)

**Expected differential:** a `0e`-coercing preimage is accepted by an MD5 loose-equality check while a random string is not

```text
pass=QNKCDZO
pass=aabg7XSs
```

### loose membership and switch

**Expected differential:** a `0` or `true` value matches a list element or numeric case under coercion where a distinct string would not

```text
role=0
mode=1e1
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
