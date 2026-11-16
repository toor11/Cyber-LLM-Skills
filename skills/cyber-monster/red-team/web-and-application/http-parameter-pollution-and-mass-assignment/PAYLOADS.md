# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http-parameter-pollution-and-mass-assignment`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http-parameter-pollution-and-mass-assignment`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Mass-assignment authority-field probe (read-back)

**Expected differential:** the authority field changes in the object read back only when the extra key is sent, and stops changing once the binder is allowlisted; non-destructive because only the attacker's own record is read

```text
display_name=probe&role=admin   (over-post role, then GET the record)
display_name=probe&tenant_id=9999   (over-post tenancy, then GET the record)
display_name=probe   (intended-path baseline, then GET the record)
```

### Duplicate-key parser differential

**Expected differential:** the two tiers select different occurrences, so the WAF inspects one value while the app consumes the other; benign values only, status and reflected value compared

```text
role=user&role=auditor   (two scalars, observe which the app echoes)
role=user%00&role=auditor   (null-byte split, observe tier disagreement)
```

### Array-versus-scalar coercion probe

**Expected differential:** a repeated or bracketed key collapses to a list at one parser and a scalar at another, changing the effective value with no destructive effect

```text
limit[]=10&limit[]=100000   (array form, observe coercion at the app)
limit=10&limit=100000   (repeated scalar, compare first-wins versus last-wins)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
