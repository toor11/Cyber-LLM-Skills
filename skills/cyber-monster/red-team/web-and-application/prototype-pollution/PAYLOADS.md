# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`prototype-pollution`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `prototype-pollution`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### JSON-body pollution

**Expected differential:** a fresh object gains pp_canary after the body is merged, and does not when the merge rejects the key

```text
{"__proto__":{"pp_canary":"polluted"}}
```

### Query-string bracket pollution

**Expected differential:** a nested-bracket key reaches __proto__ through the query parser, proving the parser is the source

```text
a[__proto__][pp_canary]=polluted
```

### Constructor-path form

**Expected differential:** the constructor.prototype form pollutes where __proto__ is blocked, revealing an incomplete blocklist

```text
{"constructor":{"prototype":{"pp_canary":"polluted"}}}
```

### Canary read-back

**Expected differential:** a later response reflects pp_canary in a default field it never set, confirming the write without a destructive action

```text
GET /config then check for pp_canary in an unset default
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
