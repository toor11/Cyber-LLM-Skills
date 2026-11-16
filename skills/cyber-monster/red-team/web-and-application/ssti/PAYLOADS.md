# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssti`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssti`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Reflection versus evaluation (engine-neutral)

**Expected differential:** the same string with and without the engine delimiter renders identically until the delimiter is present, which shows the input reaches the template rather than the output; the engine-specific arithmetic differential belongs to the Jinja2/Twig child

```text
name=Hello {{user}}
name=Hello 7*7
```

### Engine fingerprint by delimiter

**Expected differential:** only the delimiter matching the engine computes while the others return literal text

```text
q=${7*7}
q=<%= 7*7 %>
```

### Object-graph reach (Python context)

**Expected differential:** an attribute walk returns a class or method repr, proving traversal beyond arithmetic

```text
name={{''.__class__}}
name={{config.items()}}
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
