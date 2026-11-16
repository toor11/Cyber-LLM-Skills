# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssti-jinja2-and-twig`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssti-jinja2-and-twig`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Engine-evaluation differential

**Expected differential:** the arithmetic form renders its product while the literal renders verbatim; reverting to a bound variable removes the difference

```text
name={{7*7}}
name={{7*'7'}}
name=7*7
```

### Jinja2 globals read (non-destructive)

**Expected differential:** the config object serializes in the response on Flask and Jinja2 while a bound-variable control does not; no data is written

```text
profile={{config}}
profile={{config.items()}}
profile={{g}}
```

### Twig environment read

**Expected differential:** `_self` and `_context` resolve to the Twig environment on PHP while the literal does not; read-only, no filesystem or command touched

```text
bio={{_self.env}}
bio={{_context|keys}}
bio={{dump(_context)}}
```

### Statement-tag control

**Expected differential:** a `{% %}` statement such as a set or loop is executed and alters rendered structure while the same text as data is printed verbatim

```text
q={% set x=7*7 %}{{x}}
q={% for i in [1,2] %}{{i}}{% endfor %}
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
