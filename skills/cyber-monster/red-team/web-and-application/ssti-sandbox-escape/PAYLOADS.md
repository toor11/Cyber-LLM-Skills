# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssti-sandbox-escape`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssti-sandbox-escape`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### First-hop mediation baseline

**Expected differential:** a direct forbidden attribute raises a SecurityError or empty render, establishing that the sandbox is active before testing transitive hops

```text
note={{().__class__}}
note={{self.__class__}}
```

### Transitive gadget hop (Jinja2)

**Expected differential:** the `|attr` route resolves where the dotted route was blocked, proving single-level mediation per GHSA-cpwx-vrp4-4pq7; no command is run

```text
note={{ ''|attr('__class__') }}
note={{ ''|attr('format') }}
```

### Twig filter allowlist probe

**Expected differential:** a filter cleared by the safe-filter list returns an environment handle while a denied filter is rejected, isolating the GHSA-gjc5-8cfh-653x surface

```text
note={{ _self|default }}
note={{ _context|keys|first }}
```

### Thymeleaf context reach

**Expected differential:** `#ctx` resolves through `th:with` where a direct type reference is blocked, marking the restriction bypass

```text
val=__${#ctx}__
val=*{#ctx.getClass()}
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
