# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cors-misconfiguration-reflected-origin`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cors-misconfiguration-reflected-origin`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Operator-specific lookalike set

**Expected differential:** each crafted Origin targets one matching operator; the ones reflected name the exact flaw while the benign Origin is the control

```text
Origin: https://shop.example.com.reflect-probe.test (suffix-match attack)
Origin: https://shop.example.com.reflectprobe (prefix-match attack)
Origin: https://reflectprobe-example.com (substring-match attack)
```

### Null origin trust

**Expected differential:** Access-Control-Allow-Origin: null is returned for a null Origin, proving sandboxed-frame trust distinct from a string match

```text
Origin: null (delivered from a sandboxed iframe for this variant)
```

### Reflection confirmation

**Expected differential:** the crafted attacker Origin is echoed verbatim, confirming the reflection rather than a fixed allowlisted value

```text
Origin: https://id.example.com.reflect-probe.test with the session cookie attached
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
