# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cross-site-scripting`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cross-site-scripting`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Context-location marker

**Expected differential:** a unique inert marker reveals where the value lands and how it is encoded, before any break is attempted

```text
q=zqxMarker1 (locate the reflection and its surrounding context)
q=<zqxMarker1> (check whether angle brackets survive unencoded)
```

### Attribute-context break

**Expected differential:** the quoted attribute closes and a benign handler forms only when attribute encoding is missing

```text
name=zqx" data-zqx=marker1 (quote-break probe in an attribute context)
```

### URL-scheme sink probe

**Expected differential:** a javascript: scheme is accepted in an href or src where only http and https should be allowed

```text
redirect=javascript:void('zqxMarker1') (scheme-allowlist probe, non-executing marker)
```

### Browser-execution confirmation

**Expected differential:** a controlled, benign DOM change confirms active content rather than reflection when rendered in a real browser

```text
bio=<img src=x onerror="document.title='zqxMarker1'"> (benign title change as the signal)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
