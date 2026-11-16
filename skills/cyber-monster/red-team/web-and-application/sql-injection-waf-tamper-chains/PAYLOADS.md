# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection-waf-tamper-chains`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection-waf-tamper-chains`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Block-versus-pass baseline

**Expected differential:** the raw keyword payload returns the vendor block page while a benign value returns the origin response, fixing the two reference points

```text
q=widget
q=widget UNION SELECT 1
```

### Comment and whitespace transform

**Expected differential:** inline comment or alternate whitespace passes where the raw form is blocked, then reproduces the origin differential

```text
q=widget/**/UNION/**/SELECT/**/1
q=widget%0bUNION%0bSELECT%0b1
```

### Case and operator rewrite

**Expected differential:** case folding or a between rewrite evades a literal signature while preserving semantics

```text
q=widget uNiOn sElEcT 1
q=1 BETWEEN 1 AND 1
```

### Body-format differential (WAFFLED)

**Expected differential:** the same payload in multipart form passes where urlencoded is blocked, per the content-type gap

```text
Content-Type: multipart/form-data; boundary=wafchain
Content-Disposition: form-data; name="q"
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
