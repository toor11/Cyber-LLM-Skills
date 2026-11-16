# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`crlf-and-header-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `crlf-and-header-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Benign header-injection differential

**Expected differential:** a unique harmless header appears in the response for the CRLF form and is absent for the plain baseline

```text
next=/dashboard%0d%0aX-Crlf-Probe:crlf7788 (expect the probe header to materialise)
next=/dashboard (plain baseline with no control characters)
```

### Bare-LF parser differential

**Expected differential:** the bare line-feed form injects a header where the full CRLF form is blocked, revealing a filter gap

```text
lang=en%0aX-Lf-Only-Probe:lf7788 (bare LF variant)
```

### Set-Cookie and body split inspection

**Expected differential:** an injected Set-Cookie surfaces as a real cookie header, or a double CRLF starts a response body, proving a full split

```text
ref=home%0d%0aSet-Cookie:crlfprobe=1 (expect a planted probe cookie, non-session)
ref=home%0d%0a%0d%0a<marker-crlf7788> (double CRLF starts a body boundary)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
