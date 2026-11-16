# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`email-header-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `email-header-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Header-field newline probe

**Expected differential:** an embedded CR/LF plus an inert header appears in the received message versus the baseline without it

```text
reply_to=zzmail@example.org%0d%0aX-Probe: zzmail  (literal CRLF, inert extra header)
reply_to=zzmail@example.org%0aX-Probe: zzmail  (bare LF variant)
```

### Encoded-newline bypass

**Expected differential:** an encoded newline form survives decode and still splits the header, versus being stripped

```text
subject=zzmail=?utf-8?q?=0A?=X-Probe: zzmail  (RFC 2047 encoded-word newline)
subject=zzmail%E2%80%A8X-Probe: zzmail  (Unicode line separator U+2028)
```

### Body-smuggle probe

**Expected differential:** a blank line injected into a header field starts a new body segment in the received mail

```text
name=zzmail%0d%0a%0d%0azzmail-injected-body  (CRLF CRLF to begin a body)
```

### Recipient-field injection

**Expected differential:** an added recipient header appears from a single input field versus only the intended recipient

```text
email=zzmail@example.org%0d%0aCc: zzmail-second@example.org  (Cc added via newline)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
