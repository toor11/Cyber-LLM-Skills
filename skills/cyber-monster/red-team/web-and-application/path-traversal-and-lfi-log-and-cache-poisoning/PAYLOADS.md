# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`path-traversal-and-lfi-log-and-cache-poisoning`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `path-traversal-and-lfi-log-and-cache-poisoning`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Access-log User-Agent plant

**Expected differential:** the included access.log gains the inert marker only after this request, and returns to baseline once the field is encoded

```text
User-Agent: Mozilla/5.0 (inert-pl-logpoison-marker)
User-Agent: assessor-pl-logpoison-probe
```

### Referer and error-log plant

**Expected differential:** a malformed request line or Referer carrying the marker appears in error.log inclusion while access.log stays clean, isolating which log is writable

```text
Referer: https://<assessor-controlled-host>/pl-logpoison
GET /pl-logpoison-inert-request HTTP/1.1
```

### Mail-spool envelope plant

**Expected differential:** the marker planted as an envelope field surfaces when the mail spool path is included, proving a non-log write channel

```text
MAIL FROM:<pl-logpoison@assessor.test>
Subject: pl-logpoison-inert-marker
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
