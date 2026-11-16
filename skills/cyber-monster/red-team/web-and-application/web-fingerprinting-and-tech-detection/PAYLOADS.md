# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-fingerprinting-and-tech-detection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-fingerprinting-and-tech-detection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Passive header fingerprint

**Expected differential:** the response headers reveal product and version tokens

```text
GET / (read Server, X-Powered-By, Set-Cookie names)
HEAD / (headers only, no body)
```

### Asset and favicon hash

**Expected differential:** a shipped asset or favicon hash matches a known build

```text
GET /favicon.ico (compute favicon hash, match to product build)
GET /static/app.js (read path pattern and content hash)
```

### Error-template probe

**Expected differential:** a benign 404 or malformed request elicits a product-specific error template

```text
GET /wfp-nonexistent-404 (read error-page wording)
GET / HTTP/1.9 (malformed version, read server error template)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
