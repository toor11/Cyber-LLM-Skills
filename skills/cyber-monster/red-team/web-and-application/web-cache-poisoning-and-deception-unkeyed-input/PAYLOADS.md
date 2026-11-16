# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-cache-poisoning-and-deception-unkeyed-input`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-cache-poisoning-and-deception-unkeyed-input`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Unkeyed header reflection (busted)

**Expected differential:** a benign marker injected via a forwarded header is served to a clean request on the busted URL

```text
GET /go?cb=uki-aaaa with X-Forwarded-Host: uki-marker.example
GET /go?cb=uki-aaaa clean (expect uki-marker.example in Location)
```

### Duplicate-parameter unkeyed channel

**Expected differential:** the second copy of a duplicated parameter is reflected but not keyed

```text
GET /search?q=real&q=uki-dup&cb=uki-bbbb
GET /search?q=real&cb=uki-bbbb (clean, expect uki-dup reflected)
```

### Fat GET body on a cacheable route

**Expected differential:** a body on a GET influences the cached response though the key is URL-only

```text
GET /widget?cb=uki-cccc with body pref=uki-fatget
GET /widget?cb=uki-cccc (no body, expect uki-fatget reflected)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
