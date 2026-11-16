# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-cache-poisoning-and-deception`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-cache-poisoning-and-deception`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Unkeyed header poisoning (busted key)

**Expected differential:** a benign marker from an unkeyed header is stored under your cache-buster key and served to a clean request on that same busted URL

```text
GET /home?cb=wcp-aaaa with X-Forwarded-Host: wcp-marker.example
GET /home?cb=wcp-aaaa clean follow-up (expect stored marker)
```

### Cache deception via suffix

**Expected differential:** an authenticated page requested with a static-looking suffix is stored and retrievable unauthenticated

```text
GET /account/profile;wcp.css (authenticated session)
GET /account/profile;wcp.css (no session, expect cached private body)
```

### Cacheability inspection

**Expected differential:** the Cache-Control and X-Cache headers reveal whether a per-user response is being stored

```text
GET /home?cb=wcp-bbbb (read X-Cache and Cache-Control)
GET /home?cb=wcp-bbbb (repeat, expect Age to increase on HIT)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
