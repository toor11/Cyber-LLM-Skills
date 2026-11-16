# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-cache-poisoning-and-deception-deception-and-path`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-cache-poisoning-and-deception-deception-and-path`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Suffix routing probe

**Expected differential:** the private page renders unchanged with a static suffix appended, proving the router ignores it

```text
GET /account/profile/wcd.css (authenticated, expect private body)
GET /account/profile (authenticated control)
```

### Cacheability of suffixed URL

**Expected differential:** the suffixed URL returns a cache-storable status while the bare path does not

```text
GET /account/profile/wcd.css?cb=wcd-aaaa (read X-Cache and Cache-Control)
GET /account/profile?cb=wcd-aaaa (expect private, no HIT)
```

### Unauthenticated retrieval

**Expected differential:** the suffixed URL served to a cookieless request returns the victim's private field

```text
GET /account/profile/wcd.css?cb=wcd-aaaa (no Cookie header)
GET /account/profile/wcd.css?cb=wcd-aaaa (with test-account Cookie, store step)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
