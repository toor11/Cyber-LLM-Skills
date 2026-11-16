# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authentication-bypass-header-and-proxy-trust`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authentication-bypass-header-and-proxy-trust`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Forwarded-identity spoof

**Expected differential:** adding a trust header flips an internal route from 401 or 404 to 200, versus the clean request which is denied

```text
X-Forwarded-For: 127.0.0.1  on an internal-only route
X-Internal-Request: true  claimed internal marker header
```

### URL-override headers

**Expected differential:** the app authorises on the header path while the proxy gated the request line, so the override reaches a privileged route

```text
X-Original-URL: /admin/metrics  with request-line path of /
X-Rewrite-URL: /admin/metrics  with request-line path of /public
```

### Forwarded-host trust

**Expected differential:** changing the forwarded host reroutes trust or link generation, versus the canonical host which is handled normally

```text
X-Forwarded-Host: internal.local  on a password or link flow
Host: localhost  to claim loopback trust on the route
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
