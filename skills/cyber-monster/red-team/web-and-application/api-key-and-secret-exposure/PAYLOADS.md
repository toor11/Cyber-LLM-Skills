# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`api-key-and-secret-exposure`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `api-key-and-secret-exposure`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Client-asset secret sweep

**Expected differential:** a provider prefix appears in the shipped bundle but not in the server-only baseline, and the match disappears once the key is moved server-side

```text
GET /assets/app.bundle.js  then match AKIA[0-9A-Z]{16}
GET /static/js/main.js  then match the sk_live_ prefix
GET /config.json  probe for key-value secrets in a 200 body
```

### Source-map recovery

**Expected differential:** a reachable map reconstructs original source with inlined secrets, and returns 404 once maps are stripped from the production build

```text
GET /assets/app.bundle.js.map  expect 404 when maps are stripped
GET /_next/static/chunks/  probe for a build-artefact index listing
```

### Live-versus-revoked signal (read only)

**Expected differential:** an identity-only call returns the key owner for a live credential and an auth error for a revoked one, with no access to any protected resource

```text
aws sts get-caller-identity  identity echo only, no resource access
GET https://api.stripe.com/v1/account  restricted read-only account probe
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
