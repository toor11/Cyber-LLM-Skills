# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-recon-and-content-discovery-javascript-analysis`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-recon-and-content-discovery-javascript-analysis`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Source-map presence probe

**Expected differential:** the map path returns 200 while a nonexistent map returns 404, proving maps are published for the production chunk

```text
GET /static/js/main.<hash>.js.map HTTP/1.1
GET /static/js/jsrecon-missing.js.map HTTP/1.1
```

### Endpoint extraction differential

**Expected differential:** a path recovered from the bundle is checked against the authenticated baseline; absence from normal traffic marks it as build-disclosed

```text
grep -Eo '"/api/[a-zA-Z0-9_/-]+"' main.<hash>.js
linkfinder -i https://target.example/static/js/main.<hash>.js -o cli
```

### Bundled-secret liveness (read-only)

**Expected differential:** a token-shaped string is tested with a read-only identity call; a valid identity response proves the secret is live and bundled

```text
trufflehog filesystem ./bundle --only-verified
curl -sS -H 'Authorization: Bearer <recovered-token>' https://api.service.example/v1/whoami
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
