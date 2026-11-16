# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`mobile-and-hybrid-web-api-abuse`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `mobile-and-hybrid-web-api-abuse`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Direct-replay object-id differential

**Expected differential:** the same authenticated request with another tester account's object id returns that object instead of 403 or 404

```text
GET /api/v1/orders/<tester-A-id> (in-app baseline)
GET /api/v1/orders/<tester-B-id> (direct replay, tester A token)
```

### Hidden-function reachability

**Expected differential:** a function absent from the app UI answers a direct call with the tester's ordinary token

```text
POST /api/v1/admin/export (ordinary tester token)
GET /api/v1/internal/metrics (ordinary tester token)
```

### Bundled-secret and debug-route probe

**Expected differential:** a key pulled from the app bundle authenticates a direct request, or a versioned or debug route answers without production guards

```text
Authorization: ApiKey <key-from-app-bundle>
GET /debug/config (production host)
GET /api/v0/users (legacy version route)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
