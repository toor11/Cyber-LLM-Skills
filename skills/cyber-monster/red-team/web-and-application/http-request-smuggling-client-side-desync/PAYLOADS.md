# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http-request-smuggling-client-side-desync`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http-request-smuggling-client-side-desync`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Body-on-unexpected-method carrier probe

**Expected differential:** a GET or 404 request carrying a small body returns 200 and keeps the connection open for the vulnerable case, versus a 400 or a connection close for the hardened case

```text
GET request to a static path with a small Content-Length body attached (carrier probe)
GET request to the same path with no body (carrier control)
```

### Connection-reuse priming (own browser session)

**Expected differential:** a follow-up request on the primed connection is routed or reflected differently than the same request on a fresh connection, measured only against the tester's own session

```text
prime with a body-bearing GET, then follow up to a known path on the same connection (primed run)
follow up to the known path on a fresh connection (fresh-connection baseline)
```

### Routing-steer confirmation

**Expected differential:** the stranded prefix steers the follow-up toward an attacker-chosen in-scope path, shown by the follow-up response matching that path rather than the requested one

```text
stranded prefix naming an alternate in-scope path, follow-up requests the original path (steer probe)
no stranded prefix, follow-up requests the original path (steer control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
