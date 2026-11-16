# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-recon-and-content-discovery-archive-and-osint-recon`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-recon-and-content-discovery-archive-and-osint-recon`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Archive URL harvest

**Expected differential:** historical captures list endpoints the live site no longer serves

```text
wayback cdx: url=target.example/* output=text fl=original collapse=urlkey
commoncrawl index query for url=target.example/* (historical captures)
```

### Live-versus-archive diff

**Expected differential:** a recovered endpoint still responds while being absent from the current navigation

```text
GET /legacy/v1/export (recovered from archive, test liveness in scope)
GET / (current navigation, confirm the endpoint is unlinked)
```

### Public code and paste search

**Expected differential:** the domain or a secret pattern appears in a public repository or paste

```text
github search: target.example extension env or yml
paste search: target.example internal hostname or token prefix
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
