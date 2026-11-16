# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http-method-and-verb-attacks`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http-method-and-verb-attacks`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Method-override rewrite

**Expected differential:** an override header changes the acting verb after the gate, versus a server that authorizes the effective verb

```text
POST /admin/resource with X-HTTP-Method-Override: DELETE as a non-admin
POST /admin/resource with _method=DELETE in the body as a non-admin
```

### Alternate-verb reach

**Expected differential:** an uncovered verb reaches the gated handler, versus identical denial across verbs

```text
PATCH a route whose authorization rule names only POST
GET a state-changing route to test safe-method mutation
```

### Diagnostic-method exposure

**Expected differential:** TRACE or verbose OPTIONS reflects headers or lists methods, versus a server that disables them

```text
TRACE / to observe request-header reflection
OPTIONS a route to read the Allow header method list
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
