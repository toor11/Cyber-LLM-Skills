# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`openapi-and-swagger-exposure`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `openapi-and-swagger-exposure`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Spec endpoint reachability

**Expected differential:** a spec path returns a document containing openapi or swagger keys anonymously, where a protected service returns 401/403 or 404

```text
GET /v3/api-docs
GET /openapi.json
```

### Interactive UI and catalogue enumeration

**Expected differential:** the UI shell and resource listing render the operation set without a session, confirming an anonymous console

```text
GET /swagger-ui/index.html
GET /swagger-resources
```

### Environment and principal differential

**Expected differential:** the anonymous request returns the full inventory while the operator session is required on a correctly configured peer

```text
GET /v3/api-docs with an unauthenticated session
GET /v3/api-docs with an operator session
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
