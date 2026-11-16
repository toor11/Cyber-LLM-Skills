# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`rest-and-grpc-api-security`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `rest-and-grpc-api-security`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Object-level id swap

**Expected differential:** account B retrieves account A's object by id, proving missing ownership enforcement

```text
GET /api/orders/1002 as account B (owner is account A)
```

### Mass assignment

**Expected differential:** an unlisted field persists server-side, proving the deserializer binds fields outside the schema

```text
{"item":"x","role":"admin","owner_id":1}
```

### Verb and method override

**Expected differential:** a method-override header changes the effective action, proving verb confusion

```text
X-HTTP-Method-Override: DELETE on a POST route
```

### Excessive data exposure

**Expected differential:** the response carries more fields than the client renders, proving serializer over-return

```text
compare response fields to the fields the client renders
```

### Batch index alignment

**Expected differential:** a well-formed batch returns the same status per item as the same routes called alone. The defect is an error-path length mismatch in source, not a live malformed item.

```text
batch alignment: item status matches the same route called alone, and the permission callback is the handler that runs
patch-diff anchor: validation list and match list stay the same length when one subrequest fails to parse
```

### gRPC reflection enumeration

**Expected differential:** server reflection lists methods to an unauthenticated caller, proving interface exposure

```text
grpcurl -plaintext target.example:443 list
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
