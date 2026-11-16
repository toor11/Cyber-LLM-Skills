# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`openapi-and-graphql-schema-auditor-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `openapi-and-graphql-schema-auditor-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Unauthenticated operation probe

Baseline: the same request with a valid credential must return data. Probe: without the credential it must return 401/403. Differential: a 2xx without credentials on an operation the document protects is the finding.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" https://api.example/v1/orders
curl -sS -o /dev/null -w '%{http_code}\n' https://api.example/v1/orders
```

## GraphQL introspection read

Baseline: an introspection query returning types. Probe: a depth probe on a self-referential field. Differential: a query deeper than the documented limit that still returns 200.

```bash
curl -sS -X POST https://api.example/graphql -H 'content-type: application/json' -d '{"query":"{__schema{types{name}}}"}'
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
