# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`prototype-pollution-server-side`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `prototype-pollution-server-side`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### JSON-body persistence

**Expected differential:** an independent later request reflects sp_canary, proving the pollution persisted across requests

```text
{"__proto__":{"sp_canary":"server-polluted"}}
```

### Query-parser nested pollution

**Expected differential:** a bracketed key reaches __proto__ through qs, confirming the query parser as the source

```text
settings[__proto__][sp_canary]=server-polluted
```

### Authorization default flip

**Expected differential:** a later /me response reports admin true after an sp_admin pollution, reverting once keys are guarded

```text
{"constructor":{"prototype":{"sp_admin":true}}}
```

### Independent read-back

**Expected differential:** a fresh connection reads sp_canary on an unrelated object, isolating persistence from reflection

```text
GET /me on a new connection and check for sp_canary
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
