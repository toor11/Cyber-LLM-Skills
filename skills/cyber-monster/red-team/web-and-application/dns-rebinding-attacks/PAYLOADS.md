# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`dns-rebinding-attacks`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `dns-rebinding-attacks`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Resolution-flip observation

**Expected differential:** the name resolves to an external address then to an internal one across the TTL, versus a stable single answer

```text
dig +short A zzdns.<assessor-controlled-host>  (first resolution, external)
dig +short A zzdns.<assessor-controlled-host>  (after TTL, expect internal flip)
```

### Host-header acceptance check

**Expected differential:** the internal service answers a request whose Host is the attacker name versus rejecting it

```text
curl -s --resolve zzdns.<assessor-controlled-host>:80:127.0.0.1 http://zzdns.<assessor-controlled-host>/healthz
curl -s -H 'Host: zzdns.<assessor-controlled-host>' http://127.0.0.1/healthz  (does it accept foreign Host?)
```

### Internal reachability oracle

**Expected differential:** closed versus open internal ports yield distinguishable responses after the flip, without reading data

```text
curl -s -o /dev/null -w '%{http_code} %{time_total}' http://127.0.0.1:1/  (closed-port baseline)
curl -s -o /dev/null -w '%{http_code} %{time_total}' http://127.0.0.1:8080/  (candidate service)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
