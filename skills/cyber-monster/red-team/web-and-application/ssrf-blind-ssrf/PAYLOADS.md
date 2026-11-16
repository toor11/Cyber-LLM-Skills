# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssrf-blind-ssrf`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssrf-blind-ssrf`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Unique-token OAST probe

**Expected differential:** a per-request subdomain yields a callback from the target egress at issue time while the control token stays silent

```text
url=https://<unique-token>.<assessor-oast-host>/blind
url=https://control.<assessor-oast-host>/blind
```

### Timing oracle with baseline

**Expected differential:** elapsed time exceeds the measured jitter baseline only for the conditional probe

```text
url=http://<internal-host>:1/ fast-fail-control
url=http://<internal-host>:80/ slow-probe
```

### Port reachability error differential

**Expected differential:** a closed versus open internal port yields distinguishable error or timing without reading data

```text
url=http://<internal-host>:9/
url=http://<internal-host>:443/
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
