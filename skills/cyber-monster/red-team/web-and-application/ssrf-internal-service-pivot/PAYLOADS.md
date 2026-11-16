# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssrf-internal-service-pivot`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssrf-internal-service-pivot`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Internal service identification (read-only)

**Expected differential:** an internal version or root path returns service-identifying content while an external control does not

```text
source=http://kubernetes.default/version
source=http://127.0.0.1:2375/version
```

### Datastore-over-HTTP probe

**Expected differential:** an internal datastore root returns cluster info while the external control returns the normal page

```text
source=http://<internal-host>:9200/
source=http://<internal-host>:8500/v1/agent/self
```

### Open-versus-closed port oracle

**Expected differential:** an open internal port yields a distinct status or timing versus a closed one, proving reachability without reading data

```text
source=http://<internal-host>:6379/
source=http://<internal-host>:2/
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
