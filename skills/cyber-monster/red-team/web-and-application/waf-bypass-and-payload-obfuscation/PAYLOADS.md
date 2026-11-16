# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`waf-bypass-and-payload-obfuscation`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `waf-bypass-and-payload-obfuscation`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Container interchange (urlencoded versus multipart)

**Expected differential:** the same benign marker is blocked as urlencoded and passed as multipart, proving container-level inspection gaps

```text
Content-Type: application/x-www-form-urlencoded with q=<waf-marker>
Content-Type: multipart/form-data; boundary=X with a q part of <waf-marker>
```

### Multipart boundary mutation

**Expected differential:** an unusual or duplicated boundary causes the WAF to miss the part the origin still reads

```text
boundary token followed by trailing whitespace before CRLF
two Content-Disposition headers on one multipart part
```

### Parameter pollution across locations

**Expected differential:** the WAF inspects one occurrence of the parameter while the origin uses another

```text
q=<benign>&q=<waf-marker>
query q=<benign> plus body q=<waf-marker>
```

### Content-type relabel

**Expected differential:** relabeling the body to a type the WAF does not parse but the origin accepts forwards it uninspected

```text
Content-Type: application/json with {"q":"<waf-marker>"}
Content-Type: text/plain carrying a form body
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
