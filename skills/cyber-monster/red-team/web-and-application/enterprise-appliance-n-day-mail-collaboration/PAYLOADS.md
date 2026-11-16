# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`enterprise-appliance-n-day-mail-collaboration`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `enterprise-appliance-n-day-mail-collaboration`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Platform fingerprint

**Expected differential:** detected build below the fixed version versus at or above it

```text
curl -sI https://mail.example/owa/  (webmail banner and version headers)
curl -s https://mail.example/autodiscover/autodiscover.xml  (read platform build hints)
```

### Proxy-routing reachability (benign)

**Expected differential:** a front-end path routes to the backend on an affected build versus a 400 or 404 on a patched one

```text
curl -sS -o /dev/null -w '%{http_code}' 'https://mail.example/autodiscover/zzmc'  (benign routing check)
zzmc_probe=inert-marker  (single routing artefact, nothing executed)
```

### Management-endpoint exposure

**Expected differential:** the license or management servlet answers from the tester position versus being filtered

```text
curl -sI https://mail.example/<management-endpoint>  (is the servlet reachable?)
zzmc_backend=segmented-or-open  (record reachability, no gadget sent)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
