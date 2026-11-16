# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jndi-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `jndi-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Lookup-callback oracle (DNS/LDAP)

**Expected differential:** a benign provider name produces no callback while a provider URL pointing at the assessor host does, proving the lookup destination is attacker-controlled with no object returned

```text
broker=ldap://<assessor-controlled-host>:389/o=probe
broker=jms/LocalConnectionFactory (control)
```

### Scheme-allowlist differential

**Expected differential:** a jms or java name is accepted while an rmi or ldap name reaches the assessor host; acceptance of the dangerous scheme proves no protocol allowlist is present

```text
name=rmi://<assessor-controlled-host>:1099/ref
name=jms/queue/audit (control)
```

### Nested-expression unwrap probe

**Expected differential:** a literal lookup prefix is rejected but a layered form resolves identically, showing surface string matching rather than a structural control

```text
q=${lower:J}ndi-probe (layered)
q=plainvalue (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
