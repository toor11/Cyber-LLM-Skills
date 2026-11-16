---
name: jndi-injection-remote-class-loading
description: JNDI remote class loading and trust bypass. Covers LDAP and RMI remote codebase loading, JDK trustURLCodebase restrictions, and modern bypasses using local factory gadget classes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["jndi rmi", "ldap codebase", "trustURLCodebase bypass", "jndi factory"]
cwe: [CWE-917, CWE-502]
owasp: [A03:2021]
attack: [T1190]
capec: [CAPEC-242]
related: [jndi-injection, jndi-injection-logging-lookups, sql-injection, cross-site-scripting]
parent: jndi-injection
corpus_sparse: true
---

# Jndi Injection Remote Class Loading - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

After a JNDI lookup returns a naming Reference, the JVM may instantiate an object factory, and historically it would fetch that factory's bytecode from a codebase URL embedded in the reference, so an attacker who controls the directory response controls which class the JVM loads and runs. Modern JDKs set com.sun.jndi.*.object.trustURLCodebase to false, blocking remote codebase loading, which pushes attackers toward local factory gadgets such as the Tomcat BeanFactory, a GroovyClassLoader, or an EL evaluator already on the classpath. The decision point is the trustURLCodebase flag combined with which factory classes are reachable. The attacker gains code execution from a controlled directory response. A non-destructive probe confirms whether the server fetches a remote .class or resolves a local factory, using a listener rather than live bytecode.

- **Precondition chain:** A JNDI lookup resolves against an attacker-controlled directory, the JVM either trusts remote codebase URLs or exposes a local object-factory gadget, and the returned Reference can name that factory.
- **Readable differential:** A reference naming a remote factory codebase versus one naming a local factory: on a trustURLCodebase-true JVM the remote class is fetched, while a hardened JVM only instantiates local factories, and the remote fetch stops once the trust flag is false.
- **Empirical grounding:** CWE-917 and CWE-502 under OWASP Top 10:2025 A05 Injection. GHSA-mvwc-x8x9-46c3 (DataEase Impala datasource JDBC attack pivoting to JNDI/RMI, fixed 2.10.13) is a 2025 remote-reference instance, and CVE-2025-58782 disables JNDI lookups by default as the structural fix.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the remote-codebase profile is not yet confirmed **THEN** start at the parent class [`jndi-injection`](../jndi-injection/SKILL.md) (1 hop)
2. **IF** a lookup returns a Reference whose factory specifies a codebase URL **THEN** determine the JDK version and whether trustURLCodebase is true
3. **IF** the JNDI string arrives via a Log4j message lookup **THEN** switch to [`jndi-injection-logging-lookups`](../jndi-injection-logging-lookups/SKILL.md) (1 hop)
4. **IF** the returned reference triggers readObject on a serialized object **THEN** switch to [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) (1 hop)
5. **IF** the JDK is modern and remote codebase loading is blocked by default **THEN** pivot to local factory gadgets such as BeanFactory or GroovyClassLoader
6. **IF** the provider is rmi versus ldap **THEN** confirm which context the lookup resolves by watching the outbound port, 1099 versus 389
7. **IF** a WAF blocks the literal scheme string **THEN** test lower-case and layered forms before concluding the path is closed
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** trustURLCodebase is false and no local factory gadget is reachable **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The JNDI string arrives via a Log4j-style message lookup | [`jndi-injection-logging-lookups`](../jndi-injection-logging-lookups/SKILL.md) | Invariant is log-message interpolation, not codebase trust |
| The returned reference triggers Java object deserialization | [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) | Invariant is gadget execution in readObject, not factory instantiation |
| Need parent class methodology | [`jndi-injection`](../jndi-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the lookup and the reference-handling step.** Confirm the lookup resolves against a directory an attacker can influence and that its result is passed to object-factory instantiation. The reference-to-object step is the decision point.
2. **Read the trustURLCodebase posture and JDK version.** Determine whether com.sun.jndi.ldap.object.trustURLCodebase or the rmi equivalent is true and what JDK build is running. This sets whether the remote-codebase branch or only the local-factory branch is open.
3. **Enumerate reachable local factories.** On a hardened JVM, list classpath factories that double as gadgets (BeanFactory, GroovyClassLoader, an EL evaluator). This decides whether a blocked remote fetch still leaves an exploitable path.
4. **Record a baseline reference resolution.** Point the lookup at an assessor-controlled directory and observe whether the JVM connects at all, capturing the port (389 for ldap, 1099 for rmi).
5. **Probe the codebase-trust differential.** Return a reference naming a remote factory codebase versus one naming a local factory, and watch for a follow-on HTTP GET for a .class file. The fetch appears only when trust is enabled, isolating the flag.
6. **Stop condition.** Halt when the probe (a) shows a remote .class fetch that stops once trustURLCodebase is false, (b) shows the connection but no class load across baselines, or (c) would require serving working factory bytecode. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a server-initiated HTTP fetch for factory bytecode from the assessor host (or a local-factory instantiation), tied to the reference, plus the trustURLCodebase setting. An LDAP connection that never proceeds to a class load proves reachability, not remote loading.
8. **Close with the structural fix and verify.** Keep trustURLCodebase false, resolve names only against a trusted local context, and remove or constrain factory gadgets on the classpath, then replay the remote-codebase reference to confirm no bytecode is fetched.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| com.sun.jndi.ldap.object.trustURLCodebase or the rmi equivalent set to true | Proves remote codebase loading is re-enabled, the precondition for fetching attacker factory bytecode |
| The JVM issuing an HTTP GET for a .class file from a host named in a JNDI Reference | Proves remote class loading actually occurred from the controlled directory response |
| A returned Reference naming a local factory such as BeanFactory or GroovyClassLoader | Proves the modern-JDK bypass path using classpath factories rather than remote bytecode |
| ObjectFactory.getObjectInstance invoked on the result of a lookup | Proves the reference-to-object step that instantiates the attacker-selected factory |
| Outbound RMI on port 1099 followed by a codebase fetch from the same host | Proves the RMI provider path to remote class loading is live |
| trustURLCodebase false and no local factory gadget reachable on the classpath | Proves the structural control holds and only a non-exploitable reference remains |

## Worked Contrast

**Vulnerable pattern:**

```java
// Legacy flag re-enabled so a Reference from LDAP loads a remote codebase
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
Object o = ctx.lookup(name); // factory bytecode fetched from the attacker URL
```

**Hardened pattern:**

```java
// Leave remote codebase trust OFF (the JDK default) and resolve only trusted names
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "false");
System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "false");
// Never follow a Reference codebase URL; use a local, vetted context
Object o = vettedContext.lookup(name);
```

**Why this matters:** Keeping trustURLCodebase false blocks remote factory bytecode loading, so a malicious Reference cannot pull a class from the attacker URL; the only residual risk is local factory gadgets, which a vetted context and classpath hygiene remove.

## When It Is NOT This Issue

- **trustURLCodebase left at the default false:** the JVM will not fetch remote factory bytecode, so a remote-codebase reference is inert.
- **No local factory gadget on the classpath:** on a modern JDK with no BeanFactory, Groovy, or EL gadget, a returned reference cannot instantiate anything dangerous.
- **Lookup resolves only against a local vetted context:** references never carry an attacker codebase because the directory is trusted.
- **Callback observed but class load blocked:** an LDAP connection that does not proceed to a .class fetch shows reachability, not remote loading.
- **Reference with a signed or pinned factory:** a factory restricted to a known class cannot be redirected to attacker bytecode.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `jndi-injection-remote-class-loading` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jndi-injection-remote-class-loading` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: jndi-injection-remote-class-loading
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-917, CWE-502 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`jndi-injection`](../jndi-injection/SKILL.md) - Web and Application (leaf)
- [`jndi-injection-logging-lookups`](../jndi-injection-logging-lookups/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jndi-injection-remote-class-loading` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-917, CWE-502, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
