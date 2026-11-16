---
name: jndi-injection
description: Exploits JNDI lookups in Java applications and logging frameworks, including Log4Shell-style message lookups and LDAP or RMI remote class loading with modern JDK trust bypasses. Use when a Java application logs or looks up attacker-controlled strings.
family: web-and-application
tier: leaf
triggers: ["jndi injection", "log4shell", "log4j", "ldap injection java", "rmi class loading", "jndi lookup"]
cwe: [CWE-917, CWE-502]
owasp: [A03:2021]
attack: [T1190]
capec: [CAPEC-242]
related: [jndi-injection-logging-lookups, jndi-injection-remote-class-loading, sql-injection, cross-site-scripting]
---

# Jndi Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A Java component passes an attacker-influenced name or PROVIDER_URL into a JNDI operation such as InitialContext.lookup or a JMS, JCR, or JDBC resource lookup, and JNDI contacts whatever directory the URI names and acts on the object it returns. The security decision is the set of protocols and destinations the lookup may use: a naming service can hand back a Reference that causes a remote factory to load or a serialized object to be deserialized. The break is that the lookup destination, not merely a value, is under attacker control. The attacker gains code execution or an outbound connection issued by the server itself. A non-destructive probe points the lookup at an assessor-controlled host and watches for the callback, proving destination control without returning a malicious object.

- **Precondition chain:** A request value reaches a JNDI lookup as the name or provider URL, the JNDI layer permits dangerous schemes such as ldap, rmi, dns, or iiop, and the attacker can stand up or redirect to a naming service the server will contact.
- **Readable differential:** A lookup against a trusted jms or java name versus the same parameter set to ldap://assessor-host: only the second produces an outbound lookup to the assessor host, and that connection stops once a JMS-protocol allowlist like the CXF JndiHelper fix rejects the scheme.
- **Empirical grounding:** CWE-917 and CWE-502 under OWASP Top 10:2025 A05 Injection. CVE-2025-48913 (Apache CXF JMS JndiHelper accepting ldap:// and rmi:// PROVIDER_URL, fixed by a JMS-protocol allowlist) and CVE-2025-58782 (Apache Jackrabbit JCR lookup via untrusted JNDI URI, JNDI disabled by default in 2.22.2) anchor it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the injection arrives through a Log4j-style message lookup in a logged string **THEN** switch to [`jndi-injection-logging-lookups`](../jndi-injection-logging-lookups/SKILL.md) (1 hop)
2. **IF** the goal is loading a remote factory class or defeating trustURLCodebase **THEN** switch to [`jndi-injection-remote-class-loading`](../jndi-injection-remote-class-loading/SKILL.md) (1 hop)
3. **IF** a request value sets Context.PROVIDER_URL or the name argument of InitialContext.lookup **THEN** treat the lookup destination as attacker-controlled and classify the scheme
4. **IF** the scheme in the name is ldap, rmi, dns, or iiop **THEN** confirm whether a protocol allowlist like the CXF JndiHelper fix is present
5. **IF** the untrusted bytes are a serialized Java object rather than a JNDI name **THEN** switch to [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) (1 hop)
6. **IF** the injection is into an LDAP search filter, not a JNDI URI **THEN** switch to [`ldap-and-xpath-injection`](../ldap-and-xpath-injection/SKILL.md) (1 hop)
7. **IF** a filter rejects the literal ${jndi: token **THEN** test layered lookups such as ${lower:} before concluding the control holds
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the provider URL is fixed from trusted configuration and no request value reaches a lookup **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The untrusted stream is a serialized Java object, not a JNDI name | [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) | Invariant is ObjectInputStream gadget execution, not naming-service lookup |
| The injection is into an LDAP search filter rather than a JNDI URI | [`ldap-and-xpath-injection`](../ldap-and-xpath-injection/SKILL.md) | Invariant is filter-metacharacter neutralization, not lookup-destination control |
| Target matches `jndi-injection-logging-lookups` | [`jndi-injection-logging-lookups`](../jndi-injection-logging-lookups/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `jndi-injection-remote-class-loading` | [`jndi-injection-remote-class-loading`](../jndi-injection-remote-class-loading/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the JNDI operation and identify what feeds the name.** Find InitialContext.lookup, a JMS ConnectionFactory lookup, a JCR or JDBC provider setup, and record whether a request value becomes the name or the PROVIDER_URL. The lookup call is the decision point.
2. **Classify the scheme the lookup will use.** Extract the scheme from the attacker-influenced URI. jms and java are inert carriers; ldap, ldaps, rmi, dns, and iiop are the schemes that let a Reference load a factory or deserialize an object.
3. **Check for a protocol allowlist.** Read whether the code constrains permitted schemes (as the CXF JndiHelper fix does) or disables JNDI by default (as Jackrabbit does after its fix). The branch is an allowlisted lookup versus an open one.
4. **Record an outward baseline.** Set the name to an assessor-controlled host and confirm whether the server resolves or connects to it at all, capturing the originating address so server origin is provable.
5. **Probe the scheme differential.** Compare an allowed jms or java name against an ldap or rmi URI pointing at the assessor host. A callback that arrives only for the dangerous scheme isolates the missing allowlist, with no object returned.
6. **Stop condition.** Halt when the probe (a) yields a server-issued lookup to the assessor host that stops once a protocol allowlist is applied, (b) is refused identically for every dangerous scheme, or (c) would require returning a malicious Reference or object. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an outbound lookup originating from the server's egress to a destination only the server could reach, tied to the request parameter, plus the lookup source line and the absent scheme allowlist. A DNS resolution alone proves parsing, not that a lookup was issued.
8. **Close with the structural fix and verify.** Restrict the lookup to an allowlist of safe protocols, resolve names only against a trusted local context, or disable JNDI where unused, then replay the ldap/rmi probe to confirm the callback no longer occurs.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A request value assigned to Context.PROVIDER_URL or the name argument of InitialContext.lookup | Proves the lookup destination is attacker-influenced, the entry condition for JNDI injection on a Java stack |
| A lookup name whose scheme is ldap, rmi, dns, or iiop derived from input | Proves a dangerous naming protocol is reachable, which is what turns a lookup into an outbound fetch |
| An outbound connection from the JVM to an assessor host named only in a request parameter | Proves destination control non-destructively, without the directory returning any object |
| A JMS, JCR, or JDBC connector that accepts a provider URL from a configuration override | Proves a real-world carrier for the sink, as in the CXF JMS and DataEase datasource cases |
| Absence of a protocol allowlist around the naming lookup | Proves the structural control the CXF JndiHelper fix added is missing on this code path |
| A NamingException or CommunicationException naming an attacker-looking provider URL | Proves the lookup attempted to contact the controlled destination |

## Worked Contrast

**Vulnerable pattern:**

```java
// PROVIDER_URL and name taken from the request control where the lookup connects
Hashtable<String, Object> env = new Hashtable<>();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
env.put(Context.PROVIDER_URL, req.getParameter("broker"));
Context ctx = new InitialContext(env);
return ctx.lookup(req.getParameter("name"));
```

**Hardened pattern:**

```java
private static final Set<String> ALLOWED = Set.of("jms", "java"); // no ldap/rmi/dns

// env is built from trusted configuration only, never from the request
Context ctx = new InitialContext(env);
String uri = req.getParameter("name");
String scheme = URI.create(uri).getScheme();
if (scheme != null && !ALLOWED.contains(scheme.toLowerCase())) {
    throw new NamingException("JNDI scheme not permitted: " + scheme);
}
return ctx.lookup(uri);
```

**Why this matters:** The fix mirrors the CXF JndiHelper remediation: an allowlist of permitted protocols rejects ldap:// and rmi:// provider URLs before the naming lookup connects outward, and the provider environment is no longer request-derived. Destination control moves back to the server.

## When It Is NOT This Issue

- **Provider URL fixed from trusted configuration:** the lookup target is read from environment or a constant, so no request value steers the destination.
- **Protocol allowlist enforced:** the naming layer permits only jms or java schemes, rejecting ldap and rmi as the CXF fix does.
- **DNS callback without a connection:** a resolver that pre-resolves a name for validation proves resolution, not that a JNDI lookup was issued to the host.
- **Lookup of a value, not a destination:** input that becomes a leaf attribute of a fixed name, not the name or provider URL itself, does not control where the lookup connects.
- **Naming exception on an internally built name:** an error during a trusted lookup, with no attacker input in the name, is not injection.
- **JNDI disabled by default:** a component shipping with JNDI lookups turned off, as Jackrabbit does after its fix, has no reachable sink.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `jndi-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jndi-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: jndi-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-917, CWE-502 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`jndi-injection-logging-lookups`](../jndi-injection-logging-lookups/SKILL.md) - Web and Application (leaf)
- [`jndi-injection-remote-class-loading`](../jndi-injection-remote-class-loading/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jndi-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-917, CWE-502, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 25 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/oxdf (6), OffsecCyber (5), CYBER_CPT/github_security_md (5), CYBER_CPT/ctf_search (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
