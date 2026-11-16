---
name: insecure-deserialization-java-gadgets
description: Java deserialization gadget chains. Covers identifying ObjectInputStream sinks, ysoserial chain selection per library set, and JRMP or URLDNS confirmation paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["java deserialization", "ysoserial", "objectinputstream", "jrmp", "java gadget"]
cwe: [CWE-502]
owasp: [A08:2021]
attack: [T1059]
capec: [CAPEC-586]
related: [insecure-deserialization, insecure-deserialization-php-gadgets, insecure-deserialization-python-and-ruby-gadgets, insecure-deserialization-dotnet-gadgets]
parent: insecure-deserialization
---

# Insecure Deserialization Java Gadgets - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)

## Mechanism and Preconditions

A Java endpoint reconstructs an object graph by calling ObjectInputStream.readObject on bytes it received from a request, so the stream itself dictates which classes are instantiated and which of their callback methods (readObject, readResolve, finalize) run. The security decision is the resolveClass step: a default ObjectInputStream accepts any Serializable type on the classpath, so an attacker chains library classes such as Commons-Collections transformers, Spring beans, Groovy, or JRMPClient into a sequence whose side effects reach a command or lookup sink. Nothing in the payload is attacker-written code; the exploit is a composition of trusted gadget classes already shipped with the application, and the gain is code execution or an outbound JNDI/RMI connection with the JVM's privileges. Confirmation is non-destructive: a URLDNS object triggers a single DNS resolution during deserialization and proves the sink is live without running a chain.

- **Precondition chain:** Untrusted bytes reach an ObjectInputStream.readObject call, no strict resolveClass allowlist constrains the admissible types, and at least one gadget library is present on the classpath.
- **Readable differential:** A benign serialized String versus a URLDNS object sent to the same endpoint: only the latter produces an outbound DNS lookup, and that lookup disappears once a resolveClass allowlist rejects the unexpected class.
- **Empirical grounding:** CWE-502 maps this to OWASP Top 10:2025 A08 Software or Data Integrity Failures. CVE-2025-10035 (GoAnywhere MFT License Servlet) and CVE-2025-27818 (Apache Kafka Connect LDAP JAAS deserialization via a connector config override) are 2025 Java readObject instances.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the class profile is not yet confirmed as Java serialization **THEN** start at the parent class [`insecure-deserialization`](../insecure-deserialization/SKILL.md) (1 hop)
2. **IF** the stream carries the 0xACED magic or a rO0AB base64 prefix reaches an ObjectInputStream **THEN** treat the readObject call as the sink and inventory gadget libraries on the classpath
3. **IF** the payload is a .NET BinaryFormatter or Remoting stream **THEN** switch to [`insecure-deserialization-dotnet-gadgets`](../insecure-deserialization-dotnet-gadgets/SKILL.md) (1 hop)
4. **IF** the deserialization is reached through a JNDI Reference or JAAS config override **THEN** switch to [`jndi-injection`](../jndi-injection/SKILL.md) (1 hop)
5. **IF** the framework is Jackson, XStream, or SnakeYAML polymorphic typing rather than native serialization **THEN** focus on the type-handling gadget set and the enableDefaultTyping or alias configuration
6. **IF** a Commons-Collections, Spring, or Groovy jar is present and user bytes reach readObject **THEN** use a DNS-only URLDNS object to confirm the sink before any further class is tried
7. **IF** the serialized blob rides in a cookie, Authorization header, or ViewState field **THEN** capture the exact transport and content type before probing
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)
9. **IF** no untrusted bytes reach a readObject or the stream is behind a strict resolveClass allowlist **THEN** STOP and record a verified non-finding rather than reporting the mere presence of serialization

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The sink is a JNDI name resolved during deserialization rather than a gadget chain | [`jndi-injection`](../jndi-injection/SKILL.md) | Invariant is naming-service lookup, not ObjectInputStream gadget execution |
| The payload is a .NET Remoting or BinaryFormatter stream | [`insecure-deserialization-dotnet-gadgets`](../insecure-deserialization-dotnet-gadgets/SKILL.md) | Different runtime formatter and gadget universe entirely |
| Need parent class methodology | [`insecure-deserialization`](../insecure-deserialization/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the readObject sink and classify the stream source.** Read the data layer for ObjectInputStream, XMLDecoder, or a polymorphic mapper, and record whether the bytes arrive as a cookie, header, ViewState, or RMI/JMX call. The sink, not the controller, is the decision point.
2. **Determine whether a resolveClass allowlist exists.** Inspect for an ObjectInputStream subclass that overrides resolveClass, a look-ahead filter (ObjectInputFilter), or a serialization-free alternative. The branch is set by evidence here: an open readObject versus a filtered one.
3. **Inventory the gadget surface.** Enumerate classpath jars (commons-collections, commons-beanutils, groovy, spring-core) that supply known transformer or template gadgets. This decides whether an open sink is merely a robustness bug or a code-execution path.
4. **Record a deterministic baseline.** Send a benign serialized object of the expected type and capture status, length, and timing. This is the control the probe must diverge from.
5. **Send a URLDNS differential.** Deserialize an object whose only effect is a DNS resolution to an assessor-controlled host. A lookup that fires only for the URLDNS object and not the baseline isolates the sink without executing a chain.
6. **Stop condition.** Halt when the probe (a) produces a DNS callback that disappears once a resolveClass allowlist is applied, (b) produces no callback across two baselines, or (c) would require running an actual command or write gadget. Case (a) confirms, (b) is a non-finding, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is the URLDNS callback tied to one changed variable (the serialized class), the exact readObject source line reached by untrusted bytes, and the absence of a resolveClass filter. A deserialization stack trace alone is not proof.
8. **Close with the structural fix and verify.** Replace the open stream with a narrow ObjectInputFilter or a resolveClass override that permits only the single expected class, or move to a schema-bound format such as JSON with polymorphic typing disabled, then replay the URLDNS object to confirm the callback no longer fires.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A request parameter or cookie that base64-decodes to a stream beginning rO0AB (bytes AC ED 00 05) | Proves a Java serialized object is reaching the endpoint, the entry condition for a readObject sink on any JVM stack |
| A call to ObjectInputStream.readObject with no overridden resolveClass in the data layer | Proves the admissible-class allowlist is absent, so any Serializable gadget on the classpath can be instantiated |
| commons-collections, commons-beanutils, groovy, or spring-core present on the classpath | Proves gadget libraries exist to chain, which turns an open readObject into code execution on the JVM |
| A single outbound DNS lookup to an assessor host during deserialization of a URLDNS object | Proves the sink deserializes untrusted bytes without executing a chain, the canonical non-destructive confirmation |
| InvalidClassException or ClassNotFoundException thrown from resolveClass on an unexpected type | Proves an allowlist is actually filtering classes, which is a working control rather than a finding |
| Serialized Java Remote Method Protocol traffic to a registry on port 1099 after a lookup | Proves the gadget reached an RMI sink, escalating reachability on the Java tier |
| A ViewState, rememberMe cookie, or RMI endpoint carrying the serialization magic | Proves a common real-world transport for the blob, narrowing where to place the probe |

## Worked Contrast

**Vulnerable pattern:**

```java
// License blob arrives base64 in an HTTP parameter and is deserialized directly
public Object loadLicense(HttpServletRequest req) throws Exception {
    byte[] blob = Base64.getDecoder().decode(req.getParameter("license"));
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(blob));
    return ois.readObject(); // any Serializable on the classpath is instantiated
}
```

**Hardened pattern:**

```java
// Only the single expected value type may ever leave the stream
public License loadLicense(HttpServletRequest req) throws Exception {
    byte[] blob = Base64.getDecoder().decode(req.getParameter("license"));
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(blob)) {
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!desc.getName().equals(License.class.getName()))
                throw new InvalidClassException("blocked", desc.getName());
            return super.resolveClass(desc);
        }
    };
    return (License) ois.readObject();
}
```

**Why this matters:** The fix narrows resolveClass to a single expected class, so no gadget class (CommonsCollections, JRMPClient) can be instantiated, instead of trusting whatever Serializable type the stream names. The security decision moves from the attacker's bytes to a server-side allowlist.

## When It Is NOT This Issue

- **Serialization magic with a strict resolveClass allowlist:** the blob is a Java object stream, but the ObjectInputStream subclass rejects every class except an expected type, so no gadget can instantiate.
- **Gadget library present but no untrusted bytes reach readObject:** the dangerous jars exist, yet the only deserialization is of internally produced, trusted data.
- **HTTP 500 from a parse failure alone:** a deserialization exception without a reachable attacker-controlled stream is a robustness bug, not confirmed CWE-502 evidence.
- **Signed or MACed serialized payloads:** a blob whose integrity is verified by a keyed HMAC envelope before readObject cannot be attacker-substituted.
- **Caller-scoped object only:** reconstruction that affects nothing beyond the caller's own transient state, with no code-execution or outbound-connection sink, is not exploitable.
- **Allowlist-based JSON typing:** a Jackson or Gson configuration that forbids polymorphic default typing means a type-confusion gadget cannot be selected.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `insecure-deserialization-java-gadgets` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `insecure-deserialization-java-gadgets` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: insecure-deserialization-java-gadgets
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-502 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) - Blue Detection/Defense Counterpart
- [`insecure-deserialization`](../insecure-deserialization/SKILL.md) - Web and Application (core)
- [`insecure-deserialization-php-gadgets`](../insecure-deserialization-php-gadgets/SKILL.md) - Web and Application (leaf)
- [`insecure-deserialization-python-and-ruby-gadgets`](../insecure-deserialization-python-and-ruby-gadgets/SKILL.md) - Web and Application (leaf)
- [`insecure-deserialization-dotnet-gadgets`](../insecure-deserialization-dotnet-gadgets/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `insecure-deserialization-java-gadgets` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-502, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 39 |
| Distinct dataset sources | 10 |
| Top sources | OffsecCyber (10), CYBER_CPT/oxdf (8), CYBER_CPT/github_security_md (6), CYBER_CPT/hacktricks (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
