---
name: insecure-deserialization-dotnet-gadgets
description: NET deserialization gadget chains. Covers BinaryFormatter, LosFormatter and ViewState deserialization, ysoserial.net chains, and machine-key recovery to forge ViewState. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["net deserialization", "viewstate", "binaryformatter", "ysoserial.net", "machinekey"]
cwe: [CWE-502]
owasp: [A08:2021]
attack: [T1059]
capec: [CAPEC-586]
related: [insecure-deserialization, insecure-deserialization-java-gadgets, insecure-deserialization-php-gadgets, insecure-deserialization-python-and-ruby-gadgets]
parent: insecure-deserialization
---

# Insecure Deserialization Dotnet Gadgets - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)

## Mechanism and Preconditions

On .NET the same deserialization risk is concentrated in formatters that rebuild typed object graphs from attacker-reachable bytes: BinaryFormatter and LosFormatter, the ObjectStateFormatter behind ASP.NET ViewState, and the formatters used by .NET Remoting channels. ViewState is the canonical carrier, a base64 blob posted back in `__VIEWSTATE` that the server deserializes, so when its message authentication code is disabled or the `machineKey` is known, a forged ViewState resolves attacker-chosen types. Remoting adds a second path: a channel configured with a broad `TypeFilterLevel` or a permissive type whitelist resolves gadget types straight off the wire. The decision is made at the formatter's type resolution, where a `SerializationBinder` either constrains or permits the type, not in any later check. The attacker gains code execution in the worker process through a ysoserial.net-style chain. Confirmation is that a forged or substituted typed payload is deserialized, which an integrity check or a strict binder would have refused.

- **Precondition chain:** A .NET formatter deserializes attacker-reachable bytes (ViewState, a remoting payload, or a BinaryFormatter stream), ViewState MAC is disabled or the machineKey is recoverable or the remoting whitelist is broad, a gadget type is present in the loaded assemblies, and a behavioural difference is observable when a forged typed object is supplied.
- **Readable differential:** A legitimate ViewState or remoting payload versus a forged one carrying a type the application never emits; a finding exists when the forged payload is deserialized and the effect disappears once ViewState MAC is enforced or the remoting binder is restricted to an allowlist.
- **Empirical grounding:** CWE-502 under OWASP Top 10:2025 A08:2025. CVE-2025-48983 and CVE-2025-48984 (Veeam Backup & Replication) are 2025 .NET Remoting deserialization flaws caused by an overly broad type whitelist in the remoting channel, fixed in 12.3.2.4165.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not confirmed to be a .NET formatter sink **THEN** start at parent class [`insecure-deserialization`](../insecure-deserialization/SKILL.md) first
2. **IF** the carrier is an ASP.NET `__VIEWSTATE` postback **THEN** treat ViewState MAC and machineKey handling as the primary finding surface
3. **IF** ViewState MAC is enabled but the machineKey may be known or default **THEN** test whether a forged ViewState is accepted before assuming MAC protects it
4. **IF** the sink is a .NET Remoting channel with a broad type whitelist **THEN** treat the remoting binder as the primary finding, the CVE-2025-48983 and CVE-2025-48984 shape
5. **IF** the formatter is BinaryFormatter or LosFormatter reached outside ViewState **THEN** trace the exact call and whether a SerializationBinder constrains it
6. **IF** the gadget runtime is the JVM, not the CLR **THEN** switch to [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) for the Java object stream
7. **IF** ViewState is protected but a deserialized field triggers a JNDI or LDAP lookup **THEN** switch to [`jndi-injection`](../jndi-injection/SKILL.md) because the sink is naming-service trust
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)
9. **IF** ViewState MAC is enforced, the machineKey is secret, and the remoting binder is an allowlist **THEN** STOP and classify as a verified non-finding because type resolution is constrained

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The gadget runtime is the JVM, not the CLR | [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) | Invariant is Java ObjectInputStream type resolution, a different gadget ecosystem |
| ViewState is protected but a JNDI or LDAP URI is deserialized | [`jndi-injection`](../jndi-injection/SKILL.md) | Invariant is naming-service trust rather than BinaryFormatter type resolution |
| Need parent class methodology | [`insecure-deserialization`](../insecure-deserialization/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the .NET formatter and its carrier.** Identify whether the sink is ViewState through `ObjectStateFormatter`, a direct `BinaryFormatter` or `LosFormatter` call, or a Remoting channel, and record where the bytes enter.
2. **Determine the protection state.** For ViewState, read whether `enableViewStateMac` is on and whether the `machineKey` is explicit, default, or derivable; for Remoting, read the `TypeFilterLevel` and any type whitelist, because that policy is the control.
3. **Confirm the bytes are deserialized before validation.** Verify the formatter resolves the type graph on receipt rather than treating the payload as opaque, and that the carrier is attacker-reachable.
4. **Record a legitimate-payload baseline.** Capture a normal ViewState or remoting message and its response, so a forged or substituted typed payload has a known-good comparison.
5. **Substitute a benign unexpected type.** Supply a forged ViewState or remoting payload carrying a harmless type the application never emits, and observe whether the formatter instantiates it, keeping the object inert rather than a weaponised chain.
6. **Stop condition.** Halt when the substitution either (a) is deserialized in a way attributable to missing MAC or a broad whitelist and reverting when the binder or MAC is enforced, (b) is rejected identically to random bytes across two runs, or (c) would require a ysoserial.net code-execution chain to advance. Case (a) confirms, (b) is a non-finding, (c) is beyond non-destructive verification.
7. **State what counts as proof.** Proof is a behavioural differential showing the formatter resolved a type the application never emits (a forged ViewState accepted, or a non-whitelisted remoting type instantiated), tied to the formatter call, without running a destructive gadget. A `__VIEWSTATE` field alone or a MAC-validation error is not proof.
8. **Close with the structural fix.** Enforce `enableViewStateMac` with ViewState encryption and a per-application secret `machineKey`, remove BinaryFormatter and LosFormatter from untrusted paths, and set the Remoting `TypeFilterLevel` to Low with a strict `SerializationBinder` allowlist. Verify by replaying the forged payload against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `__VIEWSTATE` postback field accepted without a valid message authentication code | Proves ViewState deserialization is forgeable on ASP.NET when MAC is disabled, the classic .NET gadget carrier |
| A `machineKey` that is default, shared across hosts, or present in a config leak | Proves ViewState can be forged even with MAC on, because the signing key is recoverable |
| A .NET Remoting channel configured with `TypeFilterLevel.Full` | Proves the channel resolves arbitrary types, the overly broad policy behind CVE-2025-48983 and CVE-2025-48984 |
| A remoting type whitelist that includes general-purpose or gadget-bearing types | Proves the allowlist is too broad to stop a gadget chain on Veeam-class deployments |
| A `BinaryFormatter.Deserialize` or `LosFormatter.Deserialize` call on client-supplied data | Proves a formatter that resolves arbitrary types with no `SerializationBinder` constraint |
| An `ObjectStateFormatter` invoked on request input outside the normal page lifecycle | Proves a ViewState deserialization sink reachable by a crafted postback |
| No `SerializationBinder` set on any of the above formatters | Proves the type policy is open, the structural condition a .NET gadget chain requires |

## Worked Contrast

**Vulnerable pattern:**

```csharp
// .NET Remoting channel accepts a broad type whitelist, so gadget types resolve
channelProps["typeFilterLevel"] = TypeFilterLevel.Full;   // full deserialization of any type
var formatter = new BinaryServerFormatterSinkProvider();
var obj = formatter.Deserialize(remotingStream);           // no binder, any type instantiated
```

**Hardened pattern:**

```csharp
// Restrict the channel to remoting plumbing and allowlist only expected DTO types
channelProps["typeFilterLevel"] = TypeFilterLevel.Low;    // primitives + remoting only
var formatter = new BinaryServerFormatterSinkProvider();
formatter.Binder = new AllowListBinder(new[] {
    "MyApp.Dto.Job", "MyApp.Dto.Result"
});                                                        // unknown types throw
var obj = formatter.Deserialize(remotingStream);
```

**Why this matters:** The vulnerable channel sets a broad type filter and no binder, so a remoting payload can resolve gadget types, which is the overly broad whitelist behind the Veeam CVEs. The fix lowers the filter level and pins a strict allowlist binder, so only expected DTO types resolve and gadget types throw on sight.

## When It Is NOT This Issue

- **ViewState MAC enforced with a secret machineKey:** a signed, per-application ViewState that cannot be forged leaves no deserialization avenue through that carrier.
- **Remoting binder is a tight allowlist:** a channel at `TypeFilterLevel.Low` with a strict `SerializationBinder` rejects gadget types outright.
- **BinaryFormatter removed from untrusted paths:** when no attacker-reachable formatter resolves arbitrary types, there is no .NET gadget sink.
- **No gadget assembly loaded:** a reachable formatter with no usable ysoserial.net gadget in the loaded assemblies cannot be driven to impact.
- **MAC-validation error mistaken for a finding:** a rejection of a tampered ViewState shows the control working, not a vulnerability.
- **Opaque ViewState never deserialized server-side:** a `__VIEWSTATE` value only echoed or stored, not fed to a formatter, has no sink.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `insecure-deserialization-dotnet-gadgets` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `insecure-deserialization-dotnet-gadgets` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: insecure-deserialization-dotnet-gadgets
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-502 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) - Blue Detection/Defense Counterpart
- [`insecure-deserialization`](../insecure-deserialization/SKILL.md) - Web and Application (core)
- [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) - Web and Application (leaf)
- [`insecure-deserialization-php-gadgets`](../insecure-deserialization-php-gadgets/SKILL.md) - Web and Application (leaf)
- [`insecure-deserialization-python-and-ruby-gadgets`](../insecure-deserialization-python-and-ruby-gadgets/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `insecure-deserialization-dotnet-gadgets` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-502, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/oxdf (5), CYBER_CPT/github_security_md (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
