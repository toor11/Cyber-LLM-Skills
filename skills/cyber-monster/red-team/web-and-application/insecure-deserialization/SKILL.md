---
name: insecure-deserialization
description: Exploits insecure deserialization in Java, PHP, Python, .NET, Ruby and Node gadgets, covering gadget-chain discovery, ysoserial and phpggc payloads, and magic-method abuse. Use when an application deserializes cookies, view state, cache entries, queue messages, or RPC payloads.
family: web-and-application
tier: core
triggers: ["deserialization", "deserialize", "gadget chain", "ysoserial", "phpggc", "pickle", "viewstate", "marshalling"]
cwe: [CWE-502]
owasp: [A08:2021]
attack: [T1059]
capec: [CAPEC-586]
related: [insecure-deserialization-java-gadgets, insecure-deserialization-php-gadgets, insecure-deserialization-python-and-ruby-gadgets, sql-injection]
---

# Insecure Deserialization - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)

## Mechanism and Preconditions

The application takes attacker-reachable bytes (a cookie, view state, a cache or queue entry, or an RPC payload) and reconstructs a language object graph from them, so the deserializer, not the developer, decides which types are instantiated and which of their methods run. Native formats such as Java serialization, PHP serialize, Python pickle, Ruby Marshal, and .NET BinaryFormatter invoke type constructors and magic or callback methods (`readObject`, `__wakeup`, `__reduce__`, `ObjectInputStream`) during the rebuild, so a crafted stream can chain existing classes (a gadget chain) into a dangerous action without any missing patch. The security decision is made at the deserialization call, where the type is resolved, rather than in any later validation. The attacker gains code execution, server-side request issuance, or object-state corruption depending on the gadgets available on the classpath. Confirmation is that supplying a serialized object the application did not issue changes server behaviour, with extraction never required to prove the sink is reachable.

- **Precondition chain:** Attacker-reachable bytes are passed to a native deserializer, the deserializer resolves arbitrary types rather than a fixed allowlist, a usable gadget chain exists on the runtime classpath, and a behavioural difference is observable when a crafted object replaces a legitimate one.
- **Readable differential:** A legitimate serialized token versus a crafted object of a type the application never issues; a finding exists when the crafted object changes server behaviour and the change disappears once the deserializer is restricted to a safe type allowlist or a data-only format.
- **Empirical grounding:** CWE-502 Deserialization of Untrusted Data, under OWASP Top 10:2025 A08:2025 Software or Data Integrity Failures. CVE-2025-10035 (GoAnywhere MFT, CISA KEV), CVE-2025-27818 (Apache Kafka Connect JAAS), and CVE-2025-13081 (Drupal core gadget chain) are 2025 instances.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the runtime is the JVM and the bytes are a Java object stream **THEN** switch to [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) (1 hop)
2. **IF** the application is PHP and uses serialize or unserialize **THEN** switch to [`insecure-deserialization-php-gadgets`](../insecure-deserialization-php-gadgets/SKILL.md) (1 hop)
3. **IF** the runtime is Python pickle or Ruby Marshal **THEN** switch to [`insecure-deserialization-python-and-ruby-gadgets`](../insecure-deserialization-python-and-ruby-gadgets/SKILL.md) (1 hop)
4. **IF** the runtime is .NET with BinaryFormatter, LosFormatter, or ViewState **THEN** switch to [`insecure-deserialization-dotnet-gadgets`](../insecure-deserialization-dotnet-gadgets/SKILL.md) (1 hop)
5. **IF** a deserialized field triggers a JNDI or naming-service lookup **THEN** switch to [`jndi-injection`](../jndi-injection/SKILL.md) because the sink is naming-service trust
6. **IF** the untrusted bytes are XML rather than a native object graph **THEN** switch to [`xxe`](../xxe/SKILL.md) because the invariant is external-entity resolution
7. **IF** the payload reaches an expression evaluator instead of a deserializer **THEN** switch to [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)
9. **IF** only a data-only format is parsed and no native deserializer is reachable **THEN** STOP and classify as a verified non-finding rather than forcing a gadget theory

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A deserialized field drives a JNDI lookup | [`jndi-injection`](../jndi-injection/SKILL.md) | Invariant is naming-service trust, a distinct sink from gadget-chain instantiation |
| The untrusted bytes are XML, not a native object graph | [`xxe`](../xxe/SKILL.md) | Invariant is external-entity resolution rather than magic-method gadget execution |
| The payload reaches an expression evaluator, not a deserializer | [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) | Invariant is expression evaluation rather than object reconstruction |
| Target matches `insecure-deserialization-java-gadgets` | [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `insecure-deserialization-php-gadgets` | [`insecure-deserialization-php-gadgets`](../insecure-deserialization-php-gadgets/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `insecure-deserialization-python-and-ruby-gadgets` | [`insecure-deserialization-python-and-ruby-gadgets`](../insecure-deserialization-python-and-ruby-gadgets/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `insecure-deserialization-dotnet-gadgets` | [`insecure-deserialization-dotnet-gadgets`](../insecure-deserialization-dotnet-gadgets/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the deserialization call and the format.** Find where the application turns attacker-reachable bytes into objects (`ObjectInputStream`, `unserialize`, `pickle.loads`, `Marshal.load`, `BinaryFormatter.Deserialize`) and record the exact byte source: cookie, view state, cache, queue, or RPC.
2. **Classify the runtime and the type policy.** Decide which language runtime resolves the types and whether the deserializer is unrestricted or already constrained by a `SerializationBinder`, `allowed_classes`, or a resolver allowlist, because that policy is the real control.
3. **Confirm the bytes are attacker-reachable and reconstructed.** Verify the input is deserialized before any validation and that the object graph is actually rebuilt, not just stored as opaque bytes.
4. **Record a legitimate-token baseline.** Capture the application's own serialized token and its normal response, so a crafted object can be compared against a known-good object.
5. **Substitute a benign typed object the app never issues.** Send a serialized object of a harmless type that is not part of the normal flow and observe whether the deserializer instantiates it, keeping the object inert rather than a weaponised chain.
6. **Stop condition.** Halt when the substitution either (a) changes server behaviour in a way attributable to type resolution and reverting when an allowlist is applied, (b) is rejected or ignored identically to garbage bytes across two runs, or (c) would require a gadget chain that executes code or exfiltrates data to advance. Case (a) confirms the sink, (b) is a non-finding, (c) is beyond non-destructive verification.
7. **State what counts as proof.** Proof is a behavioural differential showing the deserializer resolved a type the application never issues, tied to the exact deserialization call, without running a destructive gadget. A serialized-looking cookie or an unpickling error alone is not proof.
8. **Close with the structural fix.** Replace the native deserializer with a data-only format plus an integrity check, or constrain it with a strict type allowlist and a `SerializationBinder` or `allowed_classes`, and sign any token that must round-trip. Verify by replaying the legitimate token and the substituted object against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A base64 cookie beginning with `rO0AB` or raw bytes `AC ED 00 05` | Proves a Java serialized object is accepted from the client on any JVM stack, the classic deserialization entry point |
| A PHP value beginning with `O:` for an object or `a:` for an array reaching `unserialize` | Proves PHP object deserialization where `__wakeup` and `__destruct` become gadget triggers |
| A `pickle.loads` or `Marshal.load` call reading request-derived bytes | Proves a Python or Ruby native deserializer that runs reduce or load callbacks during rebuild |
| A `BinaryFormatter.Deserialize` or `LosFormatter` call on client-supplied data | Proves a .NET formatter that resolves arbitrary types, routing to the dotnet gadget skill |
| A deserializer with no `SerializationBinder`, `allowed_classes`, or resolver allowlist | Proves the type policy is open, the structural condition every gadget chain depends on |
| A JAAS or connector config override that causes a login module to deserialize | Proves the Kafka Connect class of reachability mapped to CVE-2025-27818 |
| A license or management servlet deserializing an unauthenticated request | Proves the GoAnywhere MFT class of reachability mapped to CVE-2025-10035 |

## Worked Contrast

**Vulnerable pattern:**

```python
import pickle
import base64

# A session cookie is unpickled, so any gadget on the import path runs on load
def load_session(cookie_value):
    return pickle.loads(base64.b64decode(cookie_value))
```

**Hardened pattern:**

```python
import json
import hmac
import hashlib
import base64

# Data-only format plus an integrity check: no object graph is reconstructed
def load_session(token, key):
    body, sig = token.rsplit(".", 1)
    expected = hmac.new(key, body.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(base64.urlsafe_b64decode(sig), expected):
        raise ValueError("session signature mismatch")
    return json.loads(base64.urlsafe_b64decode(body))   # returns a plain dict
```

**Why this matters:** The vulnerable loader lets the deserializer decide which types to instantiate, so a crafted pickle runs gadget code during the rebuild. The fix removes object reconstruction entirely by using a data-only format and verifies integrity with an HMAC, so untrusted bytes can never resolve a dangerous type.

## When It Is NOT This Issue

- **Data-only format in use:** JSON, protobuf, or MessagePack parsed into plain structures does not reconstruct arbitrary types, so there is no gadget sink.
- **Signed token verified before decode:** a serialized blob whose signature is checked with a secret the attacker lacks cannot be substituted.
- **Type allowlist enforced:** a `SerializationBinder`, `allowed_classes`, or resolver that rejects unknown types closes the gadget path even on a native format.
- **No gadget on the classpath:** a reachable native deserializer with no usable gadget chain in the loaded libraries cannot be driven to impact.
- **Opaque bytes never deserialized:** a serialized-looking value that is only stored or forwarded, never reconstructed, has no deserialization sink.
- **Unpickling error mistaken for a finding:** an exception on malformed bytes shows the parser ran, not that an attacker-chosen type was resolved.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `insecure-deserialization` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `insecure-deserialization` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: insecure-deserialization
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-502 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) - Blue Detection/Defense Counterpart
- [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) - Web and Application (leaf)
- [`insecure-deserialization-php-gadgets`](../insecure-deserialization-php-gadgets/SKILL.md) - Web and Application (leaf)
- [`insecure-deserialization-python-and-ruby-gadgets`](../insecure-deserialization-python-and-ruby-gadgets/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `insecure-deserialization` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-502, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 50 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (31), CYBER_CPT/ctf_search (7), hackerone_disclosed_reports (3), CYBER_CPT/L5/ctf_search (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 6 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
