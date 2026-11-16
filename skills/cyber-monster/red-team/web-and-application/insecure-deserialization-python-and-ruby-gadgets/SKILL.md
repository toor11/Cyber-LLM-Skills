---
name: insecure-deserialization-python-and-ruby-gadgets
description: Python and Ruby deserialization attacks. Covers pickle and yaml unsafe load exploitation, PyYAML tags, Ruby Marshal and YAML.load gadget paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["pickle deserialization", "python deserialization", "ruby marshal", "yaml load"]
cwe: [CWE-502]
owasp: [A08:2021]
attack: [T1059]
capec: [CAPEC-586]
related: [insecure-deserialization, insecure-deserialization-java-gadgets, insecure-deserialization-php-gadgets, insecure-deserialization-dotnet-gadgets]
parent: insecure-deserialization
---

# Insecure Deserialization Python and Ruby Gadgets - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)

## Mechanism and Preconditions

The application loads a serialized blob with pickle.loads, PyYAML's unsafe load, or Ruby's Marshal.load, and these formats are designed to reconstruct arbitrary objects, so a pickle __reduce__ opcode or a YAML !!python/object tag names a callable and its arguments directly. Unlike a data format, the opcode stream is effectively a small program the loader executes during reconstruction. The decision point is the choice of loader: pickle and Marshal trust the stream, while json and yaml.safe_load never instantiate application objects. The attacker gains interpreter-level code execution in the worker process. A non-destructive probe distinguishes the loader by sending a tagged YAML or a pickle stream that only an unsafe loader accepts, carrying no payload that executes.

- **Precondition chain:** Untrusted bytes reach pickle.loads, an unsafe yaml.load, or Marshal.load, the loader is the object-reconstructing variant rather than a safe one, and the attacker can supply the full serialized stream.
- **Readable differential:** A plain JSON or scalar body versus a pickle stream (0x80 prefix) or a !!python/object YAML document: the unsafe loader reconstructs the object while a safe loader rejects or ignores the tag, and acceptance stops once the code switches to yaml.safe_load or json.
- **Empirical grounding:** CWE-502 under OWASP Top 10:2025 A08 Software or Data Integrity Failures. SOURCES.md lists no Python pickle or Ruby Marshal advisory, so this stays at taxonomy level across pickle opcodes, PyYAML object tags, and Marshal.load.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the class profile is not yet confirmed as Python or Ruby deserialization **THEN** start at the parent class [`insecure-deserialization`](../insecure-deserialization/SKILL.md) (1 hop)
2. **IF** a base64 body decodes to a pickle stream starting with 0x80 and reaches pickle.loads **THEN** treat pickle.loads as the sink because __reduce__ runs during load
3. **IF** the input is YAML and the loader is yaml.load without SafeLoader **THEN** treat the !!python/object tag path as the trigger
4. **IF** the stream begins with the Ruby Marshal magic 0x04 0x08 and reaches Marshal.load **THEN** treat Marshal.load as the sink on the Rack or Rails tier
5. **IF** the payload is Java or .NET serialization, not pickle or Marshal **THEN** switch to [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) (1 hop)
6. **IF** the deserialized object feeds a template render or a format call **THEN** consider [`ssti`](../ssti/SKILL.md) (1 hop) for the downstream evaluation
7. **IF** the data is only JSON parsed by json.loads or JSON.parse **THEN** treat as inert structured data unless a custom object_hook reconstructs classes
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)
9. **IF** loading uses yaml.safe_load or json, or Marshal is never fed untrusted bytes **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The deserialized data drives a template render or format expression | [`ssti`](../ssti/SKILL.md) | Invariant is template expression evaluation, not object reconstruction |
| The same logical payload reaches a Java or .NET service boundary | [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) | Different runtime serializer and gadget universe |
| Need parent class methodology | [`insecure-deserialization`](../insecure-deserialization/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the loader call and its input.** Find pickle.loads, yaml.load, cPickle, or Marshal.load reached by a request body, cookie, cache value, or message. The loader, not the view, is the decision point.
2. **Classify the loader as safe or object-reconstructing.** pickle, cPickle, Marshal, and yaml.load (FullLoader or no loader) reconstruct objects; json.loads, JSON.parse, and yaml.safe_load do not. The branch is chosen from which function the code calls.
3. **Identify the format from the byte signature.** A 0x80 prefix is a pickle protocol-2+ stream, 0x04 0x08 is Ruby Marshal, and a !!python/object or !!ruby/object tag marks an unsafe YAML path. This tells you which non-destructive probe to use.
4. **Record a safe-data baseline.** Send a JSON or plain scalar the handler accepts and capture the response. This control establishes normal behavior.
5. **Send a loader-discriminating differential.** Send a tagged YAML document or a pickle of a builtin tuple with a benign marker; an unsafe loader reconstructs it while a safe loader raises a constructor error. The divergence identifies the loader without executing a chain.
6. **Stop condition.** Halt when the probe (a) shows object reconstruction that stops under yaml.safe_load or json, (b) shows no reconstruction across two baselines, or (c) would require a __reduce__ or Marshal gadget that runs a command. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a loader-specific reconstruction tied to the tagged or opcode-prefixed input, the loader source line reached by untrusted bytes, and the loader being an unsafe variant. An UnpicklingError on an opaque blob alone is not proof.
8. **Close with the structural fix and verify.** Replace pickle.loads and Marshal.load on untrusted input with json, and replace yaml.load with yaml.safe_load, signing any blob that must stay binary; then replay the tagged probe to confirm the loader now rejects it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A base64 body that decodes to bytes starting with 0x80 reaching pickle.loads | Proves a pickle stream is being deserialized, where a __reduce__ opcode executes during load on a Python stack |
| yaml.load called without SafeLoader on request data | Proves the unsafe YAML path is reachable, so a !!python/object tag can instantiate arbitrary callables |
| A YAML document containing a !!python/object/apply or !!ruby/object tag | Proves the payload is targeting the object-construction path rather than plain data |
| Marshal.load invoked on params or a cookie in a Rack or Rails handler | Proves Ruby Marshal reconstruction of untrusted bytes, the entry condition for a Marshal gadget |
| _pickle.UnpicklingError or a __reduce__ frame in a Python traceback on request handling | Proves the loader is parsing attacker bytes, confirming sink reachability |
| The code path uses yaml.safe_load, json.loads, or JSON.parse exclusively | Proves a safe loader that never instantiates application objects, a working control |

## Worked Contrast

**Vulnerable pattern:**

```python
import pickle, base64

def load_state(request):
    blob = base64.b64decode(request.cookies["state"])
    return pickle.loads(blob)  # __reduce__ runs during load
```

**Hardened pattern:**

```python
import json

def load_state(request):
    # JSON reconstructs only dict/list/str/number, never arbitrary objects
    state = json.loads(request.cookies["state"])
    if not isinstance(state, dict):
        raise ValueError("state must be an object")
    return state
```

**Why this matters:** json.loads cannot invoke a constructor or a __reduce__ callable, so no gadget runs during load; the cookie becomes inert structured data. If a binary format is required, the blob must be HMAC-signed so the loader only ever sees server-produced bytes.

## When It Is NOT This Issue

- **yaml.safe_load in use:** the YAML path rejects object tags, so a !!python/object document is a parse error, not a gadget trigger.
- **pickle of trusted, server-produced data:** a pickle stream generated and consumed internally, never attacker-supplied, is not CWE-502.
- **json.loads without an object_hook:** structured input stays dict and list only, reconstructing no application classes.
- **Marshal.load on framework-signed session data:** Rails cookie data verified by an HMAC before Marshal cannot be attacker-substituted.
- **Exception on an opaque blob alone:** an UnpicklingError without a demonstrated attacker-controlled stream reaching the loader is not confirmation.
- **Caller-only object effect:** reconstruction whose side effects never leave the caller's own request context has no cross-boundary impact.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `insecure-deserialization-python-and-ruby-gadgets` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `insecure-deserialization-python-and-ruby-gadgets` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: insecure-deserialization-python-and-ruby-gadgets
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
- [`insecure-deserialization-dotnet-gadgets`](../insecure-deserialization-dotnet-gadgets/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `insecure-deserialization-python-and-ruby-gadgets` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-502, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (4), hackerone_disclosed_reports (2), CYBER_CPT/oxdf (2), CYBER_CPT/ctftime (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
