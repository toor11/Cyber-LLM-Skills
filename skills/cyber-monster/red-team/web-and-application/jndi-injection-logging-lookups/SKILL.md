---
name: jndi-injection-logging-lookups
description: JNDI injection through logging lookups. Covers Log4Shell-class message lookup injection, lookup disable flags, and payload shapes for JNDI-aware loggers. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["log4shell", "log4j jndi", "logging lookup injection", "message lookup"]
cwe: [CWE-917, CWE-502]
owasp: [A03:2021]
attack: [T1190]
capec: [CAPEC-242]
related: [jndi-injection, jndi-injection-remote-class-loading, sql-injection, cross-site-scripting]
parent: jndi-injection
---

# Jndi Injection Logging Lookups - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A logging call records an attacker-controlled string (a header such as User-Agent, a username, a path) through a layout that performs message lookups, so the logger evaluates ${...} expressions inside the logged data instead of treating it as literal text. When a jndi lookup prefix is evaluated, the logger itself issues a JNDI request, turning a log write into an outbound connection. The decision point is whether message-lookup interpolation is enabled on the layout at the moment of logging; the data was never meant to be a format string. The attacker gains the same JNDI reach as direct injection but through the telemetry path. A non-destructive check uses a benign lookup prefix such as ${env:} or a DNS-only ${jndi:dns://assessor-host} to prove that interpolation occurs.

- **Precondition chain:** Attacker-controlled text is written to a logger, the layout evaluates message lookups with the lookup resolver present, and the evaluated expression can reach a JNDI or other side-effecting lookup.
- **Readable differential:** A header logged as a plain value versus the same header containing ${jndi:ldap://assessor-host/a}: only the lookup form produces an outbound connection correlated with the log write, and it stops once formatMsgNoLookups is set or the JndiLookup resolver is removed.
- **Empirical grounding:** CWE-917 Expression Language Injection under OWASP Top 10:2025 A05 Injection. SOURCES.md contains no Log4Shell-class CVE, so the logger-interpolation sink is described at taxonomy level; the directory-query sibling CVE-2025-58782 shows the same JNDI lookup reached through a different channel.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the logger-interpolation profile is not yet confirmed **THEN** start at the parent class [`jndi-injection`](../jndi-injection/SKILL.md) (1 hop)
2. **IF** a logged header or field reaches a layout that evaluates ${...} **THEN** treat the log write as the sink and test a non-jndi lookup like ${env:} first
3. **IF** the lookup URI is handed straight to a JNDI API rather than through a log message **THEN** switch to [`jndi-injection-remote-class-loading`](../jndi-injection-remote-class-loading/SKILL.md) (1 hop)
4. **IF** the interpolation is a general template expression, not a logger lookup **THEN** switch to [`ssti`](../ssti/SKILL.md) (1 hop)
5. **IF** the literal ${jndi: is blocked but ${${lower:j}ndi: is not **THEN** treat the filter as naive string matching, not a structural control
6. **IF** formatMsgNoLookups is set or log4j-core is 2.17 or later with JndiLookup removed **THEN** verify the lookup engine is actually disabled before concluding
7. **IF** the logged value is parameterized with a placeholder and passed as an argument **THEN** the string is data, not a format, so lookups do not fire
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** no logged field reaches a lookup-enabled layout **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The lookup URI is supplied directly to a JNDI API, not through a log message | [`jndi-injection-remote-class-loading`](../jndi-injection-remote-class-loading/SKILL.md) | Invariant is codebase and factory trust, not string interpolation in a logger |
| The interpolation is a general template expression, not a logger lookup | [`ssti`](../ssti/SKILL.md) | Invariant is template-engine evaluation, a different interpolation surface |
| Need parent class methodology | [`jndi-injection`](../jndi-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the logging call that records attacker input.** Find logger.info/warn/error statements that concatenate a request header, username, or path, and the layout they use. The log write, not the business handler, is the sink here.
2. **Determine whether the layout evaluates lookups.** Inspect the pattern layout and library version for message-lookup interpolation and for the presence of a JndiLookup resolver. The branch is a lookup-enabled layout versus a disabled one.
3. **Pick a benign lookup as the oracle.** Choose the least intrusive interpolation first: a ${env:} or ${date:} expansion that changes the logged line, or a DNS-only ${jndi:dns://assessor-host} callback, before any ldap reference.
4. **Record a plain baseline.** Log a header with no ${ marker and capture the stored line and any outbound activity. This control shows the value is normally stored verbatim.
5. **Send the interpolation differential.** Submit the same header carrying a lookup expression and compare: a changed log line (for ${env:}) or a callback (for ${jndi:dns:}) that appears only for the expression proves the logger evaluates it.
6. **Stop condition.** Halt when the probe (a) produces interpolation that stops once formatMsgNoLookups is set or JndiLookup is removed, (b) shows the value stored verbatim across two baselines, or (c) would require an ldap reference returning a payload. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an interpolation effect (callback or substituted field) correlated with the log write, the logging source line reached by the header, and a lookup-enabled layout. A WAF catching the ${jndi: string upstream is not proof the logger is vulnerable.
8. **Close with the structural fix and verify.** Disable message lookups (formatMsgNoLookups or a nolookups pattern), remove JndiLookup or upgrade the logging library, and pass user values as placeholder arguments rather than inside the message, then replay the ${env:} and ${jndi:dns:} probes to confirm no interpolation occurs.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A logged header or field that still contains ${...} when the layout evaluates lookups | Proves the logger will interpolate attacker text rather than store it literally on a log4j-style stack |
| An outbound JNDI connection correlated within milliseconds of a log write | Proves message-lookup evaluation reached a side-effecting lookup through the telemetry path |
| A benign ${env:} or ${date:} lookup changing the logged line | Proves lookup interpolation is active even when the jndi prefix itself is filtered |
| Nested obfuscation such as ${${lower:j}ndi: resolving to a working lookup | Proves a naive string filter is bypassable and the lookup engine still runs |
| JndiLookup.class present in a loaded log4j-core jar below the fixed version | Proves the vulnerable lookup resolver is on the classpath |
| Parameterized logging with a placeholder carrying the user value | Proves the value is passed as an argument, not a format, so lookups do not fire |

## Worked Contrast

**Vulnerable pattern:**

```java
// User-Agent concatenated into a message that a lookup-enabled layout evaluates
logger.info("request from " + request.getHeader("User-Agent"));
```

**Hardened pattern:**

```java
// Message lookups disabled and the header passed as a placeholder argument, not a format
// log4j2.xml: <PatternLayout pattern="%m{nolookups}%n"/>
// JVM flag:   -Dlog4j2.formatMsgNoLookups=true  (or upgrade so JndiLookup is removed)
logger.info("request from {}", request.getHeader("User-Agent"));
```

**Why this matters:** Parameterized logging combined with formatMsgNoLookups means the header is treated as a literal argument, so a ${jndi:...} sequence inside it is never evaluated as a lookup. The structural control is disabling interpolation, not filtering the string.

## When It Is NOT This Issue

- **formatMsgNoLookups set or JndiLookup removed:** the logger cannot evaluate ${jndi:} regardless of what header is logged.
- **Parameterized logging:** the user value is passed as a placeholder argument, so it is never treated as a format string and lookups do not fire.
- **log4j-core at or above the fixed release:** message lookups are disabled by default, so the interpolation sink is closed.
- **Value echoed in a response, not logged through a lookup layout:** reflection into HTML is an XSS question, not a logging-lookup JNDI issue.
- **Lookup resolves only a benign local variable:** a ${env:} expansion with no path to a side-effecting lookup is informational, not exploitable.
- **WAF strips ${jndi: and layered forms never reach the logger:** if obfuscated variants are also blocked upstream, the control holds for this sink.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `jndi-injection-logging-lookups` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jndi-injection-logging-lookups` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: jndi-injection-logging-lookups
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-917, CWE-502 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`jndi-injection`](../jndi-injection/SKILL.md) - Web and Application (leaf)
- [`jndi-injection-remote-class-loading`](../jndi-injection-remote-class-loading/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jndi-injection-logging-lookups` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-917, CWE-502, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/oxdf (6), CYBER_CPT/ctf_search (3), CYBER_CPT/hacktricks (2), CYBER_CPT/pentesterlab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 7 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
