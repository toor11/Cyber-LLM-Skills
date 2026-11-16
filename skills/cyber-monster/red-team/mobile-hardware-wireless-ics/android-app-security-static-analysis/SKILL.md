---
name: android-app-security-static-analysis
description: Android static analysis. Covers decompiling and reviewing APKs and AABs, manifest attack surface, hardcoded secrets and native library inspection. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["apk static analysis", "jadx apk", "android manifest review"]
cwe: [CWE-926]
owasp: []
attack: []
capec: [CAPEC-116]
related: [android-app-security, android-app-security-component-and-deeplink, android-app-security-storage-and-network, ios-app-security]
parent: android-app-security
---

# Android App Security Static Analysis - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`android-static-malware-feature-engineering`](../../../blue-team/malware-analysis/android-static-malware-feature-engineering/SKILL.md)

## Mechanism and Preconditions

Static analysis of an Android app is a workflow with three artefacts and a decision at each. The APK is a zip of `classes*.dex`, `resources.arsc`, and `AndroidManifest.xml`; `aapt2` reads the manifest and resources, `jadx` recovers Java-like source from the dex, and `apktool` recovers smali plus decoded resources. The decision at this stage is whether the app is obfuscated and whether that changes what you can conclude: an unobfuscated build lets you read the logic, while an obfuscated one leaves strings and API calls readable even when names are not, so the findings shift toward resource-level and configuration-level defects. The second artefact is the native library set under `lib/<abi>/`, where `strings`, `readelf`, and a disassembler cover what jadx cannot. The third is the merged manifest and its provenance: a component or permission contributed by a library is invisible in the app's own source and is the most common surprise. The review output is a set of findings each tied to an artefact and an offset — a string resource, a dex method, a native symbol — because a static finding without a locator cannot be verified or fixed.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the APK is obfuscated **THEN** the readable surface is strings, resources, and API call sites; state what you could not conclude rather than concluding nothing.
2. **IF** the finding is a manifest-level defect **THEN** switch to [`android-app-security`](../android-app-security/SKILL.md) for the exported-component analysis.
3. **IF** the finding is a hardcoded secret or an unencrypted store **THEN** switch to [`android-app-security-storage-and-network`](../android-app-security-storage-and-network/SKILL.md).
4. **IF** the app has native libraries **THEN** analyse them separately; `jadx` does not cover them and their strings often carry the keys the Java layer no longer holds.
5. **IF** the artefact is an XAPK or a split APK set **THEN** merge the splits before analysis, because each split carries part of the manifest.
6. **IF** the question is behaviour rather than code **THEN** record that static analysis cannot answer it, and name the dynamic method that would.
7. **IF** every artefact is readable and the merged manifest is complete **THEN** record the artefact inventory as the deliverable, with the locators for each finding.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`android-app-security`](../android-app-security/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish the artefact set.** The APK or split set, the version, and whether a mapping file for obfuscation is available. The version matters because findings are version-specific.
2. **Decode in the order that preserves information.** `aapt2` for the manifest and resources, `jadx` for the code, `apktool` only when you need the resource decoding or smali for a specific method. Each rebuilds the artefact, so keep the original.
3. **Classify what is readable.** Names and structure (obfuscated or not), string literals, resource values, native symbols, and the merged manifest's provenance.
4. **Define the baseline-vs-probe differential.** Baseline: the decompiled artefact as it stands. Probe: the same artefact with the suspected input traced from an entry point to a sink. The differential is a dataflow you can show, not a string you noticed.
5. **Name the stop condition.** Stop when every finding has an entry point, a sink, and a locator. A string without a call site is a note, not a finding.
6. **State the proof.** Report the artefact, the locator (file, method, offset), the dataflow, and the manifest contribution if relevant. If the build is obfuscated and a dataflow cannot be traced, say so and record the finding as unconfirmed rather than absent.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `classes.dex` with readable method names | No obfuscation, so the logic is directly reviewable | `jadx` output |
| A string resource with a URL or key in `resources.arsc` | A configuration value the app uses at runtime, readable regardless of obfuscation | `aapt2 dump resources` |
| `lib/arm64-v8a/libnative.so` with exported JNI symbols | Native code holding logic that the dex does not show | `readelf -s`, `strings` |
| A component in the merged manifest absent from the app's own manifest | A library contribution, which is the most common surprise in an audit | Merged manifest |
| An `api_key` literal in a decompiled class | A hardcoded credential, which needs the storage skill for its reach | `jadx` output |
| A `mapping.txt` in the build outputs | The deobfuscation map, which turns an obfuscated finding into a located one | Build artefacts |

## Worked Contrast

**Vulnerable: analysis that stops at a decoded string with no locator or dataflow**

```text
# A string was found; nothing shows it is used, or where.
$ strings app-release.apk | rg -i "api_key|secret" | head -3
api_key
https://api.example.com/v1
```

**Hardened: a located dataflow from an entry point to a sink**

```text
# jadx output, then the call chain that reaches the sink:
com.example.net.ApiClient.<init>  ->  BuildConfig.API_KEY
com.example.net.ApiClient.request ->  okhttp3.Request.Builder.addHeader("Authorization", ...)
entry point: com.example.ui.SyncActivity.onCreate (exported=false)
sink:        ApiClient.request -> header value
```

**Why this matters:** The left output is a string that may be a resource name, a log tag, or a dead constant, and a report built on it will be rejected on review. The right output names the class, the field, the entry point, and the sink, so the developer can confirm the finding in one minute and the reviewer can verify it without re-running the analysis.

## When It Is NOT This Issue

- **A string that looks like a key but is a resource name or a test constant.** Trace it to a call site before reporting.
- **An obfuscated app where no dataflow is traceable.** Absence of evidence in an obfuscated artefact is not a non-finding; record it as unconfirmed.
- **A URL that is a public API endpoint with no embedded credential.** Public by design.
- **A native library that ships with the NDK or a standard runtime.** Its symbols are framework code.
- **A debug-only class left in the release build with no entry point.** Note it; the finding needs reachability.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `android-app-security-static-analysis` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `android-app-security-static-analysis` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: android-app-security-static-analysis
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-926 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`android-static-malware-feature-engineering`](../../../blue-team/malware-analysis/android-static-malware-feature-engineering/SKILL.md) - Blue Detection/Defense Counterpart
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`android-app-security-component-and-deeplink`](../android-app-security-component-and-deeplink/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security-storage-and-network`](../android-app-security-storage-and-network/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `android-app-security-static-analysis` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-926`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/oxdf (13), LAMDA (4), cyber-security/security-code (2), CYBER_CPT/ctftime (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
