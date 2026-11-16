---
name: android-app-security-storage-and-network
description: Android storage and network configuration. Covers insecure storage, backup exposure, network security config gaps and cleartext traffic allowances. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["android storage", "network security config", "cleartext traffic", "backup"]
cwe: [CWE-926]
owasp: []
attack: []
capec: [CAPEC-116]
related: [android-app-security, android-app-security-static-analysis, android-app-security-component-and-deeplink, ios-app-security]
parent: android-app-security
---

# Android App Security Storage and Network - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`android-static-malware-feature-engineering`](../../../blue-team/malware-analysis/android-static-malware-feature-engineering/SKILL.md)

## Mechanism and Preconditions

Storage and network review is about where data rests and where it travels, and the Android platform gives precise controls for both that are frequently not used. At rest: internal storage (`getFilesDir`, `getSharedPreferences`) is private to the app by default and protected by the sandbox; external storage is world-readable on older API levels and shared on newer ones; `EncryptedSharedPreferences` and the Keystore provide key-backed encryption where a plain preference file provides none, and a Keystore key is hardware-backed only when the device and the key's parameters allow it. In transit: `network_security_config.xml` is the decisive artefact — it sets `cleartextTrafficPermitted`, declares trust anchors per domain, and declares certificate pinning per domain, and since Android 9 cleartext is disabled by default for apps targeting that level, which makes an explicit `cleartextTrafficPermitted="true"` a deliberate decision. The third surface is logging and backup: a token written to logcat is readable by any app with `READ_LOGS` on older versions and by `adb` on a debuggable build, and `allowBackup="true"` without a rules file exports the app's data. The review question is which of these controls is absent, and each absence has a specific manifest or config line as evidence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a token or password is in `SharedPreferences` without encryption **THEN** that is the finding, regardless of whether the file is private, because backup and root change the threat model.
2. **IF** `network_security_config.xml` declares `cleartextTrafficPermitted="true"` for any domain **THEN** the finding is cleartext for that domain, and the domain list is the scope.
3. **IF** the config declares a `trust-anchors` entry with a user-installed CA **THEN** any user-installed certificate is trusted, which is the interception path.
4. **IF** the app logs a token, a header, or a response body **THEN** the branch is log exposure; check the release build's log level.
5. **IF** the app uses pinning **THEN** verify it is in the network security config or a library's configuration, not only in code that can be bypassed.
6. **IF** the finding is an exported component rather than data **THEN** start at [`android-app-security`](../android-app-security/SKILL.md).
7. **IF** every secret is in `EncryptedSharedPreferences` or the Keystore, the network config permits no cleartext, and no token is logged **THEN** record `Verified Safe` with the three artefacts.

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

1. **Enumerate the storage sites.** Every preference file name, database, file path, and cache directory the app writes, and the API it uses for each. The API is the evidence, not the filename.
2. **Read the network security config.** The base and per-domain `cleartextTrafficPermitted` values, the trust anchors, and any pin-set. This single file answers most of the transit question.
3. **Choose the branch.** Unencrypted secret at rest, cleartext transit, user-CA trust, log exposure, or backup exposure.
4. **Define the baseline-vs-probe differential.** Baseline: the file the app writes, read from a `run-as` shell on a debuggable build in a lab. Probe: the same file with the app's encryption enabled. A readable secret in the baseline and not in the probe is the finding; if both are readable, the encryption is not applied to that path.
5. **Name the stop condition.** Stop at the first secret readable at rest or the first domain permitting cleartext. Do not capture production traffic.
6. **State the proof.** Report the API, the file or the config line, the value class (token, password, key), and the control that should be present. If every site uses Keystore-backed storage and the config forbids cleartext, record the negative with both artefacts.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `getSharedPreferences("auth", MODE_PRIVATE).edit().putString("token", ...)` | A token at rest in a plaintext XML file, readable on a debuggable build and via backup | SharedPreferences API |
| `EncryptedSharedPreferences.create(...)` with a Keystore master key | Encrypted at rest with a key the app cannot export, which is the control | AndroidX Security |
| `<base-config cleartextTrafficPermitted="true">` | Every domain may use HTTP, which is the finding | Network security config |
| `<certificates src="user"/>` in a domain trust anchor | User-installed CAs are trusted for that domain, which enables interception | Network security config |
| `<pin-set>` with a backup pin for a domain | Pinning with rotation, which is a control and not a fragility | Network security config |
| `Log.d("auth", "token=" + token)` in a release path | The credential reaches logcat, which `adb` reads on a debuggable build | Logging calls |

## Worked Contrast

**Vulnerable: token in plaintext preferences, cleartext permitted, user CAs trusted, token logged**

```kotlin
// Plaintext prefs, cleartext allowed, and the token written to the log.
val prefs = getSharedPreferences("auth", Context.MODE_PRIVATE)
prefs.edit().putString("token", token).apply()
Log.d("auth", "token=$token")
```

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>
```

**Hardened: Keystore-backed encryption, no cleartext, system anchors only, no credential logging**

```kotlin
// The master key lives in the Keystore; the preference file is ciphertext.
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
val prefs = EncryptedSharedPreferences.create(
    context, "auth_enc", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
prefs.edit().putString("token", token).apply()
// No logging of the token at any level.
```

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />
    </trust-anchors>
  </base-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2027-01-01">
      <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
      <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

**Why this matters:** The left app writes its token in a file that backup and a debuggable build expose, allows cleartext so a network attacker reads the same token in transit, trusts user-installed CAs so an interception proxy works, and logs the token for good measure — four independent paths to the same credential. The right app encrypts with a non-exportable Keystore key, forbids cleartext, trusts only system anchors, pins with a backup pin for rotation, and writes nothing to the log.

## When It Is NOT This Issue

- **A non-secret in `SharedPreferences` such as a theme choice or a last-sync timestamp.** No confidentiality requirement.
- **`cleartextTrafficPermitted="true"` scoped to a `domain-config` for a localhost development host in a debug-only config.** Debug variants are outside the release threat model; confirm the release config.
- **Pinning at the certificate level rather than the public key.** Brittle against renewal but not a security defect; report it as an operational risk.
- **A user-CA trust anchor in a debug-only network config.** The release config is the one that matters.
- **`allowBackup="true"` with a `backup_rules.xml` that excludes the credential files.** The exclusion is the control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `android-app-security-storage-and-network` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `android-app-security-storage-and-network` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: android-app-security-storage-and-network
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-926 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`android-static-malware-feature-engineering`](../../../blue-team/malware-analysis/android-static-malware-feature-engineering/SKILL.md) - Blue Detection/Defense Counterpart
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`android-app-security-static-analysis`](../android-app-security-static-analysis/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security-component-and-deeplink`](../android-app-security-component-and-deeplink/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `android-app-security-storage-and-network` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-926`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (4), CYBER_CPT/gh_advisories (4), CYBER_CPT/github_security_md (2), CYBER_CPT/gh_security_lab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 6 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
