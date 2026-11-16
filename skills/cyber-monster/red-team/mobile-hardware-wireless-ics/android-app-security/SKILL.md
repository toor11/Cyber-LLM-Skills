---
name: android-app-security
description: "Assesses Android applications: manifest and permission review, exported components, storage, deep links and network configuration. Use when reviewing an APK or an installed app."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["android pentest", "apk analysis", "android security", "exported component", "android storage"]
cwe: [CWE-926]
owasp: []
attack: []
capec: [CAPEC-116]
related: [android-app-security-static-analysis, android-app-security-component-and-deeplink, android-app-security-storage-and-network, ios-app-security]
---

# Android App Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`android-static-malware-feature-engineering`](../../../blue-team/malware-analysis/android-static-malware-feature-engineering/SKILL.md)

## Mechanism and Preconditions

Android app review is about exported surface and the trust the platform places in an app's own declarations. Every component with `android:exported="true"` — activity, service, receiver, provider — is reachable by any app on the device that can construct a matching `Intent` or content URI, and since Android 12 every component with an intent filter must declare `exported` explicitly, so the declaration is a deliberate decision rather than a default. The `android:permission` attribute on a component is the only enforcement the platform offers at that boundary, and a component exported without one is open to every app. The data layer is the second surface: a `ContentProvider` with `grantUriPermissions`, a provider that opens files by caller-supplied path, or a `FileProvider` misconfigured with a root of `/` reaches the app's private storage. The platform changes in Android 16 are relevant to the review because they shift defaults rather than adding APIs: intent redirection hardening is on by default for all apps, `Safer Intents` becomes an opt-in for apps targeting 16 that requires explicit intents to match the target's intent filter, and local network access moves behind a runtime permission in the `NEARBY_DEVICES` group — which changes what a malicious app can do without asking, not what your app can be tricked into doing.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a component is exported and has no `android:permission` **THEN** that is the finding, and the input it accepts decides severity.
2. **IF** the component is exported, permission-protected, and the permission is a normal-level one **THEN** the protection is nominal; check the protection level.
3. **IF** a `ContentProvider` opens files or queries by caller-supplied values **THEN** switch to [`android-app-security-component-and-deeplink`](../android-app-security-component-and-deeplink/SKILL.md) for the URI and intent analysis.
4. **IF** the finding is a stored secret or an unencrypted database **THEN** switch to [`android-app-security-storage-and-network`](../android-app-security-storage-and-network/SKILL.md).
5. **IF** the artefact is an APK you cannot read **THEN** switch to [`android-app-security-static-analysis`](../android-app-security-static-analysis/SKILL.md) for the decompilation path.
6. **IF** the app targets Android 16 and relies on implicit local network access **THEN** record the migration item; the runtime permission is a behaviour change, not a vulnerability.
7. **IF** the manifest declares `android:debuggable="true"` or `android:allowBackup="true"` in a release build **THEN** those are findings independent of the component surface.
8. **IF** no component is exported beyond the launcher activity and no provider is exposed **THEN** record `Verified Safe` with the manifest excerpt.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `android-app-security-static-analysis` | [`android-app-security-static-analysis`](../android-app-security-static-analysis/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `android-app-security-component-and-deeplink` | [`android-app-security-component-and-deeplink`](../android-app-security-component-and-deeplink/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `android-app-security-storage-and-network` | [`android-app-security-storage-and-network`](../android-app-security-storage-and-network/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the merged manifest, not the source manifest.** Library manifests merge into the app's, and a dependency can export a component the app's own file never mentions. `aapt2 dump xmltree` on the built APK is the authoritative source.
2. **Enumerate exported components and their protection.** For each, the `android:exported` value, the `android:permission`, that permission's `protectionLevel`, and the input type it accepts.
3. **Choose the branch.** Exported without permission, exported with a normal-level permission, exported provider with path traversal, or a debuggable or backup-enabled release build.
4. **Define the baseline-vs-probe differential.** Baseline: the component invoked with no permission from a test app. Probe: the same invocation with a permission the attacker does not hold. A `SecurityException` on the probe and success on the baseline is the finding; a `SecurityException` on both means the permission is enforced.
5. **Name the stop condition.** Stop at the first component an unprivileged app can invoke with attacker-controlled input. Do not build an exploit for the input handler.
6. **State the proof.** Report the component, its `exported` and `permission` attributes, the permission's protection level, the intent or URI that reached it, and the effect observed. If every exported component is permission-protected at `signature` level, record the negative with the list.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `<activity android:exported="true">` with no `android:permission` | Any installed app can launch it with arbitrary extras | Merged manifest |
| `android:permission="android.permission.INTERNET"` on a component | A normal-level permission every app holds, so the protection is nominal | Manifest component attribute |
| A provider with `android:grantUriPermissions="true"` and no `android:pathPermission` | URI grants widen reach beyond the provider's own permission check | ContentProvider declaration |
| `android:allowBackup="true"` on an app holding tokens | `adb backup` extracts the app's data on a debuggable or backup-enabled build | Manifest application element |
| `android:debuggable="true"` in a release variant | Any app with `run-as`-equivalent access reads the app's private data | Build type configuration |
| `android:exported="false"` with `android:permission` at `signature` level | Correctly closed, and the control to cite | Merged manifest |

## Worked Contrast

**Vulnerable: exported activity and provider with no meaningful protection, backup enabled**

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
  <application android:allowBackup="true" android:debuggable="true">
    <activity android:name=".AdminActivity" android:exported="true">
      <intent-filter>
        <action android:name="com.example.app.ADMIN" />
        <category android:name="android.intent.category.DEFAULT" />
      </intent-filter>
    </activity>
    <provider android:name=".FilesProvider"
        android:authorities="com.example.app.files"
        android:exported="true"
        android:grantUriPermissions="true" />
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>
```

**Hardened: only the launcher exported, internal components signature-protected, backup off**

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
  <permission android:name="com.example.app.permission.INTERNAL"
      android:protectionLevel="signature" />
  <application android:allowBackup="false" android:debuggable="false">
    <activity android:name=".AdminActivity"
        android:exported="false"
        android:permission="com.example.app.permission.INTERNAL" />
    <provider android:name=".FilesProvider"
        android:authorities="com.example.app.files"
        android:exported="false"
        android:grantUriPermissions="false" />
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>
```

**Why this matters:** The left manifest exposes an administrative activity and a file provider to every app on the device, and enables backup and debugging so the private data directory is extractable without any component at all. The right manifest exports only the launcher, protects the internal surfaces with a signature-level permission, disables URI grants on the provider, and turns off backup and debugging in the release configuration.

## When It Is NOT This Issue

- **An exported launcher activity.** It must be exported to appear in the launcher; the finding would be the input it accepts.
- **An exported component protected by a `signature`-level permission.** Only apps signed with the same key can reach it.
- **`allowBackup="true"` on an app that stores no credentials and declares a backup rules file excluding its data.** The exclusion is the control.
- **A provider exported with `android:readPermission` and `writePermission` both set.** Both directions are protected.
- **An exported receiver for a broadcast the system sends.** `BOOT_COMPLETED` and similar are expected; check what the receiver does with the intent.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `android-app-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `android-app-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: android-app-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-926 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`android-static-malware-feature-engineering`](../../../blue-team/malware-analysis/android-static-malware-feature-engineering/SKILL.md) - Blue Detection/Defense Counterpart
- [`android-app-security-static-analysis`](../android-app-security-static-analysis/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security-component-and-deeplink`](../android-app-security-component-and-deeplink/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security-storage-and-network`](../android-app-security-storage-and-network/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `android-app-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-926`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 38 |
| Distinct dataset sources | 10 |
| Top sources | CYBER_CPT/oxdf (15), bugbounty-hunter-v1 (6), SecEval/android_sec_doc (6), SecEval/owasp_mastg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
