---
name: android-app-security-component-and-deeplink
description: Android component and deep link abuse. Covers exported activities, services, broadcast receivers and providers, plus deep link and intent redirection issues. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["exported activity", "deeplink abuse", "intent redirection", "content provider"]
cwe: [CWE-926]
owasp: []
attack: []
capec: [CAPEC-116]
related: [android-app-security, android-app-security-static-analysis, android-app-security-storage-and-network, ios-app-security]
parent: android-app-security
---

# Android App Security Component and Deeplink - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`android-static-malware-feature-engineering`](../../../blue-team/malware-analysis/android-static-malware-feature-engineering/SKILL.md)

## Mechanism and Preconditions

Component and deeplink review is about the intent surface specifically: what an external app can put into your process, and what your process does with it. A deep link is an intent filter with a `VIEW` action and a data scheme or host; the platform hands the resulting URI to whichever app declares a matching filter, and when two apps declare the same host the user or the platform picks one, which is why App Links verification with `android:autoVerify="true"` and `assetlinks.json` matters — without it, any app can claim the host. Once the intent arrives, the receiving code parses extras and URI parameters, and the classic defects follow: an unchecked `Intent` extra used as a file path, a nested `Intent` passed as a `Parcelable` and started with the receiver's identity (intent redirection), a `PendingIntent` handed to another app with mutable flags so the recipient can rewrite its inner intent, and a WebView that loads a URL from an extra with JavaScript enabled and a `JavascriptInterface` attached. Android 16 hardened intent redirection by default and added the opt-in `Safer Intents` matching rules, which reduce the platform-level part of this surface but leave every parsing defect in place.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a deep link host is declared without `android:autoVerify="true"` and an `assetlinks.json` **THEN** any app can claim the host, which is the finding.
2. **IF** the receiving code starts a nested `Intent` from an extra **THEN** the branch is intent redirection, and the `PendingIntent` flags decide exploitability.
3. **IF** the code writes a file at a path built from an extra or URI parameter **THEN** the branch is path traversal within the app's sandbox, which is still a finding when it reaches shared storage.
4. **IF** a WebView loads a URL from an intent extra **THEN** the branch is WebView reachability; check JavaScript, the interface, and `file://` access separately.
5. **IF** the component itself is exported without permission **THEN** start at [`android-app-security`](../android-app-security/SKILL.md) for the manifest analysis and use this skill for the input handling.
6. **IF** the target is an iOS URL scheme **THEN** switch to [`ios-app-security-storage-and-url-handling`](../../mobile-hardware-wireless-ics/ios-app-security-storage-and-url-handling/SKILL.md); the mechanisms differ.
7. **IF** the app targets Android 16 and relies on implicit intents to its own components **THEN** record the `Safer Intents` migration item, since explicit intents must match the target's filter under the opt-in.
8. **IF** every deep link host is verified, every extra is validated against an allowlist, and every nested intent is constructed rather than forwarded **THEN** record `Verified Safe` with the manifest and the validation site.

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

1. **Enumerate the intent surface.** Every intent filter with a `VIEW` action, every exported component accepting extras, and every `PendingIntent` the app creates. The manifest and the source together.
2. **Classify each input by what it reaches.** A file path, a URL, a nested intent, a database query, or a UI field. The sink decides the finding.
3. **Choose the branch.** Unverified host, intent redirection, path traversal, WebView reachability, or PendingIntent mutability.
4. **Define the baseline-vs-probe differential.** Baseline: the deep link invoked with a well-formed URI, which navigates as designed. Probe: the same link with a parameter that reaches the sink (a traversal sequence, an absolute URL, a nested intent extra). The differential is the effect at the sink, observed in logs or in the UI, not the string.
5. **Name the stop condition.** Stop at the first probe that reaches a sink the design did not intend. Do not attempt to exfiltrate data or execute code.
6. **State the proof.** Report the filter, the extra or parameter, the sink, the observed effect, and the validation that should exist. If every input is validated against an allowlist before the sink, record the negative with the validation site.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A `<data android:host="app.example.com">` filter without `autoVerify` | The host is unclaimed, so any app can register the same filter and receive the link | AndroidManifest intent filter |
| `getParcelableExtra("next")` then `startActivity(next)` | Intent redirection: the nested intent runs with the receiver's identity and permissions | Activity and receiver code |
| `PendingIntent.getActivity(..., FLAG_MUTABLE)` | The recipient can rewrite the inner intent and its extras | Notification and widget code |
| `File(baseDir, intent.getStringExtra("name"))` | Path traversal from an intent extra into the app's file space | File handling in components |
| `webView.loadUrl(getIntent().getStringExtra("url"))` with `javaScriptEnabled=true` | WebView reachability with script execution from an external input | WebView configuration |
| `intent.data?.host in ALLOWED_HOSTS` before use | Allowlist validation, which is the control | Deeplink handler |

## Worked Contrast

**Vulnerable: unverified host, traversal from an extra, nested intent forwarded, mutable PendingIntent**

```kotlin
// The host is not verified, so any app can claim it; the extra reaches a file path
// and a nested intent is started with this app's identity.
class DeepLinkActivity : AppCompatActivity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val name = intent.getStringExtra("file") ?: return
        val target = File(filesDir, name)              // traversal: ../../shared/...
        openFile(target)
        val next = intent.getParcelableExtra<Intent>("next")
        if (next != null) startActivity(next)          // intent redirection
    }
}
```

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.example.com" />
  </intent-filter>
</activity>
```

**Hardened: verified host, canonicalised path under an allowlisted directory, no forwarded intents**

```kotlin
// App Links verification claims the host; the path is resolved and checked against
// a fixed directory; nested intents are never accepted from outside.
class DeepLinkActivity : AppCompatActivity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val requested = intent.data?.lastPathSegment ?: return finish()
        val root = File(filesDir, "documents").canonicalFile
        val target = File(root, requested).canonicalFile
        if (!target.path.startsWith(root.path + File.separator)) return finish()
        openFile(target)
    }
}
```

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
  <intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/doc/" />
  </intent-filter>
</activity>
```

**Why this matters:** The left activity accepts a filename that resolves outside its directory and forwards an arbitrary nested intent with its own identity, and the unverified host means any app can feed it. The right activity claims the host through verification, canonicalises the resolved path and rejects anything outside a fixed directory, and never starts an intent from caller-supplied data.

## When It Is NOT This Issue

- **A deep link host declared with `autoVerify` and a published `assetlinks.json`.** The host is claimed; an impersonating app fails verification.
- **`getParcelableExtra` used for a value the app itself put there, in a non-exported component.** No external input.
- **A `PendingIntent` with `FLAG_IMMUTABLE`.** The recipient cannot rewrite it, which is the fix for that branch.
- **A WebView loading a fixed internal asset URL.** No external input reaches the loader.
- **A nested intent forwarded after an explicit `component` and package check.** The check is the control; state it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `android-app-security-component-and-deeplink` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `android-app-security-component-and-deeplink` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: android-app-security-component-and-deeplink
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
- [`android-app-security-storage-and-network`](../android-app-security-storage-and-network/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `android-app-security-component-and-deeplink` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-926`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 6 |
| Top sources | hackerone_disclosed_reports (8), CYBER_CPT/github_security_md (2), bugbounty-hunter-v1 (1), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
