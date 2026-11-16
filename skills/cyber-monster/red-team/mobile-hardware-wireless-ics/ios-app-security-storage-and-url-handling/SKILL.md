---
name: ios-app-security-storage-and-url-handling
description: iOS storage and URL handling. Covers keychain and file protection classes, plist storage, URL scheme hijacking and universal link validation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["ios keychain", "url scheme hijack", "universal link", "plist storage"]
cwe: [CWE-926]
owasp: []
attack: []
capec: [CAPEC-116]
related: [ios-app-security, ios-app-security-binary-and-entitlements, android-app-security, mobile-instrumentation-and-pinning-bypass]
parent: ios-app-security
---

# Ios App Security Storage and Url Handling - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

iOS storage and URL handling fail in ways that are specific to the platform. The Keychain is the only store whose access is mediated by the security framework: an item carries a protection class that decides whether it is readable while locked and whether it is included in an encrypted backup, and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` is the strongest class that still allows background use at unlock. `UserDefaults` and files in the app container are protected only by the container's sandbox and by the device's data-protection class at the file level, so a credential there is readable from an unencrypted backup, from a jailbroken device, and from a misconfigured extension sharing the container. On the URL side, `application(_:open:options:)` and `scene(_:openURLContexts:)` receive input from any app on the device through a custom scheme, `WKWebView` can execute JavaScript from a URL parameter if the caller loads it directly, and a share extension can be handed a file whose type and size the app does not check. The review question is which store holds the credential and which handler trusts external input, and both are answerable from the source with a locator per finding.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a credential is in `UserDefaults` or a plain file in Documents **THEN** that is the finding; the Keychain is the store that has an access-control model.
2. **IF** a Keychain item uses `kSecAttrAccessibleAlways` **THEN** it is readable while locked and included in backups, which is the finding even though it is in the Keychain.
3. **IF** a URL handler reads a token or performs an action **THEN** the branch is URL authority, and the universal-link comparison is the control.
4. **IF** a `WKWebView` loads a URL from a parameter **THEN** the branch is WebView reachability; check `javaScriptEnabled` and the message handlers separately.
5. **IF** the file is in `Documents` and the app declares `UIFileSharingEnabled` **THEN** the container is visible in Files, which widens the exposure.
6. **IF** the finding is an entitlement or a binary property **THEN** start at [`ios-app-security-binary-and-entitlements`](../ios-app-security-binary-and-entitlements/SKILL.md).
7. **IF** every credential is in the Keychain with a device-only class, no URL handler trusts external input, and the container holds no secrets **THEN** record `Verified Safe` with the three artefacts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`ios-app-security`](../ios-app-security/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the stores.** Every `UserDefaults` key, every file path under the container, every Keychain query, and every shared container used by an extension.
2. **Classify each credential store by its protection.** The Keychain accessibility attribute, the file protection class, and whether the container is backup-eligible.
3. **Choose the branch.** Plaintext store, weak Keychain class, URL authority, WebView reachability, or extension container sharing.
4. **Define the baseline-vs-probe differential.** Baseline: the item read from the app's own process. Probe: the same item read from a backup image or from a second app in the same access group. Readable in the probe is the finding; a `errSecItemNotFound` is the control, and the OSStatus is the evidence.
5. **Name the stop condition.** Stop at the first credential readable outside its intended process, or the first URL handler that performs an action from external input.
6. **State the proof.** Report the store, the key or path, the protection attribute, the probe that succeeded, and the attribute that should be set. If every store is device-only and every handler validates, record the negative with the queries.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `UserDefaults.standard.set(token, forKey: "authToken")` | A credential in a plist included in an unencrypted backup | `UserDefaults` |
| `kSecAttrAccessibleAlways` on a Keychain item | Readable while locked and backed up, which defeats the Keychain's purpose | `SecItemAdd` query |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Not backed up and not readable while locked — the control | `SecItemAdd` query |
| A file written to `Documents` with `UIFileSharingEnabled` | The container is visible in the Files app, so the exposure is user-facing | `Info.plist`, file writes |
| A `WKWebView` loading `url` from a URL parameter | Script execution from external input if JavaScript is enabled | `WKWebView.load(_:)` |
| A share extension reading a file with no type or size check | A file from another app reaching the app's parser | Share extension handler |

## Worked Contrast

**Vulnerable: token in UserDefaults, weak Keychain class, URL parameter rendered in a WebView**

```swift
// A credential in a plist, a Keychain item readable while locked, and a URL
// parameter loaded as a page.
UserDefaults.standard.set(token, forKey: "authToken")

let addQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "refresh",
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,   // readable while locked
    kSecValueData as String: refresh.data(using: .utf8)!,
]
SecItemAdd(addQuery as CFDictionary, nil)

func application(_ app: UIApplication, open url: URL, options: [:] = [:]) -> Bool {
    if let target = URLComponents(url: url, resolvingAgainstBaseURL: false)?
        .queryItems?.first(where: { $0.name == "u" })?.value {
        webView.load(URLRequest(url: URL(string: target)!))      // external URL
    }
    return true
}
```

**Hardened: Keychain device-only, no plist credential, allowlisted navigation**

```swift
// One store, one protection class, and navigation restricted to a fixed host.
let addQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "authToken",
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecValueData as String: token.data(using: .utf8)!,
]
SecItemAdd(addQuery as CFDictionary, nil)

func application(_ app: UIApplication, open url: URL, options: [:] = [:]) -> Bool {
    guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let target = comps.queryItems?.first(where: { $0.name == "u" })?.value,
          let parsed = URL(string: target),
          parsed.host == "app.example.com",
          parsed.scheme == "https" else { return false }
    webView.load(URLRequest(url: parsed))
    return true
}
```

**Why this matters:** The left app puts the token where a backup reads it, sets a Keychain class that allows access while locked, and loads any URL an external app supplies into a WebView. The right app keeps one item under a device-only class and restricts navigation to a single HTTPS host, so neither the storage nor the handler exposes anything the design did not intend.

## When It Is NOT This Issue

- **`UserDefaults` holding a non-secret such as a feature flag.** No confidentiality requirement.
- **A Keychain item with `kSecAttrAccessibleAfterFirstUnlock` for a background refresh token.** A deliberate trade-off; state the window.
- **A file in `Documents` that the user is meant to see, with `UIFileSharingEnabled`.** User-visible by design; the finding would be a secret in that directory.
- **A `WKWebView` loading a fixed local asset.** No external input.
- **A URL handler that only navigates to a fixed in-app screen.** No authority and no attacker-controlled target.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ios-app-security-storage-and-url-handling` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ios-app-security-storage-and-url-handling` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ios-app-security-storage-and-url-handling
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-926 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security-binary-and-entitlements`](../ios-app-security-binary-and-entitlements/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ios-app-security-storage-and-url-handling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-926`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 29 |
| Distinct dataset sources | 13 |
| Top sources | SecEval/apple_platform_security (6), OffsecCyber (5), bugbounty-hunter-v1 (3), SecEval/owasp_mastg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
