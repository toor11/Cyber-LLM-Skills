---
name: ios-app-security
description: "Assesses iOS applications: binary and entitlement review, keychain usage, URL scheme and universal link handling, and storage protections. Use when reviewing an IPA or app store build."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["ios pentest", "ipa analysis", "ios security", "keychain", "url scheme ios"]
cwe: [CWE-926]
owasp: []
attack: []
capec: [CAPEC-116]
related: [ios-app-security-binary-and-entitlements, ios-app-security-storage-and-url-handling, android-app-security, mobile-instrumentation-and-pinning-bypass]
---

# Ios App Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

iOS app review has three trust surfaces and the platform makes each one explicit. The URL surface: an app declares schemes in `CFBundleURLSchemes` and associated domains in the `com.apple.developer.associated-domains` entitlement, and any app on the device can open a custom scheme while only the domain owner can satisfy a universal link, so a custom scheme carrying a token or an authorisation decision is the classic finding. The data surface: the Keychain is the correct store for credentials and `UserDefaults` is not, and the Keychain's protection class (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` versus `kSecAttrAccessibleAlways`) decides whether the item survives a backup and whether it is readable while the device is locked. The binary surface: entitlements are the app's declared capabilities, and a shipped binary that carries `get-task-allow`, a debugging entitlement, or an over-broad keychain access group can be inspected or impersonated. iOS 26 adds Enhanced Security, a build setting that enables hardened-process entitlements, arm64e pointer authentication, and optional libc++ hardening, and App Attest remains the server-side mechanism for proving a request came from a genuine instance of the app — which is what a client-side check cannot do.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a custom URL scheme carries a token, a session, or an authorisation decision **THEN** that is the finding; any app can register the same scheme.
2. **IF** the finding is in the entitlements or the binary's signing properties **THEN** switch to [`ios-app-security-binary-and-entitlements`](../ios-app-security-binary-and-entitlements/SKILL.md).
3. **IF** the finding is a credential store or a URL handler **THEN** switch to [`ios-app-security-storage-and-url-handling`](../ios-app-security-storage-and-url-handling/SKILL.md).
4. **IF** the app relies on a client-side integrity check for server trust **THEN** the branch is attestation: the server must verify, not the client.
5. **IF** the app is built without Enhanced Security **THEN** record it as a hardening item with the platform version, not as a vulnerability.
6. **IF** the app uses a universal link for the same purpose as a custom scheme **THEN** compare the entitlements with the `apple-app-site-association` file; the domain ownership is the control.
7. **IF** every scheme carries no authority, every credential is in the Keychain with a device-only protection class, and the release binary has no `get-task-allow` **THEN** record `Verified Safe` with the three artefacts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `ios-app-security-binary-and-entitlements` | [`ios-app-security-binary-and-entitlements`](../ios-app-security-binary-and-entitlements/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `ios-app-security-storage-and-url-handling` | [`ios-app-security-storage-and-url-handling`](../ios-app-security-storage-and-url-handling/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the entry surfaces.** URL schemes, universal link paths, document types, share extensions, and any `openURL` handling. Each is reachable from outside the app.
2. **Read the entitlements and the signing properties.** `codesign -d --entitlements` on the shipped binary, plus the provisioning profile. This is the authoritative statement of what the app can do.
3. **Choose the branch.** Custom scheme with authority, insecure credential storage, over-broad keychain group, debugging entitlement, or client-side-only integrity.
4. **Define the baseline-vs-probe differential.** Baseline: the scheme opened by the app itself with a well-formed URL. Probe: the same scheme opened from another app with an attacker-chosen parameter, and a universal link for the same action. A scheme that performs the action and a universal link that does not is the finding.
5. **Name the stop condition.** Stop at the first scheme or handler that performs an authoritative action from external input. Do not attempt to extract data.
6. **State the proof.** Report the scheme or entitlement key, the handler, the parameter, the effect, and the control that should exist (universal link, server-side check, attestation). If every surface is closed, record the negative with the `Info.plist` and entitlement excerpts.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `CFBundleURLSchemes` containing `myapp` and a handler that reads a token parameter | Any app can open the scheme, so the token is attacker-supplied | `Info.plist`, `application(_:open:options:)` |
| A `com.apple.developer.associated-domains` entry with `applinks:example.com` | Universal links are claimed, which is the control for the same action | Entitlements |
| `UserDefaults.standard.set(token, forKey: "token")` | A credential in a plist readable from a backup and from the container | `UserDefaults` |
| `kSecAttrAccessibleAlways` on a Keychain item | Readable while the device is locked and included in backups | Keychain query |
| `get-task-allow` true in a distribution build | A debugging entitlement, so a debugger can attach to the shipped app | `codesign -d --entitlements` |
| A client-side jailbreak check gating a server action | The check is bypassable on the client, so the server must verify | Attestation gap |

## Worked Contrast

**Vulnerable: custom scheme carrying an authorisation token, credential in UserDefaults**

```swift
// Any app can register "myapp://" and hand this handler a token it chose.
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    if let token = URLComponents(url: url, resolvingAgainstBaseURL: false)?
        .queryItems?.first(where: { $0.name == "token" })?.value {
        AuthSession.current = AuthSession(token: token)   // trusted verbatim
        return true
    }
    return false
}

// The credential is in a plist, not the Keychain.
UserDefaults.standard.set(session.token, forKey: "authToken")
```

```xml
<key>CFBundleURLTypes</key>
<array><dict>
  <key>CFBundleURLSchemes</key><array><string>myapp</string></array>
</dict></array>
```

**Hardened: universal link for the authoritative action, token exchanged server-side, Keychain storage**

```swift
// The token arrives through a verified universal link and is exchanged server-side;
// the client never treats a URL parameter as an authenticated session.
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    guard url.host == "example.com", url.path.hasPrefix("/auth/callback") else { return false }
    Task { await AuthSession.exchange(codeFrom: url) }   // server validates and issues
    return true
}
```

```swift
// Keychain with a device-only protection class, which survives neither backup nor
// a locked device.
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "authToken",
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecValueData as String: token.data(using: .utf8)!,
]
SecItemAdd(query as CFDictionary, nil)
```

**Why this matters:** The left handler accepts a session token from any app that can open the scheme, and stores it in a plist that a backup or a container inspection reads. The right handler only acts on a verified universal link for one host and path, exchanges the code server-side so the client never mints its own session, and keeps the resulting token in a Keychain item that is neither backed up nor readable while locked.

## When It Is NOT This Issue

- **A custom scheme used only to open a screen with no authority.** Navigation without a token is not a finding.
- **A universal link and a custom scheme that both exist, with the scheme only for legacy deep links that carry no session.** Check the handler before filing.
- **`UserDefaults` holding a non-secret preference.** No confidentiality requirement.
- **A Keychain item with `kSecAttrAccessibleAfterFirstUnlock` for a background-sync token.** A deliberate trade-off; state the exposure window.
- **A jailbreak check used for telemetry rather than as the only control.** Note it; the finding would be a server action gated only by that check.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ios-app-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ios-app-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ios-app-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-926 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`ios-app-security-binary-and-entitlements`](../ios-app-security-binary-and-entitlements/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`ios-app-security-storage-and-url-handling`](../ios-app-security-storage-and-url-handling/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ios-app-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-926`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 13 |
| Top sources | SecEval/owasp_mastg (2), SecEval/apple_platform_security (2), ctf-solver-dataset (2), CYBER_CPT/atomic_red_team (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
