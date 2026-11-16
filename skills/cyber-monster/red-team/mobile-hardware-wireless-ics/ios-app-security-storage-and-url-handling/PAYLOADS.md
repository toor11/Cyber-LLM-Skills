# Verification Probes and Expected Differentials

> Sub-skill: [`ios-app-security-storage-and-url-handling`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Store inventory

```text
# Every credential store, with the file and line.
rg -n --no-heading "UserDefaults|SecItemAdd|SecItemCopyMatching|writeToFile|FileManager.default" ios/App/
rg -n --no-heading -B2 -A6 "kSecAttrAccessible" ios/App/
```

Expected differential: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` is the control; `kSecAttrAccessibleAlways` or a `UserDefaults` write of a token is the finding, and each line is its own citation.

## Class 2 — Backup-read probe

```text
# On a lab device: does an unencrypted backup contain the credential?
xcrun simctl get_app_container booted com.example.app data  # ios-app-security-storage-and-url-handling: class 2 backupread probe
plutil -p "$CONTAINER/Library/Preferences/com.example.app.plist" | rg -i "token|secret"
# And the file protection class of the container files:
xcrun simctl spawn booted stat -f "%Sp %N" "$CONTAINER/Documents/"*
```

Expected differential: a token in the plist is the finding; a Keychain-only item with no plist entry is the control, and the file listing shows which container files are unprotected.

## Class 3 — Navigation probe

```text
# Open the scheme with an absolute external URL in the parameter.
xcrun simctl openurl booted "myapp://open?u=https://attacker.example/"
# Then observe whether the WebView navigated off-host.
xcrun simctl spawn booted log stream --predicate 'process == "App"' | rg -i "navigat|load"
```

Expected differential: a rejected URL or an allowlist log line is the control; the WebView loading an off-host URL is the finding, and the host is the evidence.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
