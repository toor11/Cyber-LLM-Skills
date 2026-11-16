# Verification Probes and Expected Differentials

> Sub-skill: [`ios-app-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Surface inventory

```text
# URL schemes, associated domains, and document types from the shipped bundle.
plutil -p Payload/App.app/Info.plist | rg -A4 "CFBundleURLTypes|CFBundleDocumentTypes"
codesign -d --entitlements :- Payload/App.app 2>/dev/null | rg -A2 "associated-domains|keychain-access-groups|get-task-allow"
```

Expected differential: an `applinks:` entitlement present is the control for universal links; a `CFBundleURLSchemes` entry whose handler acts on a token parameter is the finding.

## Class 2 — Scheme authority probe

```text
# Open the scheme from a different app (a lab harness) with an attacker-chosen token.
xcrun simctl openurl booted "myapp://auth?token=lab-controlled"
xcrun simctl openurl booted "https://example.com/auth/callback?code=lab-controlled"
# Compare the resulting state in the app's log or UI.
```

Expected differential: the custom scheme changing the session while the universal link does not is the finding; both changing means the universal link handler is also unvalidated.

## Class 3 — Storage inspection

```text
# On a lab device with a debug build: where is the credential?
xcrun simctl get_app_container booted com.example.app data  # ios-app-security: class 3 storage inspection
plutil -p "$CONTAINER/Library/Preferences/com.example.app.plist" | rg -i "token|password|secret"
security dump-keychain 2>/dev/null | rg -A3 "com.example.app"
```

Expected differential: a token in the preferences plist is the finding; the item appearing only in the Keychain with a device-only class is the control.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
