# Verification Probes and Expected Differentials

> Sub-skill: [`android-app-security-component-and-deeplink`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Intent-surface inventory

```text
# Filters that accept external VIEW intents, and whether the host is claimed.
rg -n --no-heading -A6 "android.intent.action.VIEW" app/src/main/AndroidManifest.xml
rg -n --no-heading "autoVerify" app/src/main/AndroidManifest.xml || echo "no autoVerify anywhere"
# Sinks fed from intent data.
rg -n --no-heading "getStringExtra|getParcelableExtra|intent.data|intent?.data" app/src/main/java/
```

Expected differential: `autoVerify="true"` on the host filter plus a validation site before the sink is the control; a host filter without it, with an extra reaching a file path or a `startActivity`, is the finding.

## Class 2 — Host-claim verification

```text
# The claimed hosts and the assetlinks file the platform will fetch.
aapt2 dump xmltree --file AndroidManifest.xml app.apk | rg -n "android:host|autoVerify"
curl -s "https://app.example.com/.well-known/assetlinks.json" | jq -r '.[].target.package_name'
```

Expected differential: the package name in `assetlinks.json` matching the app and the filter carrying `autoVerify` is the control; a filter without `autoVerify` or a missing `assetlinks.json` means the host is unclaimed.

## Class 3 — Sink probe

```text
# Absolute path traversal and an external URL, against a lab build only.
adb shell am start -a android.intent.action.VIEW -d "https://app.example.com/doc/..%2F..%2Fshared_prefs%2Fauth.xml"
adb shell am start -a android.intent.action.VIEW -d "https://app.example.com/doc/https://attacker.example/"
adb logcat -d | rg -i "FileNotFound|ENOENT|open failed" | tail -3
```

Expected differential: a rejection or a `FileNotFound` on the canonicalised path is the control; the file content being read, or the WebView navigating to the external host, is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
