# Verification Probes and Expected Differentials

> Sub-skill: [`android-app-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Merged-manifest inventory

```text
# Exported components and their protection, from the built APK (authoritative).
aapt2 dump xmltree --file AndroidManifest.xml app-release.apk \
  | rg -n "E: (activity|service|receiver|provider)|android:exported|android:permission|android:name" | head -60
# And the merged manifest the build produced, which shows library contributions.
rg -n --no-heading "android:exported=\"true\"" app/build/intermediates/merged_manifests/
```

Expected differential: an exported component with no adjacent `android:permission` is the finding; an exported component with a `signature`-level permission is the control.

## Class 2 — Permission protection level

```text
aapt2 dump permissions app-release.apk | rg -n "com.example|protectionLevel"
rg -n --no-heading "<permission" -A3 app/src/main/AndroidManifest.xml
```

Expected differential: a custom permission at `protectionLevel="signature"` is a real boundary; `normal` or `dangerous` means any app that requests it holds it, so the component is effectively open.

## Class 3 — Invocation differential

```text
# From a test app with no permissions: can the component be reached?
adb shell am start -n com.example.app/.AdminActivity --es action delete
adb shell am start -n com.example.app/.AdminActivity   # after adding the permission to the caller
adb logcat -d | rg -i "SecurityException|Permission Denial" | tail -5
```

Expected differential: the first command succeeding and the second producing a `Permission Denial` is the finding; both denied means the protection is enforced.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
