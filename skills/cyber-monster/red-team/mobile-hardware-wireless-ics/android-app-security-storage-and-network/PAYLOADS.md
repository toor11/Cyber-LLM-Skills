# Verification Probes and Expected Differentials

> Sub-skill: [`android-app-security-storage-and-network`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Storage-site inventory

```text
# Where does the app write, and with which API?
rg -n --no-heading "getSharedPreferences|EncryptedSharedPreferences|openFileOutput|getExternalFilesDir|SQLiteDatabase|Room.databaseBuilder" app/src/main/java/
# Secrets in preference writes.
rg -n --no-heading -B2 -A2 "putString\(\"(token|password|secret|api_key)" app/src/main/java/
```

Expected differential: `EncryptedSharedPreferences` with a Keystore master key is the control; `getSharedPreferences(...).putString("token", ...)` is the finding, and the preference file name is the locator.

## Class 2 — Network config audit

```text
rg -n --no-heading "cleartextTrafficPermitted|certificates src|<pin-set|<domain" app/src/main/res/xml/network_security_config.xml
rg -n --no-heading "networkSecurityConfig" app/src/main/AndroidManifest.xml
```

Expected differential: `cleartextTrafficPermitted="false"` with only `system` anchors is the control; `true` at base level or a `user` anchor is the finding, and the domain or the base scope is the citation.

## Class 3 — At-rest differential

```text
# On a lab device with a debuggable build: read the file, then read it after the fix.
adb shell run-as com.example.app cat shared_prefs/auth.xml
adb shell run-as com.example.app ls -l shared_prefs/
```

Expected differential: readable XML containing a token is the finding; a ciphertext-only file with the key in the Keystore is the control, and the file listing shows which preference files exist.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
