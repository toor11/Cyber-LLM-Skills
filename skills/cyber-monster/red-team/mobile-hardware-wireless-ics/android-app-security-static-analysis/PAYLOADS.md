# Verification Probes and Expected Differentials

> Sub-skill: [`android-app-security-static-analysis`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Artefact inventory

```text
# What is in the package, without executing anything.
unzip -l app-release.apk | awk '{print $4}' | rg "^(classes.*dex|lib/|resources.arsc|AndroidManifest.xml)"
aapt2 dump badging app-release.apk | head -5
```

Expected differential: a single `classes.dex` with readable strings after `jadx` means unobfuscated; multiple dex files and single-letter class names means obfuscated, and the finding set shifts to resources and native libraries.

## Class 2 — Manifest provenance

```text
# Which components and permissions came from libraries?
aapt2 dump permissions app-release.apk
rg -n --no-heading "android:name=\"(android.permission|[a-z]+\.[a-z]+\.permission)" app/build/intermediates/merged_manifests/*/AndroidManifest.xml
```

Expected differential: a permission or exported component present in the merged manifest but absent from `app/src/main/AndroidManifest.xml` is a library contribution, which is the finding and needs the library named.

## Class 3 — Located string analysis

```text
# Every candidate secret with the class and method that references it.
jadx -d out/ --no-res app-release.apk >/dev/null 2>&1
rg -n --no-heading -B3 -A3 "api_key|secret|token" out/sources/ | rg -v "^\s*//" | head -40
# Native strings, which jadx does not cover.
for so in $(unzip -Z1 app-release.apk 'lib/*/*.so'); do unzip -p app-release.apk "$so" | strings | rg -i "key|secret|http" | head -3; done
```

Expected differential: a string in a class that is called from an activity is a dataflow candidate; the same string in an unused resource is a note. The native pass catches what the dex does not.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
