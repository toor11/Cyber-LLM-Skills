# Verification Probes and Expected Differentials

> Sub-skill: [`ios-app-security-binary-and-entitlements`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Entitlement diff across variants

```text
# The distribution variant versus the development variant, side by side.
codesign -d --entitlements :- build/Distribution/App.app 2>/dev/null | rg -v "^Executable" > dist.txt
codesign -d --entitlements :- build/Development/App.app 2>/dev/null | rg -v "^Executable" > dev.txt
diff -u dev.txt dist.txt
```

Expected differential: an entitlement present in `dist.txt` that has no justification is the finding; identical files mean the build variants are not differentiated, which is its own finding.

## Class 2 — Binary encryption and symbols

```text
otool -l Payload/App.app/App | rg -A4 "LC_ENCRYPTION_INFO"
nm -gU Payload/App.app/App 2>/dev/null | rg -i "attach|debug|ptrace" | head -5
strings -a Payload/App.app/App | rg -i "api_key|secret" | head -5
```

Expected differential: `cryptid 1` is the control; `cryptid 0` on a store build means the binary is unencrypted, and the symbol and string passes then become the analysis surface.

## Class 3 — Profile hygiene

```text
security cms -D -i Payload/App.app/embedded.mobileprovision > profile.plist
plutil -p profile.plist | rg -A2 "ExpirationDate|ProvisionedDevices|get-task-allow|Name"
```

Expected differential: a distribution profile with no `ProvisionedDevices` and a future `ExpirationDate` is the control; an expired profile or one listing device UDIDs means the wrong profile shipped.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
