# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`macos-security-bypass-tcc-and-privacy-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `macos-security-bypass-tcc-and-privacy-bypass`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Grant inventory

**Expected differential.** A full-disk-access grant for a general-purpose utility proves broad inheritance; a narrow signed helper does not.

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "select service,client,auth_value from access"
ls -l ~/Library/Application\ Support/com.apple.TCC/TCC.db
```

## Client identity

**Expected differential.** A client whose signature does not satisfy the recorded requirement cannot reuse the grant, which bounds the finding.

```bash
codesign -dv --verbose=4 /Applications/Utility.app
log show --predicate 'subsystem == "com.apple.TCC"' --last 1h | head -40
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
