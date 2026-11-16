# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`macos-security-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `macos-security-bypass`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Layer status

**Expected differential.** Assessments disabled or SIP off proves the layer is not enforcing; both enabled proves it is.

```bash
spctl --status
csrutil status
```

## TCC and quarantine state

**Expected differential.** A full-disk-access grant for an unexpected binary, or a missing quarantine attribute on a download, is the finding.

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db 'select service,client,auth_value from access'
xattr -l ~/Downloads/Suspect.app
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
