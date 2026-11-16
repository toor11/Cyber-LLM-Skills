# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`macos-security-bypass-gatekeeper-and-notarization`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `macos-security-bypass-gatekeeper-and-notarization`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Signature and assessment

**Expected differential.** A `rejected` verdict proves the control blocked; `accepted` with a Developer ID proves the trust chain; an ad-hoc signature bounds capability.

```bash
codesign -dv --verbose=4 /Applications/Suspect.app
spctl -a -vvv -t exec /Applications/Suspect.app
```

## Quarantine state

**Expected differential.** An absent attribute on a downloaded bundle proves assessment will not run; a present one proves it will.

```bash
xattr -p com.apple.quarantine ~/Downloads/Suspect.app
mdls -name kMDItemWhereFroms ~/Downloads/Suspect.app
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
