# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`initial-access-via-phishing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `initial-access-via-phishing`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Message authentication

**Expected differential.** A DMARC fail on a domain with `p=reject` that was still delivered proves a gateway gap; a pass proves alignment.

```bash
dig +short TXT _dmarc.example.com
dig +short TXT selector1._domainkey.example.com
```

## Attachment execution policy

**Expected differential.** An attachment retaining its zone identifier proves Protected View will engage; a missing identifier proves the proxy stripped it.

```bash
Get-Item .\invoice.docm -Stream Zone.Identifier -ErrorAction SilentlyContinue
Get-MpPreference | Select-Object EnableFileHashComputation,DisableBlockAtFirstSeen
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
