# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-certificate-services-esc5-through-esc8`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-certificate-services-esc5-through-esc8`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## CA flags and roles

**Expected differential.** A set subject-name flag proves ESC6; a non-tier-0 CA role assignment proves ESC7.

```bash
certutil -getreg policy\EditFlags
certutil -getreg CA\Security
```

## Enrollment endpoint authentication

**Expected differential.** Windows Authentication enabled with EPA off proves the ESC8 precondition; EPA required proves the control.

```bash
curl -sSI http://ca01/certsrv/ -o /dev/null -w '%{http_code}\n'
Get-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site' -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name '*'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
