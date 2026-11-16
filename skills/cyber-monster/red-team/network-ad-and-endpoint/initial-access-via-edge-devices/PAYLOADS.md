# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`initial-access-via-edge-devices`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `initial-access-via-edge-devices`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## External surface

**Expected differential.** A management path answering on the internet address proves the plane is exposed; a redirect to an internal name proves it is not.

```bash
curl -sSI https://vpn.example.com/ --max-time 10
nmap -Pn -p 443,8443,10443 --reason vpn.example.com
```

## Version identification

**Expected differential.** A build string matching an advisory proves applicability; a build newer than the fix does not.

```bash
curl -sS https://vpn.example.com/ | Select-String -Pattern 'version|build'
openssl s_client -connect vpn.example.com:443 -servername vpn.example.com </dev/null 2>/dev/null | openssl x509 -noout -dates
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
