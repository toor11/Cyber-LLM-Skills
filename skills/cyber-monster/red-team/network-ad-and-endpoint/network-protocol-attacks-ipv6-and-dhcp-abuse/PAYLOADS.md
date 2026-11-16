# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-protocol-attacks-ipv6-and-dhcp-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `network-protocol-attacks-ipv6-and-dhcp-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Endpoint IPv6 posture

**Expected differential.** A link-local address with no managed DHCPv6 server proves the endpoint is self-configuring, which is the precondition rather than the finding.

```bash
ip -6 addr show scope link
Get-NetIPAddress -AddressFamily IPv6 | Select-Object InterfaceAlias,IPAddress,PrefixOrigin
```

## Resolver assignment differential

**Expected differential.** The resolver list gaining an unexpected IPv6 address proves the advertisement was accepted; an unchanged list proves the guard works.

```bash
Get-DnsClientServerAddress -AddressFamily IPv6
ip -6 route show default
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
