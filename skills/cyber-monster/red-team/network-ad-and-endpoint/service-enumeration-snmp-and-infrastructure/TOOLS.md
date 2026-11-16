# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`service-enumeration-snmp-and-infrastructure`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `snmpget` | `snmpget -v2c -c public -t 2 10.20.30.30 1.3.6.1.2.1.1.1.0` | Single-OID identity read | Linux / macOS |
| `snmpwalk` | `snmpwalk -v2c -c public -t 2 10.20.30.30 1.3.6.1.2.1.2.2.1.2` | Interface description subtree only | Linux / macOS |
| `snmpbulkwalk` | `snmpbulkwalk -v2c -c public -Cn0 -Cr10 10.20.30.30 1.3.6.1.2.1.4.20` | Bounded ARP table read | Linux |
| `nmap` | `nmap -sU -p161 --script snmp-info,snmp-interfaces 10.20.30.30` | Discovery without a full walk | Cross-platform |
| `onesixtyone` | `onesixtyone -c communities.txt -i hosts.txt -o results.txt` | Community string sweep against owned devices only | Linux |

## Minimal Lab Validation Script

Read identity OIDs and one bounded table, printing the OID alongside each value so the report cites what the agent returned.

```python
from pysnmp.hlapi import (SnmpEngine, CommunityData, UdpTransportTarget,
                          ContextData, ObjectType, ObjectIdentity, getCmd, nextCmd)

def get_one(host, community, oid, timeout=2, retries=1):
    it = getCmd(SnmpEngine(), CommunityData(community, mpModel=1),
                UdpTransportTarget((host, 161), timeout=timeout, retries=retries),
                ContextData(), ObjectType(ObjectIdentity(oid)))
    err, status, _, binds = next(it)
    print(host, oid, "error" if err else binds[0][1])

get_one("10.20.30.30", "public", "1.3.6.1.2.1.1.1.0")
```

## Flag Notes

- `-t 2 -r 1` keeps a filtered agent from stalling the run for the default timeout chain.
- `-Cn0 -Cr10` limits bulk requests to ten repetitions, which is what keeps a core switch responsive.
- Numeric OIDs avoid MIB resolution differences between hosts, which otherwise make outputs non-diffable.
