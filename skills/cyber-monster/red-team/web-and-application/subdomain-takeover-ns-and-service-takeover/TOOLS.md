# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`subdomain-takeover-ns-and-service-takeover`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` | `dig NS legacy.<target-domain> +trace` | Trace delegation from the root to reveal whether the final nameservers answer authoritatively | Linux, macOS, Windows |
| `dnsrecon` | `dnsrecon -d <target-domain> -t std` | Enumerate NS, MX, and SOA records to surface lame or stale delegations | Linux, macOS, Windows |
| `whois` | `whois ns1.<lapsed-dns-provider>` | Check registrability of the delegated nameserver domain before claiming a takeover | Linux, macOS, Windows |
| `nmap` | `nmap -sn <released-ip>` | Confirm whether a released address is live and in the expected cloud range without connecting to services | Linux, macOS, Windows |

## Minimal Script Shape

Reads the delegated NS set from the parent nameserver and asks each delegated nameserver for the SOA, flagging a possible NS takeover when none answer authoritatively.

```python
import subprocess

LABEL = "legacy.target.example"
PARENT_NS = "ns-parent.example.net"

def dig(args):
    out = subprocess.run(["dig", "+short"] + args, capture_output=True, text=True, timeout=15)
    return out.stdout.strip().splitlines()

delegated = dig(["NS", LABEL, "@" + PARENT_NS])
lame = []
for ns in delegated:
    soa = dig(["+norecurse", "SOA", LABEL, "@" + ns.rstrip(".")])
    if not soa:
        lame.append(ns)
print({"delegated_ns": delegated, "lame_or_unanswered": lame,
       "possible_ns_takeover": bool(delegated) and len(lame) == len(delegated)})
```
