# Verification Probes and Expected Differentials

> Sub-skill: [`ics-ot-protocol-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — OPC UA endpoint inventory

```text
# What does the server offer? Read-only discovery.
python - <<'ICSOTPROTOCOLAD97E_CLASS1'
from opcua import Client
c = Client("opc.tcp://10.20.30.40:4840")
c.connect()
for ep in c.get_endpoints():
    print(ep.EndpointUrl, ep.SecurityPolicyUri.split("#")[-1], ep.SecurityMode,
          [t.TokenType for t in ep.UserIdentityTokens])
c.disconnect()
ICSOTPROTOCOLAD97E_CLASS1
```

Expected differential: only a current policy with `SignAndEncrypt` and certificate tokens is the control; `Basic128Rsa15` or `None` with an `Anonymous` token is the finding, and the endpoint line is the citation.

## Class 2 — Reachability per protocol

```text
nmap -p 502,20000,44818,4840,102 --script modbus-discover,opcua-info "$TARGET"
# Then from a host outside the zone, the same probe: a response is the finding.
```

Expected differential: a filtered port from outside the zone is the control; an open port answering a protocol request is the finding, and the source host is part of the evidence.

## Class 3 — Configuration review

```text
rg -n --no-heading "SecurityPolicy|Basic128Rsa15|SecurityMode|Anonymous|UserToken" server-config.xml
rg -n --no-heading "secureAuth|SecureAuthentication|DNP3" outstation.conf 2>/dev/null
```

Expected differential: a policy list containing only current policies is the control; every deprecated policy and every anonymous token entry is a separate finding with its line.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
