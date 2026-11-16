# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`service-enumeration-snmp-and-infrastructure`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `service-enumeration-snmp-and-infrastructure`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Agent identity

**Expected differential.** A returned `sysDescr` proves answerability; `authorizationError` proves the agent is present but the community is wrong, which is a different finding.

```bash
snmpget -v2c -c public -t 2 -r 1 10.20.30.30 1.3.6.1.2.1.1.1.0
snmpget -v3 -l authPriv -u monitor -a SHA -A authpw -x AES -X privpw 10.20.30.30 1.3.6.1.2.1.1.1.0
```

## Reachability versus answerability

**Expected differential.** `open|filtered` on UDP 161 with no reply and `filtered` with an ICMP unreachable are different states, and only one of them suggests an agent behind a firewall.

```bash
nmap -sU -p 161 --reason 10.20.30.30
nmap -sU -p 161 --script snmp-info 10.20.30.30
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
