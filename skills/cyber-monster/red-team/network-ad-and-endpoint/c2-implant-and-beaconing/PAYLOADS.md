# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`c2-implant-and-beaconing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `c2-implant-and-beaconing`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Inter-arrival statistics

**Expected differential.** A narrow distribution at a round interval proves a scheduled check-in; a wide distribution proves human or variable traffic.

```bash
cat conn.log | zeek-cut id.orig_h id.resp_h ts | awk '{print $1,$2,$3}' | head -50
nfdump -r nfcapd.current -s record/bytes -n 20
```

## Sanctioned-agent comparison

**Expected differential.** A destination absent from the inventory proves the pattern is unexplained; a listed destination does not.

```bash
Get-Content sanctioned-agents.txt
tcpdump -ni eth0 -c 200 'tcp port 443' | Select-String 'suspect.example'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
