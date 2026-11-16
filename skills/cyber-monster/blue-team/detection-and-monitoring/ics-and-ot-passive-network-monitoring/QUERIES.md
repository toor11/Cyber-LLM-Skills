# Detection Queries and Telemetry Artifacts

> Sub-skill: [`ics-and-ot-passive-network-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Queries read passive protocol logs produced by a span port or tap — typically Zeek with OT parsers, whose Modbus output records function code, address, quantity, and values per transaction. None of the blocks polls a device. Field names below follow the CISA ICSNPP-style Zeek logs (`modbus_detailed.log`, `modbus.log`) and a generic flow record; substitute your parser's names after confirming the field set.

## Class 1 — Communication matrix build (baseline)

Expected hit: one row per source-destination pair per protocol with its observed function codes and request rate. This table is the definition of normal for every later class.

```spl
index=ot sourcetype="zeek:modbus_detailed" earliest=-14d@d latest=@d
| eval pair = id_orig_h."->".id_resp_h
| stats values(func) AS function_codes, min(quantity) AS qty_min, max(quantity) AS qty_max,
        count AS txns, dc(uid) AS sessions by pair
| eval txns_per_session = round(txns/nullif(sessions,0), 1)
| sort - txns
```

False-positive note: a 14-day window that contains no recipe change or maintenance period omits legitimate traffic; confirm the modes covered before treating an unlisted function code as anomalous.

## Class 2 — Write-direction function codes from a read-only source

Expected hit: a pair where the source has only ever read, now issuing a write. A change of role for a known host is stronger evidence than a brand-new host, because the host's credentials and position are already trusted.

```spl
index=ot sourcetype="zeek:modbus_detailed" earliest=-24h@h latest=@h
| eval is_write = if(func IN ("5","6","15","16","22","23"), 1, 0)
| stats sum(is_write) AS writes, count AS total by id_orig_h, id_resp_h
| join type=left id_orig_h, id_resp_h
    [ search index=ot sourcetype="zeek:modbus_detailed" earliest=-30d@d latest=-1d@d
      | eval is_write = if(func IN ("5","6","15","16","22","23"), 1, 0)
      | stats sum(is_write) AS base_writes by id_orig_h, id_resp_h ]
| where writes > 0 AND (isnull(base_writes) OR base_writes == 0)
| sort - writes
```

False-positive note: function code numbering differs between Modbus variants and some parsers log names rather than numbers; confirm the mapping in your parser before relying on the numeric list.

## Class 3 — Program download and block transfer

Expected hit: programming or download service codes on a destination. In S7comm these are the block download services; in DNP3 they are the file-transfer function codes. This class carries the highest severity in most plants.

```spl
index=ot sourcetype="zeek:s7comm" earliest=-7d@d latest=@d
| where service IN ("0x1a","0x1b","0x1c","0x1d","0x28","0x29")
| stats count AS events, values(service) AS services, dc(id_orig_h) AS sources by id_resp_h
| sort - events, id_resp_h
```

False-positive note: an engineering workstation performing a scheduled logic update produces exactly this shape; the work order is the discriminator, so join the change record before assigning severity.

## Class 4 — Mode change and restart

Expected hit: cold or warm restart, stop, or mode-change events on a controller. These often accompany a logic download and are worth alerting on independently because some tooling restarts the device without an explicit download.

```spl
index=ot sourcetype="zeek:modbus_detailed" earliest=-7d@d latest=@d
| where func IN ("8") AND sub_function IN ("1","2","4")
| stats count AS restarts, values(id_orig_h) AS sources, min(_time) AS first, max(_time) AS last
        by id_resp_h
| sort - restarts
```

False-positive note: diagnostics function 8 with other sub-functions is routine line monitoring; only the restart sub-functions change device state, so the sub-function filter is what keeps this quiet.

## Class 5 — Source role drift across destinations

Expected hit: a host contacting destinations it has never contacted, or contacting far more destinations than its role implies. Inside OT this is the lateral-movement shape and it is visible without protocol depth.

```spl
index=ot sourcetype="zeek:conn" earliest=-7d@d latest=@d
| where id_resp_p IN (502, 102, 20000, 44818, 4840)
| stats dc(id_resp_h) AS dests, count AS conns by id_orig_h
| join type=left id_orig_h
    [ search index=ot sourcetype="zeek:conn" earliest=-60d@d latest=-7d@d
      | where id_resp_p IN (502, 102, 20000, 44818, 4840)
      | stats dc(id_resp_h) AS base_dests by id_orig_h ]
| where dests > coalesce(base_dests, 0) + 2
| sort - dests
```

False-positive note: a vendor laptop brought in for commissioning contacts many devices by design; check whether the host is in the asset inventory and whether a work order covers the period.

## Class 6 — MAC and IP pairing stability

Expected hit: a known IP presenting a new MAC, or a MAC appearing under more than one IP. On a stable OT segment this indicates a replaced device, an impersonation, or an unauthorised laptop.

```spl
index=ot sourcetype="zeek:arp" OR sourcetype="zeek:dhcp" earliest=-7d@d latest=@d
| stats dc(mac) AS macs, values(mac) AS mac_list by ip
| where macs > 1
| sort - macs
```

False-positive note: a device replacement, a NIC swap, or a redundant controller pair sharing a virtual address legitimately produces multiple MACs; confirm against the maintenance record.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Attach the operating modes the baseline covered and the covered segments to every deployed OT rule; a rule without them cannot be reviewed by a process engineer.
