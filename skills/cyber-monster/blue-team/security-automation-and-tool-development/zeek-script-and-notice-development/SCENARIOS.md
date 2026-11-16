# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`zeek-script-and-notice-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative script-engineering failures, each with the artifact that proves the diagnosis.

## Case 1: Worker memory climbs until the sensor is restarted

- **Surface & Preconditions:** a script tracks per-source DNS query counts in a global `table[addr] of count` with no expiry on a busy sensor.
- **Root cause & impact:** every distinct source address ever seen keeps an entry for the life of the worker process. Memory grows with capture duration rather than with current activity, and the sensor is eventually OOM-killed.
- **Verification & fix:** inspect the table declaration for `&create_expire`; move the counter into a `SumStats` reducer with an epoch, which resets on flush. See [`QUERIES.md`](QUERIES.md) for the replay gate.

## Case 2: Notice fires in `notice.log` but nobody is paged

- **Surface & Preconditions:** a new `Notice::Type` is declared and emitted, and the SOC reports no alert for a week.
- **Root cause & impact:** the site's `Notice::policy` never escalates the new type, so the notice is logged at default action and silently discarded by the forwarding pipeline.
- **Verification & fix:** grep the site policy for the type name; add an explicit `Notice::ACTION_ALERT` (or the site's escalation hook) for it before enabling.

## Case 3: Cluster under-counts by the number of workers

- **Surface & Preconditions:** a per-source counter is implemented as a script-level table during a pilot on a standalone sensor, then promoted to a clustered production deployment.
- **Root cause & impact:** each worker sums only the flows it was assigned, so a source distributing its traffic across workers never crosses the threshold. The detection looks like a tuning failure.
- **Verification & fix:** move the aggregation to `SumStats`, which is cluster-transparent by design, and re-validate on the cluster rather than in `-C` replay only.

## Case 4: SQL-injection notice attributes the wrong host after upgrade

- **Surface & Preconditions:** a site upgrades to Zeek 8 and reads `protocols/http/detect-sqli.zeek` output unchanged.
- **Root cause & impact:** Zeek 8's replacement script `detect-sql-injection.zeek` puts the victim in `dst` and the attacker in `src`, and carries the first sampled connection `uid`; a consumer assuming the old field placement blames the victim.
- **Verification & fix:** key downstream logic on the presence of `uid` and `dst` to tell which script produced the entry, and re-map any dashboard or enrichment that read `src` as the victim.
