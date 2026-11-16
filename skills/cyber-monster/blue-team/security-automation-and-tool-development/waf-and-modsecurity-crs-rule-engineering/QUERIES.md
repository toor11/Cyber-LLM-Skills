# Detection Queries and Telemetry Artifacts

> Sub-skill: [`waf-and-modsecurity-crs-rule-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

WAF rule and regression artifacts owned by this slug. Confirm CRS version and paranoia level on the target before deploying an exclusion.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `ctl:ruleRemoveTargetById=<id>;ARGS:<name>` on a path scope | High | Exactly one rule's view of one argument is excluded |
| 2 | Same `ctl` in the phase where the variable exists | High | The exclusion executes where the target is populated |
| 3 | Blocking evaluation rule still present and enabled | High | The overall control still blocks above threshold |
| 4 | `tx.blocking_paranoia_level` in CRS 4 | High | Configuration uses the current variable name |
| 5 | go-ftw case blocking an attack on the excluded endpoint | High | The exception did not become a bypass |

## Detection Artifacts

```text
[waf-and-modsecurity-crs-rule-engineering:rule-spec] exclude a rule's target on a path, never the rule or the evaluation rule
[waf-and-modsecurity-crs-rule-engineering:filter-fp] phase mismatch makes a ctl a no-op with no error
[waf-and-modsecurity-crs-rule-engineering:correlate] rule id + variable + path identifies one exclusion unambiguously
```

Confirm which rules are firing on the false positive before changing anything (Linux shell on the WAF host; WSL or SSH from Windows):

```bash
grep -o 'id "[0-9]*"' /var/log/modsec_audit.log | sort | uniq -c | sort -rn | head
```

Check the effective paranoia variables in the running configuration:

```bash
grep -rE 'blocking_paranoia_level|detection_paranoia_level|paranoia_level' /etc/modsecurity/crs/crs-setup.conf
```

Regression run with go-ftw, in detection mode, filtered to the affected rule:

```bash
cd /opt/waf
./go-ftw run --config .ftw.apache.yaml -d ../coreruleset/tests/regression/tests/ -i "942100|1000100"
```

```text
# go-ftw summary lines to look for: one pass for the excluded legitimate request,
# one pass for the attack case that must still be blocked on the same endpoint
```

Validation that the exclusion did not silence the evaluation rule:

```bash
grep -c 'SecRuleRemoveById 949110' /etc/modsecurity/*.conf /etc/modsecurity/crs/*.conf 2>/dev/null
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the CRS version and paranoia level with every exclusion; the same rule behaves differently across versions.
- Keep detection-only traffic logs for the excluded endpoint for a week after the change to confirm the exception is not hiding attack traffic.
