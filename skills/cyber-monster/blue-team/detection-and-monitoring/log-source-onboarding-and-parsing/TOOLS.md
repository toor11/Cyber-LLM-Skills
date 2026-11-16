# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`log-source-onboarding-and-parsing`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for proving emission, delivery and mapping separately. Never invent undocumented flags — check `--help` on the installed version, because collector component names and exporter options change between minor releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| OpenTelemetry Collector | `otelcol-contrib validate --config=file:config.yaml` then `otelcol-contrib --config=config.yaml --dry-run` is not supported; use `validate` before reload | Reject a broken pipeline config before it replaces a working one | Linux, Windows, macOS |
| Collector telemetry | `curl -s localhost:8888/metrics` and read `otelcol_receiver_accepted_log_records` / `otelcol_exporter_sent_log_records` / `otelcol_exporter_send_failed_log_records` | Reconcile accepted against sent against failed for one receiver | Any host running the collector |
| `fluent-bit` | `fluent-bit -c /etc/fluent-bit/fluent-bit.conf --dry-run` | Parse the config and exit without starting tail, catching syntax and plugin errors | Linux, Windows |
| `fluent-bit` metrics | `curl -s localhost:2020/api/v1/metrics` | Read per-input bytes and per-output retries to localise loss | Linux, Windows |
| `logstash` | `bin/logstash -f pipeline.conf --config.test_and_exit` | Validate a pipeline without running it | Linux, Windows |
| Elastic ingest simulate | `POST _ingest/pipeline/<id>/_simulate` with a captured document body | Prove the mapping produces the target fields from real bytes | Any host with HTTPS to Elasticsearch |
| `tcpdump` | `tcpdump -i any -s 0 -A 'tcp port 514' -c 20` | Capture raw syslog at the receiver to confirm the producer format before writing a parser | Linux |
| `jq` | `jq -c '.event // .message' sample.jsonl` | Inspect which branch a JSON log event actually populated | Linux, macOS, Windows |

## Minimal Script Shape

The shape below is the minimum defensible onboarding check: it reconciles collector counters for one receiver, then proves the target field survives the mapping.

```bash
#!/usr/bin/env bash
# onboarding-gate.sh — delivery reconciliation, then a mapping prove-out.
set -euo pipefail

METRICS="${METRICS:-http://localhost:8888/metrics}"
MIN_PCT="${MIN_PCT:-95}"

# 0. Validate config before touching the running pipeline.
otelcol-contrib validate --config=file:"${CONFIG:-./config.yaml}"

# 1. Delivery gate: sent must be within MIN_PCT of accepted for the receiver.
acc=$(curl -s "$METRICS" | awk '/otelcol_receiver_accepted_log_records\{/ {s+=$2} END {print s+0}')
sent=$(curl -s "$METRICS" | awk '/otelcol_exporter_sent_log_records\{/ {s+=$2} END {print s+0}')
pct=$(awk -v a="$acc" -v s="$sent" 'BEGIN { if (a==0) print 0; else printf "%.1f", 100*s/a }')
echo "accepted=${acc} sent=${sent} pct=${pct}"
awk -v p="$pct" -v m="$MIN_PCT" 'BEGIN { exit (p+0 >= m+0) ? 0 : 1 }' \
  || { echo "GAP: delivery below ${MIN_PCT}% -> INCONCLUSIVE (Telemetry Gap)"; exit 2; }

# 2. Mapping gate: the required field must survive the pipeline.
curl -s -u "$ES_AUTH" -H 'Content-Type: application/json' \
  "$ES_HOST/_ingest/pipeline/$PIPELINE/_simulate" \
  -d @<(jq -n --slurpfile d "${SAMPLE:-./sample.json}" '{docs:[{_source:$d[0]}]}') \
  | jq -e '.docs[0].doc._source.source.ip != null' >/dev/null \
  || { echo "GAP: source.ip not produced by pipeline -> detect rules on this field are blind"; exit 3; }
```

## Notes That Prevent Wrong Runs

- `--config.test_and_exit` and `validate` do not prove the parser is correct, only that the config is syntactically valid. Correctness comes from `_simulate` against a captured document.
- Collector metrics are cumulative since start; take two samples and subtract before computing a percentage, or a restart will look like a loss event.
- `tcpdump -A` prints payload as text and will mangle binary or compressed logs; use `-X` when the format is not plain text.
- `_ingest/pipeline/_simulate` does not write to an index. It is safe to run against production and is the correct way to test a mapping without backfilling.
