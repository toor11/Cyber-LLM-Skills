---
name: siem-query-transpiler-and-enrichment-scripting
description: "Develops programmatic SIEM query runners and context-enrichment services (KQL, Splunk SDK, Elasticsearch Python client): parameterized query templates (preventing query injection), local MaxMind/ASN/CMDB-owner caching, and paginated alert hydration. Use when scripting SIEM investigations or alert enrichment."
family: security-automation-and-tool-development
tier: core
triggers: ["siem enrichment script", "kql python sdk", "splunk sdk query", "alert hydration script"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# SIEM Query Transpiler and Enrichment Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A SIEM query string is code, and the platforms treat it that way: KQL, SPL, and Elasticsearch Query DSL all have quoting, wildcard, and operator semantics that user-supplied values can break out of. An alert title, a hostname, or an IOC pasted into a query template is an injection surface, and the mitigation differs per platform — KQL and SPL have no bind parameters, so values must be escaped by a strict allowlist (quote, backslash, and wildcard escaping) and length-bounded, while Elasticsearch accepts a structured query object where the value never joins the query text at all. Every SDK also has its own result model. `azure-monitor-query`'s `LogsQueryClient.query_resource` returns a `LogsQueryResult` or `LogsQueryPartialResult` and requires a `timespan` — a `timedelta` for "last N" or a `(start, end)` tuple of timezone-aware datetimes — and a partial result must be handled, not treated as success. Splunk's `splunklib` returns a stream that `results.JSONResultsReader` parses, with `results.Message` entries interleaved among result dicts. Elasticsearch's `AsyncElasticsearch.search` takes `index`, `query` (a DSL dict), and `size`. Enrichment is the second half: resolving an IP to an ASN or a host to a CMDB owner must be cached locally and must never turn an alert pipeline into a per-alert API call storm.

- **CWE-778 (Insufficient Logging):** an enrichment service that swallows a query error and returns an unenriched alert hides the failure inside what looks like a normal result.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are building a query from user- or alert-supplied values **THEN** never concatenate: bind into a structured query object where the platform supports it (Elasticsearch DSL), and for KQL/SPL apply a strict escaping plus allowlist function with a length cap.
2. **IF** you query Azure Monitor **THEN** pass `timespan` as `timedelta(days=N)` or a `(start, end)` tuple of UTC-aware datetimes, and handle `LogsQueryPartialResult` explicitly rather than assuming `LogsQueryStatus.SUCCESS`.
3. **IF** you query Splunk **THEN** use `service.jobs.oneshot(query, output_mode="json")` with `results.JSONResultsReader` and skip `results.Message` entries; the XML `ResultsReader` is deprecated.
4. **IF** you enrich per alert **THEN** put a bounded LRU cache in front of any network lookup and pre-load the local MaxMind/ASN database, so one incident with 500 alerts does not become 500 lookups.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `siem-query-transpiler-and-enrichment-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable query and enrichment shapes | [`QUERIES.md`](QUERIES.md) | Parameterized KQL/SPL/ES queries, caching, pagination |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | SDK entry points and version pins |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Injection and enrichment-storm incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Investigation-handoff runbook |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** `azure-monitor-query` `LogsQueryClient`/`LogsQueryStatus`, `splunklib` `client.connect` + `results.JSONResultsReader`, `elasticsearch.AsyncElasticsearch.search`, with a local MaxMind/CMDB cache in front of all enrichment
- **Mandatory Self-Validation Command:** `python -m py_compile siem_enrich.py`

1. **Confirm the inputs.** Establish the platform(s) in scope, the query language and its escaping rules, the time range semantics the platform expects, the result-pagination model, and the enrichment sources with their rate limits. Confirm which values in the query come from untrusted input — alert fields are untrusted by default.
2. **Choose the branch.** Structured query platform → bind values as objects. Text query platform → escape and allowlist every interpolated value. Multi-platform → a small transpiler with per-platform escaping, tested per target. Enrichment → cache-first with a bounded size and TTL.
3. **Define how to validate the script.** For injection: a value containing a quote, a wildcard, and a newline must not change the parsed query structure — assert on the resulting query object or escaped string. For results: assert that a partial result is surfaced as partial, that pagination retrieves all pages, and that a cached lookup returns the same value as the first call without a second network request.
4. **Name the stop condition.** Stop when an interpolated value escapes its quoting, when a query returns a partial result that is treated as complete, when a page loop does not advance its cursor, or when enrichment lookups scale linearly with alert count instead of with distinct entities.
5. **State what counts as a working tool.** A working runner exits `0` only when the query executed against the intended range and every result page was consumed, `1` when a partial result or a rejected value occurred, and `2` on authentication or connectivity failure — with the failure distinguishable from an empty result set.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `query={"bool": {"filter": [{"term": {"host.name": value}}]}}` | Proves the value is data in a DSL object, not text spliced into a query |
| Escaped-and-allowlisted interpolation for KQL/SPL | Proves text-platform queries cannot be restructured by an alert field |
| `LogsQueryStatus.SUCCESS` versus partial-result handling | Proves a truncated Azure query is reported as partial, not as complete |
| `results.JSONResultsReader` skipping `results.Message` | Proves Splunk diagnostics are separated from result rows |
| Bounded cache with TTL in front of enrichment | Proves lookups scale with distinct entities, not with alert volume |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: alert fields concatenated into the query, no time bound, no partial
# handling, and an enrichment lookup per alert.
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

client = LogsQueryClient(DefaultAzureCredential())

def hunt(hostname: str, ioc: str) -> list:
    query = f"SecurityEvent | where Computer == '{hostname}' and CommandLine contains '{ioc}'"
    response = client.query_workspace(workspace_id="ws", query=query, timespan=None)
    return [row for table in response.tables for row in table.rows]
```

**Production-Grade Starter Skeleton (USE):**

```python
# siem_enrich.py - Exit 0 complete, 1 partial result or rejected value, 2 auth/transport failure
import datetime as dt
import re
import sys
from collections import OrderedDict

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
SAFE_HOST = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
SAFE_IOC = re.compile(r"^[A-Za-z0-9 ./:_-]{1,256}$")

def require_safe(value: str, pattern: re.Pattern, label: str) -> str:
    if not pattern.match(value):
        raise ValueError(f"{label} rejected by allowlist: {value[:40]!r}")
    return value

def escape_kql_literal(value: str) -> str:
    """Escape a value for a KQL single-quoted string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")

class BoundedCache:
    def __init__(self, capacity: int = 2048, ttl_seconds: int = 900):
        self.capacity = capacity
        self.ttl = dt.timedelta(seconds=ttl_seconds)
        self._data: OrderedDict[str, tuple[dt.datetime, str]] = OrderedDict()

    def get(self, key: str) -> str | None:
        hit = self._data.get(key)
        if not hit:
            return None
        stored_at, value = hit
        if dt.datetime.now(dt.timezone.utc) - stored_at > self.ttl:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def put(self, key: str, value: str) -> None:
        self._data[key] = (dt.datetime.now(dt.timezone.utc), value)
        self._data.move_to_end(key)
        while len(self._data) > self.capacity:
            self._data.popitem(last=False)

def hunt(client: LogsQueryClient, workspace: str, hostname: str, ioc: str) -> tuple[list, bool]:
    host = escape_kql_literal(require_safe(hostname, SAFE_HOST, "hostname"))
    needle = escape_kql_literal(require_safe(ioc, SAFE_IOC, "ioc"))
    query = (
        "SecurityEvent"
        f" | where Computer == '{host}'"
        f" | where CommandLine contains '{needle}'"
        " | project TimeGenerated, Computer, Account, CommandLine"
    )
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=24)
    response = client.query_workspace(workspace_id=workspace, query=query, timespan=(start, end))
    if response.status == LogsQueryStatus.SUCCESS:
        rows = [row for table in response.tables for row in table.rows]
        return rows, False
    partial = [row for table in response.partial_data for row in table.rows]
    sys.stderr.write(f"partial result: {response.partial_error}\n")
    return partial, True

def main() -> int:
    try:
        client = LogsQueryClient(DefaultAzureCredential())
        rows, partial = hunt(client, "workspace-id", "WEB01", "powershell -enc")
    except ValueError as exc:
        sys.stderr.write(f"rejected input: {exc}\n")
        return 1
    except HttpResponseError as exc:
        sys.stderr.write(f"query failed: {exc}\n")
        return 2
    for row in rows:
        print(row)
    return 1 if partial else 0

if __name__ == "__main__":
    raise SystemExit(main())
```

**Why this matters:** the hostname and IOC pass an allowlist and an escaping function before entering the query text, the time window is explicit rather than unbounded, and a partial response is returned with a distinct exit code instead of being reported as a complete hunt.

## When It Is NOT This Issue

- **An alert query returns nothing for a host that clearly exists** — field names differ per table and per schema version (`Computer` vs `host.name`); confirm the table schema before concluding the host had no activity.
- **A query works interactively but times out from the SDK** — the SDK enforces a server timeout and a row cap; a partial result is the platform telling you it truncated, not a code bug.
- **Enrichment values are wrong but plausible** — the local MaxMind database is stale; check the database build date before trusting any ASN or country.
- **Splunk returns a `results.Message` instead of a result** — that is a diagnostic (often a search warning), not an empty result set; skipping it silently hides query problems.
- **A parameterized query still fails on a value with an apostrophe** — the escaping function handles the platform's literal syntax, not shell or JSON syntax; using the wrong escaper for the layer is the bug.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER present string concatenation into KQL/SPL as safe because the value "comes from an alert"; alert fields are attacker-influenced.
- NEVER treat `LogsQueryPartialResult` as success, and never report an empty result before distinguishing it from an auth failure.
- NEVER call an enrichment API once per alert; cache by entity with a bounded size and TTL.
- NEVER assert a specific SDK method or field name without checking the installed package version — these clients change namespaces across majors.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Platform(s), query language escaping rules, time-range semantics, and enrichment sources for `siem-query-transpiler-and-enrichment-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The query builder, escaping function, or cache is specific and runnable (no generic 'validate inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: siem-query-transpiler-and-enrichment-scripting
- **Target Stack & Schema**: azure-monitor-query LogsQueryClient, splunklib JSONResultsReader, or Elasticsearch DSL with per-platform value binding
- **Safety, Scope & Exit-Code Guards**: [Allowlist plus escaping, explicit timespan, partial-result handling, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Field-name divergence, truncated results, stale enrichment data, diagnostic messages]
- **Implementation**:
  [Runnable runner or enrichment service following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile siem_enrich.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Produces the normalized fields these queries filter on
- [`syslog-and-cloudtrail-stream-parsers`](../syslog-and-cloudtrail-stream-parsers/SKILL.md) - Supplies the cloud event stream being queried
- [`soar-playbook-and-webhook-connector-development`](../soar-playbook-and-webhook-connector-development/SKILL.md) - Consumes enriched alerts for automated response
- [`edr-api-triage-and-containment-scripting`](../edr-api-triage-and-containment-scripting/SKILL.md) - The endpoint-side query surface with the same guarded-call pattern

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `siem-query-transpiler-and-enrichment-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
