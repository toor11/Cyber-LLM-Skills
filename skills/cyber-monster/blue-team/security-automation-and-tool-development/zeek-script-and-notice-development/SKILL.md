---
name: zeek-script-and-notice-development
description: "Authors Zeek `.zeek` network security scripts: protocol event handlers (`http_request`, `dns_request`, `ssl_established`), `SumStats` threshold aggregation, JA3/JA4 and certificate anomaly detection, custom log streams, and `NOTICE` framework integration tested via `btest` over PCAPs. Use when extending Zeek network telemetry and detections."
family: security-automation-and-tool-development
tier: core
triggers: ["zeek script", "write bro script", "zeek notice framework", "sumstats zeek", "zeek btest"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, suricata-lua-and-rule-qa-tooling, ocsf-and-ecs-log-normalizer-development]
corpus_sparse: true
---

# Zeek Script and Notice Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A Zeek script is an event handler attached to a protocol analyzer, not a pattern matcher. The analyzer parses traffic into typed events (`http_request`, `dns_request`, `ssl_established`), and a handler either writes a field into a log stream or raises a `NOTICE`. Two consequences follow. First, detection logic can only see what the analyzer already parsed, so a script that "detects" a malformed header is really observing a parse failure event. Second, state is per-connection and per-worker: a global `table` accumulates across every flow a worker handles, so any table keyed by attacker-chosen values needs `&create_expire` or a `SumStats` reducer, otherwise worker memory grows without bound. `SumStats` is the cluster-transparent aggregator — observations go in, reducers compute, epochs flush results — and it is the only correct way to express "more than N of X in T seconds" on a clustered deployment, because the framework handles the flow-based load-balancing across workers. Zeek 8 keeps the Notice framework and `SumStats` API intact while renaming a base detection script (`detect-sqli.zeek` → `detect-sql-injection.zeek`) and changing which host lands in `src` versus `dst` for those notices.

- **CWE-778 (Insufficient Logging):** a script that silently drops an event class, or a notice type nobody routes, leaves the same blind spot as a disabled sensor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the detection is a simple per-connection property **THEN** write an event handler that raises `NOTICE([$note=..., $msg=..., $src=..., $dst=..., $identifier=...])` and `@load base/frameworks/notice`; validate with `zeek -Cr fixture.pcap local_policy.zeek`.
2. **IF** the detection is a rate or count over a window **THEN** use `SumStats::observe()` plus `SumStats::create()` with a `Reducer` (`SumStats::REDUCER_SUM`/`UNIQUE`) and an `epoch` interval, and never a bare global `table` counter.
3. **IF** the deployment is a cluster **THEN** rely on `SumStats` for cross-worker aggregation; a script that sums in a worker-local table reports per-worker numbers and silently under-counts.
4. **IF** the request is to change the wire-to-log mapping rather than add a detection **THEN** open [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md); field normalization belongs downstream of `conn.log`/`http.log`.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `zeek-script-and-notice-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable script and test invocations | [`QUERIES.md`](QUERIES.md) | `zeek -Cr` gate, `btest` layout, `sumstats` shapes |
| Need CLI syntax, flags, and framework references | [`TOOLS.md`](TOOLS.md) | `zeek` flags, `zeek-cut`, `btest` entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Memory-growth and notice-routing incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Sensor-scope handoff while a script is fixed |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Zeek 8.x scripting (`@load base/frameworks/notice`, `SumStats` framework, typed `record`/`NOTICE`), tested with `zeek -Cr` and `btest`
- **Mandatory Self-Validation Command:** `zeek -Cr test.pcap local_policy.zeek`

1. **Confirm the inputs.** Establish the Zeek version, whether the deployment is standalone or clustered, which analyzers are loaded (a script cannot fire on events an unloaded analyzer never raises), and which PCAP fixtures exist. Confirm the log stream that will carry the result.
2. **Choose the branch.** Per-connection property → event handler plus `NOTICE`. Rate/count over time → `SumStats` reducer with an epoch. Cross-connection correlation with a cheap key → `table` with `&create_expire`. Anything that must survive restarts does not belong in a script at all.
3. **Define how to validate the script.** Run `zeek -Cr` against a fixture PCAP that contains the behaviour, assert the notice appears in `notice.log` with the expected `note` and host fields, then run the same script against a benign PCAP and assert it does not. Wrap both in `btest` so the pair runs on every change.
4. **Name the stop condition.** Stop when a global table grows without an expiry, when a notice fires on the benign fixture, when the script fails to load (`zeek -Cr` reports a script error and exits non-zero), or when a cluster deployment produces counts that differ by worker.
5. **State what counts as a working tool.** A working script loads cleanly, produces exactly one notice for the malicious fixture and none for the benign one, keeps its state bounded by an explicit expiry or epoch, and names a `NOTICE` type that the notice routing (`Notice::policy`) actually escalates.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `NOTICE([$note=..., $src=..., $dst=..., $identifier=...])` | Proves the detection surfaced through the notice framework with a routable type, not a `print()` that nothing consumes |
| `SumStats::observe()` + `SumStats::create()` with `epoch` | Proves the rate detection is cluster-transparent and bounded per epoch rather than per worker |
| `table[addr] of count` with `&create_expire` | Proves per-source state cannot grow unbounded across a multi-hour capture |
| `notice.log` fields `note`, `src`, `dst`, `identifier` | Proves which host the script considers the actor — the Zeek 8 sqli notices moved the victim from `src` to `dst`, so the field choice is auditable |
| `zeek -Cr fixture.pcap policy.zeek` exit status | Proves the script compiles and loads; a script error invalidates every downstream assertion |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```zeek
# ANTI-PATTERN: unbounded global table, per-worker counts, and a print() nobody routes
@load base/protocols/dns

global dns_seen: table[addr] of count;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local src = c$id$orig_h;
    dns_seen[src] = dns_seen[src] + 1;
    if ( dns_seen[src] > 200 )
        print fmt("possible dns tunnel: %s", src);
    }
```

**Production-Grade Starter Skeleton (USE):**

```zeek
##! policy/dns_tunnel_window.zeek
##! Flags sources issuing many distinct subdomains of one parent within an epoch.
@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/dns

export {
    redef enum Notice::Type += { DNS_Tunnel_Window };
    const window: interval = 5min &redef;
    const threshold: count = 200 &redef;
}

event zeek_init()
    {
    local r = SumStats::Reducer($stream="dns.unique_query",
                                $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="dns_tunnel_window",
                      $epoch=window,
                      $reducers=set(r),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
                          return double(result["dns.unique_query"]$num);
                      },
                      $threshold=threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          NOTICE([$note=DNS_Tunnel_Window,
                                  $msg=fmt("%s issued %d unique queries in %s",
                                           key$host, result["dns.unique_query"]$num, window),
                                  $src=key$host,
                                  $identifier=cat(key$host)]);
                      }]);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( qtype != 1 && qtype != 28 )
        return;
    SumStats::observe("dns.unique_query", [$host=c$id$orig_h], [$str=query]);
    }
```

**Why this matters:** the count lives in a reducer with a declared epoch, so a clustered deployment aggregates correctly and memory is bounded by the epoch rather than by capture length; the alert exits through `NOTICE` with a typed note the site's `Notice::policy` can route.

## When It Is NOT This Issue

- **The notice never appears but `-C` replay shows the traffic** — check `Notice::policy`/`Site::notice_*` suppression before editing the script; a suppressed type logs nothing and looks identical to a logic bug.
- **A script "detects" SQL injection but reports the wrong host** — Zeek 8 replaced `detect-sqli.zeek` with `detect-sql-injection.zeek`, which places the victim in `dst` and the attacker in `src`, and populates `uid`. A site still reading the old semantics will mis-attribute.
- **Counts differ between standalone and cluster runs** — that is worker-local state, not a threshold tuning problem; move the aggregation into `SumStats`.
- **`zeek -Cr` fails on a script that worked interactively** — a `@load` path resolved from the interactive load path may not resolve in the same way from the CLI; confirm the script is in `ZEEKPATH` or passed by path.
- **DNS tunneling heuristics firing on CDN or software-update domains** — high distinct-subdomain counts are normal for some providers; the observable matches the technique without the technique being present.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER claim a `print()` or `NOTICE` without `@load base/frameworks/notice` will produce a routable alert; the notice type must be declared in `Notice::Type` to exist.
- NEVER present a bare global `table` counter as a rate detection on a cluster — it counts per worker, not per site.
- NEVER state that `SumStats` replaces a log stream, or that a notice replaces a log field: `notice.log` and the protocol logs are separate outputs.
- NEVER assert a specific JA3/JA4 field name without checking the installed Zeek version's `ssl.log` schema.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Zeek version, cluster mode, loaded analyzers, and fixture PCAPs for `zeek-script-and-notice-development` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The script, reducer, or btest case is specific and runnable (no generic 'add logging' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: zeek-script-and-notice-development
- **Target Stack & Schema**: Zeek 8.x with Notice framework, SumStats reducers, typed NOTICE
- **Safety, Scope & Exit-Code Guards**: [Table expiry, epoch bounds, fixture-only replay, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Suppressed notice types, cluster vs standalone counts, CDN-heavy DNS]
- **Implementation**:
  [Runnable `.zeek` script following the Starter Skeleton]
- **Self-Validation Command**: `zeek -Cr test.pcap local_policy.zeek`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md) - Portable rule layer that consumes these logs
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - File-side signatures for captured payloads
- [`suricata-lua-and-rule-qa-tooling`](../suricata-lua-and-rule-qa-tooling/SKILL.md) - The IDS counterpart with its own PCAP regression harness
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Normalizes `conn.log`/`http.log` for downstream search
- [`pcap-and-netflow-beacon-analysis-scripting`](../pcap-and-netflow-beacon-analysis-scripting/SKILL.md) - Offline periodicity analysis that complements online notices

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `zeek-script-and-notice-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
