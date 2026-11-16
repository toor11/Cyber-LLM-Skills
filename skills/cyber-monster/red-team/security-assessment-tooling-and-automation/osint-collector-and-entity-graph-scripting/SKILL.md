---
name: osint-collector-and-entity-graph-scripting
description: "Engineers passive OSINT collection and entity-resolution pipelines in Python: rate-limited Certificate Transparency (`crt.sh`/CertStream), RDAP/WHOIS, and passive DNS clients, deterministic entity graph deduplication (`domain`, `ip`, `asn`, `org`), and provenance-stamped SQLite/JSONL storage. Use when building passive reconnaissance or brand-monitoring tools."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["osint python script", "crt.sh collector", "entity graph osint", "rdap python", "certstream"]
cwe: [CWE-200]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
---


# OSINT Collector and Entity Graph Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)

## Mechanism and Preconditions

Building an OSINT collector that stores observations in SQLite with provenance — source, retrieval timestamp, and a hash of the raw record — and then derives an entity graph by joining observations that share a strong identifier. The engineering discipline is that every edge in the graph must be traceable to a stored observation, so a conclusion can be re-derived or retracted when a source changes.

- **Provenance precedes analysis.** A row without source, timestamp, and hash cannot be defended later, and a graph edge without a row is an opinion.
- **Entity resolution needs a confidence tier.** Exact identifier matches (certificate fingerprint, account id) are strong; name or avatar similarity is weak and must be stored separately.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a source returns mutable data **THEN** store the raw payload hash so a later change is detectable rather than silent.
2. **IF** two records share only a display name **THEN** record a weak edge and require a second independent identifier before promoting it.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an authorised collection scope, a rate limit per source, and a schema that stores provenance — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11+ with `sqlite3` (WAL mode), `httpx` for retrieval, and a schema where every row carries `source`, `fetched_at`, `raw_sha256`
- **Mandatory Self-Validation Command:** `python -c "import sqlite3, httpx; print(sqlite3.sqlite_version)"`

1. Confirm the target surface: write the collection scope down (which sources, which identifiers), and confirm each source's terms allow the query.
2. Choose the branch: identifier-first collection (certificate, account id, domain), name-first collection for discovery, or archive-first collection when the live record is gone.
3. Define the differential: re-fetch one record and compare its stored hash; a change means the source is mutable and the earlier observation must be kept, not overwritten.
4. Name the stop condition: a per-source request budget and a fixed collection window, recorded in the output so coverage is explicit.
5. Prove it: every graph edge carries the observation ids on both ends, so a reviewer can walk from a cluster back to the retrieved record.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `sqlite3.connect(db, isolation_level=None) with `PRAGMA journal_mode=WAL`` | Makes concurrent writes safe while a long collection runs, without a server. |
| `store(raw_sha256, source, fetched_at)` | The provenance tuple; without all three a later claim cannot be sourced. |
| `strong vs weak edge tables` | Keeps exact-identifier joins separate from similarity joins so confidence is a schema property. |
| `per-source token bucket before each request` | Rate limiting as code, matching each source's published limits. |

## Worked Contrast

**Collector That Overwrites and Merges on Name:**

```python
rows = fetch_all("https://source.example/search", params={"q": target})
for r in rows:
    db.execute("INSERT OR REPLACE INTO entity(name, data) VALUES (?, ?)",  # BUG: no source, no timestamp, no hash
               (r["display_name"], str(r)))
```

**Provenance-First Insert With Explicit Edge Strength:**

```python
import hashlib, json, sqlite3, time

con = sqlite3.connect("osint.db", isolation_level=None)
con.execute("PRAGMA journal_mode=WAL")
con.execute("""CREATE TABLE IF NOT EXISTS obs (
  id INTEGER PRIMARY KEY, source TEXT, query TEXT, fetched_at TEXT,
  raw_sha256 TEXT, payload TEXT)""")

def store(source, query, payload):
    blob = json.dumps(payload, sort_keys=True).encode()
    con.execute("INSERT INTO obs (source, query, fetched_at, raw_sha256, payload) VALUES (?,?,?,?,?)",
                (source, query, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 hashlib.sha256(blob).hexdigest(), blob.decode()))
```

**Why this matters:** `INSERT OR REPLACE` on a display name silently destroys the earlier observation and merges two entities that merely share a name. Storing each retrieval with its source, timestamp and hash preserves the record, and separating edge strength in the schema means a name-only coincidence never appears with the same weight as a certificate fingerprint match.

## When It Is NOT This Issue

- **Name collision read as same entity.** Two people with the same display name are not one entity; require a second identifier.
- **Archive copy read as current state.** A cached or archived record describes the past; timestamp decides whether it is evidence of the present.
- **Source returning synthesised data.** Some aggregators infer fields; confirm the field appears in the primary source before treating it as observed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `sqlite3` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `osint-collector-and-entity-graph-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: osint-collector-and-entity-graph-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `sqlite3`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile osint_collector_and_entity.py; python osint_collector_and_entity.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `osint-collector-and-entity-graph-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 27 |
| Distinct dataset sources | 2 |
| Top sources | osint-tool-database (16), osint-ctf-corpus-fr (11) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 11 cases |
| Grounding | multi-dataset corpus-grounded |
