---
name: stix-taxii-and-misp-ioc-pipeline-scripting
description: "Builds Threat Intelligence (CTI) ingestion and IOC lifecycle scripts using `stix2`, `taxii2-client`, and `PyMISP`: indicator canonicalization (defang/refang), RFC1918/Alexa-top-domain/CDN allowlist filtering to prevent self-inflicted outages, confidence time-decay, and expiration sweepers. Use when automating IOC feeds into SIEM/EDR/firewalls."
family: security-automation-and-tool-development
tier: core
triggers: ["stix2 python", "taxii2 client script", "pymisp automation", "ioc pipeline allowlist", "ioc confidence decay"]
cwe: [CWE-20]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# STIX TAXII and MISP IOC Pipeline Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

An IOC pipeline is a supply chain in the literal sense: untrusted third-party data flows into enforcement points (firewalls, DNS sinks, EDR blocklists) where a bad entry causes an outage rather than a bad report. STIX 2.1 is the interchange format — an `Indicator` carries a `pattern` in the STIX patterning language plus a `pattern_type` of `stix`, and `valid_from`/`valid_until` express the window in which the indicator is meaningful. TAXII 2.1 is the transport (`taxii2client.v21.Collection` with `get_objects`/`as_pages` for paging and `add_objects` for publishing), and MISP is the operational store most SOCs actually run, reachable through PyMISP. The pipeline itself has four non-negotiable stages, in order. Canonicalize the observable: refang defanged input (`hxxp://`, `[.]`, `[:]`) before comparison, because a defanged value never matches a live log. Filter for self-harm: reject RFC1918/loopback/link-local addresses, your own registered domains, shared CDN and cloud ranges, and public resolver addresses — blocking those is how an IOC feed takes out internal traffic. Score and decay confidence: an indicator's usefulness decays with age, so a static confidence value overstates old data. And expire: `valid_until` plus a local sweeper removes indicators that no longer justify enforcement.

- **CWE-20 (Improper Input Validation):** unfiltered feed data reaching an enforcement point converts a third party's typo into your outage.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you ingest a feed **THEN** parse with `stix2.parse` (or the TAXII client's returned bundle) and validate every indicator's `pattern_type` is `stix` before attempting to interpret the pattern.
2. **IF** a value looks defanged (`hxxp`, `[.]`, `[:]`) **THEN** refang it first, then canonicalize (lowercase hostnames, strip trailing dots, normalize IP notation) before any comparison or enforcement.
3. **IF** a candidate indicator is private, loopback, link-local, a shared CDN/cloud range, a public resolver, or one of your own domains **THEN** drop it and record why; never push it to a blocklist.
4. **IF** you publish to a store **THEN** set `valid_from`/`valid_until` and carry a confidence value that decays with age; the sweeper deletes expired indicators rather than leaving them enforced forever.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `stix-taxii-and-misp-ioc-pipeline-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable ingest and filter shapes | [`QUERIES.md`](QUERIES.md) | STIX parse, TAXII paging, MISP publish, allowlist filters |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `stix2`, `taxii2client`, `PyMISP` entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Self-block and stale-indicator incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Feed-compromise handoff |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** `stix2` (>= 3.0, STIX 2.1 `Indicator` with `pattern_type="stix"`), `taxii2client.v21` (`Collection`, `as_pages`), `PyMISP` (>= 2.5, `PyMISP`/`MISPEvent`/`MISPAttribute`) with local allowlist and confidence-decay logic
- **Mandatory Self-Validation Command:** `python -m py_compile ioc_pipeline.py`

1. **Confirm the inputs.** Establish feed sources and their trust level, the transport (TAXII collection, MISP event, or file drop), the enforcement points and their tolerances, your own domain and address inventory, and the retention policy for indicators. Confirm who can authorize a manual override of an allowlist.
2. **Choose the branch.** Ingest-only → parse, canonicalize, filter, store. Enforce → additionally require confidence threshold plus expiry plus a rollback path. Publish outward → require STIX validity fields and TLP marking so downstream consumers know the sharing scope.
3. **Define how to validate the pipeline.** Fixture set: a defanged indicator that must refang and match, a private address that must be filtered, your own domain that must be filtered, a stale indicator that must be expired by the sweeper, and a CDN range that must be excluded. Assert counts per outcome so the filter is measured rather than assumed.
4. **Name the stop condition.** Stop when an indicator's pattern cannot be parsed, when the allowlist decision is ambiguous (e.g. a domain that resolves into a shared range), when confidence is below the enforcement threshold, or when `valid_until` has passed. Every dropped indicator is recorded with a reason.
5. **State what counts as a working tool.** A working pipeline exits `0` when every feed item was classified (enforced, stored-only, or dropped-with-reason), `1` when a policy decision requires review, and `2` on transport or authentication failure. It never enforces a value that failed the self-harm filters, and it can answer "why is this indicator blocked" from its own records.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `stix2.parse(...)` with `pattern_type == "stix"` check | Proves the pattern is in the language being interpreted, not an arbitrary string |
| Refang-then-canonicalize step before comparison | Proves defanged feed values match live telemetry and dedupe consistently |
| `ipaddress.ip_address(x).is_private` plus explicit resolver/CDN ranges | Proves self-harm filters run before any blocklist write |
| `valid_from`/`valid_until` on the published indicator | Proves enforcement has an expiry the sweeper can act on |
| Confidence value with an age-based decay function | Proves old indicators cannot retain their original weight indefinitely |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: raw pattern text pushed to the blocklist, no refang, no self-harm
# filter, no expiry, and a static confidence for every indicator.
import requests

def push(bundle_url, firewall_api):
    bundle = requests.get(bundle_url, timeout=10).json()
    for obj in bundle.get("objects", []):
        if obj["type"] != "indicator":
            continue
        value = obj["pattern"].split("'")[1]
        requests.post(firewall_api, json={"block": value, "confidence": 100}, timeout=10)
```

**Production-Grade Starter Skeleton (USE):**

```python
# ioc_pipeline.py - Exit 0 classified, 1 review needed, 2 transport/auth failure
import datetime as dt
import ipaddress
import json
import re
import sys

import stix2

DEFANG_MAP = (("hxxps", "https"), ("hxxp", "http"), ("[.]", "."), ("[:]", ":"), ("[at]", "@"))
OWN_DOMAINS = {"example.com", "example.internal"}
SHARED_RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24",)]
RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}
CONFIDENCE_FLOOR = 40
MAX_AGE_DAYS = 90

def refang(value: str) -> str:
    out = value
    for bad, good in DEFANG_MAP:
        out = out.replace(bad, good).replace(bad.upper(), good)
    return out

def canonical(value: str, kind: str) -> str:
    if kind == "ipv4-addr" or kind == "ipv6-addr":
        return str(ipaddress.ip_address(value.strip()))
    return value.strip().rstrip(".").lower()

def self_harm(value: str, kind: str) -> str | None:
    if kind in ("ipv4-addr", "ipv6-addr"):
        addr = ipaddress.ip_address(value)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return "non_routable"
        if str(addr) in RESOLVERS:
            return "public_resolver"
        if any(addr in net for net in SHARED_RANGES):
            return "shared_range"
        return None
    if kind == "domain-name":
        if any(value == d or value.endswith("." + d) for d in OWN_DOMAINS):
            return "own_domain"
        if value in {"localhost"}:
            return "local_host"
    return None

def decay_confidence(base: int, created: dt.datetime, now: dt.datetime) -> int:
    age = max(0, (now - created).days)
    if age >= MAX_AGE_DAYS:
        return 0
    return int(base * (1 - age / MAX_AGE_DAYS))

def classify(raw_pattern: str, created: dt.datetime, now: dt.datetime) -> dict:
    m = re.match(r"^\[([a-z0-9-]+):[a-z0-9._]+ = '([^']+)'\]$", raw_pattern.strip())
    if not m:
        return {"outcome": "reject", "reason": "unparseable_pattern", "pattern": raw_pattern[:80]}
    kind, raw_value = m.group(1), m.group(2)
    value = canonical(refang(raw_value), kind)
    reason = self_harm(value, kind)
    if reason:
        return {"outcome": "drop", "reason": reason, "value": value, "type": kind}
    confidence = decay_confidence(80, created, now)
    if confidence < CONFIDENCE_FLOOR:
        return {"outcome": "drop", "reason": "confidence_below_floor", "value": value, "confidence": confidence}
    return {"outcome": "enforce", "value": value, "type": kind, "confidence": confidence}

def main(bundle_path: str) -> int:
    now = dt.datetime.now(dt.timezone.utc)
    try:
        with open(bundle_path, encoding="utf-8") as fh:
            bundle = stix2.parse(fh.read(), allow_custom=True)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"fatal: {exc}\n")
        return 2
    review = 0
    for obj in bundle.get("objects", []):
        if getattr(obj, "type", "") != "indicator":
            continue
        if getattr(obj, "pattern_type", "") != "stix":
            review += 1
            print(json.dumps({"outcome": "review", "reason": "unsupported_pattern_type",
                              "id": obj.get("id", "")}))
            continue
        created = obj.get("created", now)
        if isinstance(created, str):
            created = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
        print(json.dumps({"id": obj.get("id", ""), **classify(obj["pattern"], created, now)}))
    return 1 if review else 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("usage: ioc_pipeline.py <bundle.json>\n")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
```

**Why this matters:** refanging happens before canonicalization so the value matches live telemetry, the self-harm filters run before any enforcement decision, and confidence is decayed from the indicator's own creation time — so an old or internal indicator cannot reach a blocklist.

## When It Is NOT This Issue

- **An indicator from a feed never matches your logs** — it is probably still defanged in the feed; refang before comparing, and confirm canonicalization (case, trailing dot) on both sides.
- **Internal traffic broke after a blocklist update** — a private or own-domain indicator reached enforcement; that is the self-harm filter failing, not the feed being malicious.
- **A blocked domain resolves into a CDN range** — shared infrastructure means blocking it blocks unrelated services; exclude shared ranges and prefer domain-level indicators with a manual review path.
- **Confidence is high but the indicator is a year old** — static confidence values overstate old data; apply age decay before comparing against an enforcement threshold.
- **A TAXII collection returns objects but PyMISP rejects them** — MISP attribute types and distribution settings differ from STIX types; the mapping is explicit work, not a pass-through.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER push an indicator to an enforcement point without passing the non-routable, own-domain, resolver, and shared-range filters.
- NEVER treat a defanged value as equivalent to its refanged form without normalizing both.
- NEVER assert a MISP attribute type or TAXII object shape from memory; confirm against the installed client version and the server's schema.
- NEVER publish an indicator without `valid_from`/`valid_until` and a decaying confidence.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Feed sources, transport, enforcement points, and own-asset inventory for `stix-taxii-and-misp-ioc-pipeline-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The filter, decay function, or sweeper is specific and runnable (no generic 'validate feed data' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: stix-taxii-and-misp-ioc-pipeline-scripting
- **Target Stack & Schema**: stix2 (STIX 2.1), taxii2client.v21, PyMISP 2.5+ with local allowlist and confidence decay
- **Safety, Scope & Exit-Code Guards**: [Self-harm filters before enforcement, validity windows, decaying confidence, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Defanged input, shared CDN ranges, own domains, stale indicators]
- **Implementation**:
  [Runnable pipeline following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile ioc_pipeline.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`soar-playbook-and-webhook-connector-development`](../soar-playbook-and-webhook-connector-development/SKILL.md) - Consumes these indicators for automated block/contain actions
- [`siem-query-transpiler-and-enrichment-scripting`](../siem-query-transpiler-and-enrichment-scripting/SKILL.md) - Enriches alerts with indicator context
- [`phishing-email-and-header-triage-automation`](../phishing-email-and-header-triage-automation/SKILL.md) - Produces extracted observables that feed this pipeline
- [`pcap-and-netflow-beacon-analysis-scripting`](../pcap-and-netflow-beacon-analysis-scripting/SKILL.md) - Confirms network indicators against captured traffic

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `stix-taxii-and-misp-ioc-pipeline-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
