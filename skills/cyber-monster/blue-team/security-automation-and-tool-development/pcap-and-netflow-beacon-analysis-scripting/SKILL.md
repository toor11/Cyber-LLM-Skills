---
name: pcap-and-netflow-beacon-analysis-scripting
description: "Engineers streaming PCAP and NetFlow analyzers in Python (`dpkt`, `scapy.PcapReader`, or `tshark -T ek`): calculating inter-arrival delta periodicity/jitter CV (coefficient of variation) for C2 beacon hunting, Shannon entropy + NXDOMAIN ratios for DNS tunneling/DGA, and TLS SNI/JA3 profiling without loading multi-GB PCAPs into RAM. Use when scripting network forensics."
family: security-automation-and-tool-development
tier: core
triggers: ["pcap analysis script", "dpkt streaming", "beacon jitter python", "dns entropy script", "pcapreader"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# PCAP and NetFlow Beacon Analysis Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Beacon hunting is a statistical argument about timing regularity, and its power comes from how weak that argument is for individual packets and how strong it is in aggregate. A C2 implant sleeps approximately a fixed interval with optional jitter; a human-driven session does not. So for each `(source, destination, destination port)` tuple you collect the timestamps of connection starts (TCP SYN without ACK), compute the inter-arrival deltas, and measure dispersion — the coefficient of variation (standard deviation over mean) is the standard statistic because it is scale-free: a 60-second beacon with 10% jitter and a 600-second beacon with 10% jitter both score 0.1. That scale-freedom is also the trap: low CV alone flags anything periodic, including software update checks, NTP, and health probes, so CV must be combined with a minimum sample count, a plausible interval band, and context (destination reputation, JA3/JA4 consistency, payload size uniformity). The DNS side is analogous: DNS tunneling and DGA traffic produce anomalous label-length distributions and high query entropy per parent domain, and NXDOMAIN ratios distinguish a DGA from a legitimately busy resolver. All of it must stream: a 20 GB PCAP cannot be read into memory, so `dpkt.pcap.Reader` (fast) or `scapy.PcapReader` (feature-rich but slower) are the only viable readers, and `rdpcap` is never acceptable.

- **CWE-778 (Insufficient Logging):** an analyzer that samples only the first N packets, or drops flows when its table grows, reports a periodicity verdict on a fraction of the evidence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the capture is large **THEN** stream with `dpkt.pcap.Reader` and aggregate per flow; never `rdpcap`, and never accumulate raw packet objects.
2. **IF** you measure beaconing **THEN** require a minimum connection count, compute mean interval and standard deviation, and rank by coefficient of variation within a plausible interval band (not CV alone).
3. **IF** you measure DNS tunneling **THEN** compute per-parent-domain query volume, label-length distribution, and the NXDOMAIN ratio; a high-entropy long-label pattern with a high NXDOMAIN ratio is the signal.
4. **IF** you inspect TLS **THEN** extract SNI from the ClientHello and build a JA3/JA4-style fingerprint per destination; consistency across beacons is corroboration, not proof.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `pcap-and-netflow-beacon-analysis-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable analyzer shapes | [`QUERIES.md`](QUERIES.md) | Streaming SYN collection, CV ranking, DNS entropy, SNI extraction |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `dpkt`, `scapy`, `tshark -T ek` invocations |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | False-positive periodicity and memory-blowup incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Network-scope handoff for a suspected beacon |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11 streaming analyzers over `dpkt.pcap.Reader` (primary) or `scapy.PcapReader` (when richer decoding is needed), with `statistics` for interval dispersion and `math` for Shannon entropy
- **Mandatory Self-Validation Command:** `python -m py_compile beacon_analyze.py`

1. **Confirm the inputs.** Establish the capture size and link type, the capture window (a short window cannot distinguish a 10-minute beacon from a periodic job), whether the capture is inbound/outbound/both, and the known-good periodic traffic in the environment (patch, NTP, monitoring). Confirm the flow key granularity to aggregate on.
2. **Choose the branch.** Timing analysis → SYN-based connection starts per flow. Volume analysis → bytes/packets per flow over time. DNS analysis → query name features per parent domain. TLS analysis → SNI plus fingerprint per destination. Each branch answers a different question; running all four and reporting one score obscures which evidence drove the verdict.
3. **Define how to validate the analyzer.** Feed a synthetic capture with a known 60-second beacon (CV near 0) and one with random intervals (CV near 1), plus a capture with a known periodic-but-benign NTP client, and assert the ranking separates them. Assert peak memory stays bounded on a large capture.
4. **Name the stop condition.** Stop when a flow has fewer connections than the minimum sample, when the capture window is shorter than a few multiples of the candidate interval, when the flow table exceeds its bound (a truncated table is not a complete analysis), or when the only supporting evidence is CV with no corroborating signal.
5. **State what counts as a working tool.** A working analyzer exits `0` when it processed the whole capture and produced ranked candidates with their statistics, `1` when candidates exceed the reporting threshold (if used as a detector), and `2` on an unreadable or truncated capture. Every candidate row carries count, mean, standard deviation, CV, and the corroborating evidence used.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| TCP SYN-only timestamps per `(src, dst, dport)` | Proves connection starts are counted once per attempt, not per packet |
| Coefficient of variation with sample count and mean interval | Proves the regularity claim is quantitative and scale-free |
| DNS label-length distribution plus NXDOMAIN ratio per parent domain | Proves tunneling or DGA patterns rather than merely odd names |
| JA3/JA4-style fingerprint consistency per destination | Proves the same client stack recurs, corroborating automation |
| Bounded flow-table size with an eviction counter | Proves the analysis covered the capture rather than a truncated prefix |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: loads the whole capture into memory, counts every packet instead of
# connection starts, and flags on a hardcoded delta threshold with no sample floor.
from scapy.all import rdpcap, IP, TCP

def beacons(path):
    packets = rdpcap(path)                       # whole capture in RAM
    last = {}
    hits = []
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
            if key in last and (pkt.time - last[key]) < 5:
                hits.append(key)
            last[key] = pkt.time
    return set(hits)
```

**Production-Grade Starter Skeleton (USE):**

```python
# beacon_analyze.py - Stream a PCAP and rank flows by inter-arrival regularity.
# Exit 0 analysis complete, 1 candidates above threshold, 2 unreadable capture.
import collections
import math
import statistics
import sys

import dpkt

MIN_CONNECTIONS = 12
MIN_INTERVAL_S = 5.0
MAX_INTERVAL_S = 86_400.0
MAX_FLOWS = 200_000
CV_THRESHOLD = 0.15

def collect_connection_starts(path: str) -> tuple[dict, int]:
    flows: dict[tuple, list[float]] = collections.defaultdict(list)
    evicted = 0
    with open(path, "rb") as fh:
        try:
            reader = dpkt.pcap.Reader(fh)
        except ValueError:
            reader = dpkt.pcapng.Reader(fh)
        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.UnpackError, ValueError):
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if not (tcp.flags & dpkt.tcp.TH_SYN) or (tcp.flags & dpkt.tcp.TH_ACK):
                continue
            key = (".".join(map(str, ip.src)), ".".join(map(str, ip.dst)), tcp.dport)
            if key not in flows and len(flows) >= MAX_FLOWS:
                flows.pop(next(iter(flows)))
                evicted += 1
            flows[key].append(ts)
    return flows, evicted

def score(flows: dict) -> list[dict]:
    rows = []
    for (src, dst, dport), stamps in flows.items():
        if len(stamps) < MIN_CONNECTIONS:
            continue
        deltas = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
        if len(deltas) < MIN_CONNECTIONS - 1:
            continue
        mean = statistics.fmean(deltas)
        if not (MIN_INTERVAL_S <= mean <= MAX_INTERVAL_S):
            continue
        stdev = statistics.stdev(deltas)
        cv = stdev / mean if mean else float("inf")
        rows.append({
            "src": src, "dst": dst, "dport": dport,
            "connections": len(stamps), "mean_interval_s": round(mean, 3),
            "stdev_s": round(stdev, 3), "cv": round(cv, 4),
        })
    return sorted(rows, key=lambda r: r["cv"])

def main(path: str) -> int:
    try:
        flows, evicted = collect_connection_starts(path)
    except OSError as exc:
        sys.stderr.write(f"fatal: {exc}\n")
        return 2
    ranked = score(flows)
    for row in ranked[:200]:
        print(row)
    if evicted:
        sys.stderr.write(f"warning: {evicted} flows evicted; analysis is partial\n")
        return 1
    return 1 if any(r["cv"] <= CV_THRESHOLD for r in ranked) else 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: beacon_analyze.py <capture.pcap>\n")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
```

**Why this matters:** only connection starts are counted, the flow table is bounded with an eviction counter so truncation is visible, and the ranking reports the statistics behind each candidate instead of a bare hit list — so an analyst can tell a 60-second beacon from an NTP client by reading the row.

## When It Is NOT This Issue

- **A flow scores near-zero CV and is benign** — patch checks, NTP, and monitoring agents are genuinely periodic; corroborate with destination reputation, JA3 consistency, and payload size before calling it C2.
- **The capture window is short relative to the interval** — five minutes of capture cannot establish a ten-minute period; a low candidate count is the tell.
- **Memory grows while reading a large PCAP** — the reader is accumulating packets (`rdpcap`, or a list of parsed packets); stream and aggregate instead.
- **Every DNS name looks high-entropy** — CDN and telemetry domains use random-looking labels legitimately; the NXDOMAIN ratio and per-parent query volume separate DGA from normal CDN use.
- **TCP retransmissions inflate the connection count** — count only SYN without ACK, and consider deduplicating by `(src, dst, sport, dport)` within a short window.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER present a coefficient of variation alone as proof of command-and-control; it is a ranking signal that requires corroboration.
- NEVER use `rdpcap` on a production-sized capture.
- NEVER claim a beacon interval from a capture window shorter than several intervals.
- NEVER assert a specific JA3/JA4 field layout without checking the producing tool's version.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Capture size, link type, window, and known benign periodic traffic for `pcap-and-netflow-beacon-analysis-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The analyzer or statistic is specific and runnable (no generic 'look for beacons' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: pcap-and-netflow-beacon-analysis-scripting
- **Target Stack & Schema**: Python 3.11 streaming dpkt/scapy readers with bounded flow tables and CV-based ranking
- **Safety, Scope & Exit-Code Guards**: [Streaming only, bounded flow table, minimum sample floor, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Benign periodic jobs, short capture windows, retransmissions, CDN label entropy]
- **Implementation**:
  [Runnable analyzer following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile beacon_analyze.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`zeek-script-and-notice-development`](../zeek-script-and-notice-development/SKILL.md) - Online periodicity detection via SumStats on live traffic
- [`suricata-lua-and-rule-qa-tooling`](../suricata-lua-and-rule-qa-tooling/SKILL.md) - IDS rules over the same captures
- [`stix-taxii-and-misp-ioc-pipeline-scripting`](../stix-taxii-and-misp-ioc-pipeline-scripting/SKILL.md) - Publishes confirmed network observables
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - Inspects payloads carved from the same traffic

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `pcap-and-netflow-beacon-analysis-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
