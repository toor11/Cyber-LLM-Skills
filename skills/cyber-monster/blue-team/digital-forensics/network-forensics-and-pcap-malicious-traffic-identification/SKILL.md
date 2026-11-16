---
name: network-forensics-and-pcap-malicious-traffic-identification
description: Malicious traffic identification. Covers spotting C2, exfiltration and scanning patterns in capture data using behavioural and signature signals. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: digital-forensics
tier: leaf
triggers: ["malicious traffic analysis", "c2 in pcap", "exfil detection pcap"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [network-forensics-and-pcap, network-forensics-and-pcap-protocol-reconstruction, disk-forensics-and-artifacts, windows-artifact-forensics]
parent: network-forensics-and-pcap
---

# Network Forensics and PCAP Malicious Traffic Identification - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Malicious traffic is recognised by shape, not by content, because the content is usually encrypted and the shape is not. Three shapes carry most of the signal. Periodic beaconing produces connections whose inter-arrival deltas cluster tightly around a value that has nothing to do with the payload — the client sleeps, wakes, connects, and sleeps again, so the distribution of deltas is narrow and the same value survives across days while the destination rotates. Exfiltration produces an outbound byte ratio that is inconsistent with the protocol: a TLS session to an unclassified host carrying far more client-to-server bytes than server-to-client is the inverse of how web browsing, updates and streaming all behave. Scanning produces connection attempts that never complete, or complete and immediately close with no application data, across many destinations or ports from one source. On top of shape sit fingerprints: the TLS ClientHello exposes cipher suites, extensions, elliptic curves and ALPN before any key is negotiated, and hashing those fields gives JA3 (MD5 over the field list in wire order) or JA4 (a structured `a_b_c` form with sorted cipher and extension hashes, which survives extension reordering that breaks JA3). What none of these can tell you: a beacon interval proves a machine cadence, not a malicious one, because every agent, updater and health check has one; a JA3 match proves the peer's TLS stack resembles a known tool, and the same stack is used by legitimate software built on the same library; and a JA4 fingerprint can be reproduced deliberately by a client that copies a browser's ClientHello. Encrypted Client Hello removes the SNI from the observable handshake entirely.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `network-forensics-and-pcap-malicious-traffic-identification` **THEN** start at parent class [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) first.
2. **IF** the traffic is encrypted **THEN** take the fingerprint-and-shape branch and restrict claims to handshake fields, byte ratios and cadence; **IF** it is clear text **THEN** delegate payload reconstruction to [`network-forensics-and-pcap-protocol-reconstruction`](../network-forensics-and-pcap-protocol-reconstruction/SKILL.md) instead of duplicating it here.
3. **IF** you are evaluating a candidate beacon **THEN** require the interval to hold across at least three separate sessions and to be inconsistent with the host's other periodic traffic; a single interval is a coincidence with good marketing.
4. **IF** the destination is a major CDN, cloud region or SaaS edge **THEN** treat the fingerprint as weak evidence, because shared infrastructure serves both benign and hostile tenants from the same address space.
5. **IF** the capture is inbound-only or egress-only at the sensor **THEN** state that the byte ratio cannot be computed and drop every asymmetry claim from the report.
6. **IF** telemetry source covering `beacon pattern` or `exfil volume` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `network-forensics-and-pcap-malicious-traffic-identification` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need to prove what content actually moved | [`network-forensics-and-pcap-protocol-reconstruction`](../network-forensics-and-pcap-protocol-reconstruction/SKILL.md) | Object export and completeness accounting |

## Procedure

1. **Confirm the capture can support a shape claim at all.** Read `capinfos` for duration and snaplen, confirm the sensor sees both directions of the flows you intend to score, and confirm the capture covers enough time for cadence analysis — a five-minute capture cannot distinguish a 60-second beacon from a busy client. A one-directional, short, or truncated capture makes every ratio and every interval meaningless.
2. **Choose the branch from what the transport exposes.** Encrypted flows take the fingerprint branch (JA4 for stability, JA3 only to match public feeds) plus the cadence branch. Clear-text flows take the content branch and belong to the reconstruction skill. Mixed estates take the per-flow branch: classify each flow, then compare the shape distributions rather than eyeballing individual flows.
3. **Build the differential against the host's own fleet, not a global threshold.** For each candidate host, compute its interval distribution and its outbound-to-inbound ratio, then compare against the same statistics for hosts in the same role and against a quiet-day capture. The finding is a host whose shape is distinct from its peers and stable across days, not a host whose absolute beacon count is highest.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the capture is one-directional (no ratio computable), when the window is shorter than three beacon intervals, when the destination is shared CDN infrastructure that also serves the baseline population, or when Encrypted Client Hello removes the SNI and the destination cannot be attributed.
5. **State what counts as proof.** Proof requires three independent agreements: a stable interval across at least three sessions, a byte-ratio or payload shape inconsistent with the protocol the port implies, and a second artefact from outside the capture — an endpoint process event, a DNS resolution record, or a proxy log naming the same client to the same destination inside the stated tolerance. Two of the three is a strong lead that must be labelled as such.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Inter-arrival deltas clustered within a few percent of one value across three or more sessions to a rotating destination set | TCP/UDP connection timing | Proves a machine-scheduled client at the observation point on any OS; the rotation plus the narrowness, not the period alone, is what separates it from a fixed agent heartbeat |
| Client-to-server bytes exceeding server-to-client by a wide margin on a TLS session to an unclassified host | Directional byte ratio | Proves the client pushed more than it pulled, which is the inverse of browsing, streaming and update behaviour — a shape claim, not a content claim |
| Repeated SYN to many ports or hosts with no completed handshake, from a source absent from the scanner inventory | Half-open connection pattern | Proves reconnaissance-shaped traffic at the observation point; the inventory check is what turns it into a finding |
| JA4 fingerprint matching a published malicious family, on a host whose other TLS fingerprints are all browser-like | TLS ClientHello structure | Proves the TLS stack resembles that family's stack; on shared infrastructure this is corroboration only, never the primary proof |
| ClientHello that omits SNI while claiming a browser user agent over the same session | Handshake-versus-claim divergence | Proves the client is not the browser it claims to be; some legitimate privacy tooling does this, so pair it with the destination classification |
| Long-lived session with fixed-size request frames and fixed-size responses at irregular but bounded intervals | Frame-size regularity | Proves a framed application protocol running over an opaque port, which is how a custom C2 channel looks when it avoids both HTTP and DNS |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: one period, one threshold, one verdict.
tshark -r incident.pcap -Y "ip.dst==203.0.113.9" -T fields -e frame.time_epoch |
  awk 'NR>1{d=$1-p; if(d>55&&d<65) c++} {p=$1} END{print c" beacons"}'
# 60-second filter with a +/-5s window, no fleet comparison, no session grouping,
# no check that the destination is shared CDN space, and no second artefact.
# This finds the NTP client, the licensing check and the EDR heartbeat, then stops.
```

**High-Signal Grounded Artifact:**

```python
#!/usr/bin/env python3
"""beacon_shape.py — per-host cadence and ratio profile, compared to fleet peers."""
import json, statistics, subprocess, sys
from collections import defaultdict

CAP = sys.argv[1] if len(sys.argv) > 1 else "incident.pcap"

def flows():
    out = subprocess.run(["tshark", "-r", CAP, "-T", "json", "-e", "frame.time_epoch",
                          "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.stream",
                          "-e", "tcp.len"], capture_output=True, text=True, check=True)
    for rec in json.loads(out.stdout or "[]"):
        layers = rec["_source"]["layers"]
        try:
            yield (float(layers["frame.time_epoch"][0]), layers["ip.src"][0],
                   layers["ip.dst"][0], layers.get("tcp.stream", ["-"])[0])
        except (KeyError, IndexError):
            continue

sessions = defaultdict(list)
for ts, src, dst, stream in flows():
    sessions[(src, dst)].append((ts, stream))

profile = {}
for (src, dst), rows in sessions.items():
    stamps = sorted(ts for ts, _ in rows)
    streams = sorted({s for _, s in rows})
    if len(streams) < 3:
        continue                      # fewer than three sessions cannot show cadence
    deltas = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
    if len(deltas) < 2:
        continue
    cv = statistics.pstdev(deltas) / statistics.mean(deltas) if statistics.mean(deltas) else 9
    profile[(src, dst)] = (round(statistics.mean(deltas), 1), round(cv, 4), len(streams))

# Fleet-relative: only pairs whose interval is stable AND unlike their peers survive.
for (src, dst), (mean_d, cv, n) in sorted(profile.items(), key=lambda kv: kv[1][1]):
    peers = [v[1] for k, v in profile.items() if k[0] == src and k != (src, dst)]
    fleet_cv = statistics.median(peers) if peers else None
    print(f"{src:>15} -> {dst:<16} interval={mean_d:>7}s cv={cv:<7} sessions={n:<3} "
          f"peer_cv_median={fleet_cv}")
```

**Why this matters:** the weak form searches for the number it already suspects, so it finds whatever else happens to use 60 seconds and stops there. The strong form requires at least three sessions before a pair is scored at all, measures dispersion rather than a threshold window, and prints each candidate beside the median dispersion of the same host's other destinations — so a host that is uniformly periodic across everything is visibly a normal agent, and a host with one tightly-clustered outlier is the only thing left on the page.

## When It Is NOT This Issue

- **Agent, updater and health-check heartbeats:** these are machine-periodic by design and will always dominate a cadence ranking. The distinguishing features are a stable destination set, a stable fingerprint shared with other hosts in the fleet, and a short session with tiny payloads — none of which rotate.
- **Shared CDN and cloud address space:** JA3/JA4 matches and destination reputation are weak when the address serves thousands of tenants. A fingerprint match on a CDN edge is corroboration; treating it as the primary finding produces both false positives and false negatives at the same address.
- **Load-balancer and NAT aggregation in the capture:** one observed source address may be hundreds of clients, which flattens every cadence measurement into noise or fabricates a perfect interval. Confirm whether the sensor sees pre- or post-NAT addresses before computing any interval.
- **Vulnerability scanners with a narrow port profile:** an authenticated scan of a small port set from an inventory host looks exactly like focused reconnaissance. Check the scanner schedule and source inventory first; the shape alone cannot separate them.
- **QUIC and HTTP/2 traffic that defeats flow heuristics:** these protocols multiplex streams over one connection, so per-stream timing and per-request byte ratios computed at the TCP layer are artefacts of multiplexing rather than client behaviour.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `beacon pattern` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Bidirectionality confirmed:** the capture sees both directions for every flow scored, and no byte-ratio claim is made from a one-directional capture.
- [ ] **Cadence sample size met:** every candidate interval is derived from at least three sessions, and the dispersion is reported beside the mean.
- [ ] **Fleet comparison run:** each candidate is printed against the median dispersion of the same host's other destinations and against peer hosts in the same role.
- [ ] **Fingerprint scope stated:** any JA3 or JA4 match is labelled corroboration or primary evidence, with the destination's shared-infrastructure status named.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: network-forensics-and-pcap-malicious-traffic-identification
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) - Digital Forensics (core)
- [`network-forensics-and-pcap-protocol-reconstruction`](../network-forensics-and-pcap-protocol-reconstruction/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Shape before fingerprint:** a fingerprint names a software stack and can be copied; a cadence confined to one destination on one host is much harder to fake accidentally. Lead with shape and use fingerprints as corroboration.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; never block an address range based on a fingerprint match alone, because shared infrastructure will take unrelated services with it.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (2), CYBER_CPT/secwiki (2), CYBER_CPT/xz_aliyun (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
