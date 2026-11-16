---
name: network-forensics-and-pcap
description: "Analyses network traffic: pcap triage, protocol reconstruction, extracting transferred files and identifying malicious flows. Use when packet capture or flow data is available."
family: digital-forensics
tier: core
triggers: ["network forensics", "pcap analysis", "packet capture forensics", "flow analysis"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [network-forensics-and-pcap-protocol-reconstruction, network-forensics-and-pcap-malicious-traffic-identification, disk-forensics-and-artifacts, windows-artifact-forensics]
---

# Network Forensics and PCAP - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

A capture file is a sequence of link-layer frames, each stamped by the capturing host's clock and truncated to a snap length chosen at capture time. That single sentence governs everything downstream. The link type determines whether you are reading Ethernet, raw IP, Linux cooked capture or 802.11 radiotap, and a capture read under the wrong link type decodes into convincing nonsense rather than an error. The snap length (`-s`) determines how many bytes of each frame survived; a 96-byte snaplen leaves you the headers of every packet and none of the payload, so `--export-objects` returns zero files while the transfer is plainly visible in the conversation statistics. The timestamp is the *capturing sensor's* clock, not the endpoint's, and in a SPAN or TAP deployment it is also the point of observation, which is upstream or downstream of any NAT, proxy or load balancer between the sensor and the host. Packet loss at the sensor is invisible in the file: a capture with a full ring buffer silently drops frames, and a retransmission-heavy stream looks identical whether the cause was loss on the wire or loss at the capture point. Flow records (NetFlow, IPFIX, Zeek `conn.log`) are a different artefact class entirely — they retain who talked to whom, how much, and for how long, but never payload, and their exporter sampling rate changes every volume figure by that factor. What a pcap cannot tell you: which process on the endpoint opened the connection, whether the user intended it, or what happened in traffic that never crossed the observation point.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves `protocol-reconstruction` **THEN** switch to [`network-forensics-and-pcap-protocol-reconstruction`](../network-forensics-and-pcap-protocol-reconstruction/SKILL.md) (1 hop).
2. **IF** the target specifically involves `malicious-traffic-identification` **THEN** switch to [`network-forensics-and-pcap-malicious-traffic-identification`](../network-forensics-and-pcap-malicious-traffic-identification/SKILL.md) (1 hop).
3. **IF** you have a capture file **THEN** run `capinfos` first and read link type, snaplen, packet count and duration before any display filter; **IF** the capture is live **THEN** set a ring buffer with a documented snaplen instead of capturing to a single file.
4. **IF** you have only flow records and no packets **THEN** take the flow-only branch and restrict conclusions to volume, timing and endpoints — never claim payload content from a NetFlow record.
5. **IF** the sensor sits behind NAT, a proxy, or a load balancer **THEN** record the observation point and treat every address as an observation-point address, not an endpoint identity.
6. **IF** telemetry source covering `tshark` or `Wireshark` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `network-forensics-and-pcap` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `network-forensics-and-pcap-protocol-reconstruction` | [`network-forensics-and-pcap-protocol-reconstruction`](../network-forensics-and-pcap-protocol-reconstruction/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `network-forensics-and-pcap-malicious-traffic-identification` | [`network-forensics-and-pcap-malicious-traffic-identification`](../network-forensics-and-pcap-malicious-traffic-identification/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the capture's own provenance before reading a single packet.** `capinfos` reports file type, encapsulation, snap length, packet count, first and last timestamp, and whether the file was truncated at the end. Record the sensor, its position relative to NAT and proxies, and its drop counters for the capture window. A capture whose snaplen is short or whose drops are non-zero cannot support a "no such traffic occurred" statement, only a "no such traffic was observed at this point" one.
2. **Choose the branch by what survived capture.** Full-payload captures take the packet branch (`tshark` display filters, stream reassembly, object export). Header-only captures take the metadata branch (conversations, protocol hierarchy, TLS handshake fields, DNS names). Flow-only data takes the flow branch (volume, cadence, endpoint pairs). State which branch in the output, because the branch determines which claims are even possible.
3. **Establish the differential across a matched comparison, not a threshold.** Compare the incident capture against a capture of the same sensor, same time of day, same client population on a quiet day. The finding is the endpoint pair, protocol or byte ratio that changed — not the largest conversation in one file, which is almost always a backup or an update feed.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the capture has non-zero kernel drops across the relevant window, when the snaplen precludes payload claims, when the timestamps have no verified timezone or clock discipline, or when the observed flow disappears behind a TLS or QUIC session whose keys are unavailable. Do not present a truncated capture as complete coverage.
5. **State what counts as proof.** Proof is two artefacts describing the same transfer from different observation points and agreeing on the byte count within the retransmission and header overhead you can account for: the pcap conversation bytes and a proxy, firewall or Zeek log entry for the same endpoint pair inside the same UTC minute, with the difference explained rather than ignored.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `capinfos` snaplen of 96 bytes with a populated HTTP conversation | Capture metadata versus conversation statistics | Proves headers were retained and payload was not, on any OS; object export will return nothing and that emptiness is a capture property, not an absence of files |
| Non-zero drop counter reported by `tshark -q -z io,stat` gaps or the sensor's own stats | Capture-plane loss | Proves the file under-represents the wire for that window; every rate and volume derived from it is a floor, never a total |
| Conversation where one direction carries 20 KB and the reverse carries 4 MB | Byte-asymmetry class | Proves data moved predominantly inbound on that pair; combined with an unauthenticated protocol it locates staging, but it does not prove the file was written to disk |
| Single SYN with no completing handshake repeated at fixed intervals to many ports | Half-open connection pattern | Proves a scan reached the observation point; proves nothing about whether the target host answered, since the reply may not cross the same sensor |
| `frame.time_epoch` sequence whose inter-arrival deltas are quantised to a fixed value independent of payload | Timing class | Proves a machine-generated cadence at the observation point; the fixed value is a property of the client's sleep timer, not of the server |
| Two captures of the same session from different sensors with different byte totals | Multi-point divergence | Proves at least one point lost frames or saw a different path; the delta localises where the loss or the asymmetry occurred |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: open the biggest file, sort by bytes, call the top talker malicious.
tshark -r incident.pcap -q -z conv,tcp | sort -k3 -n -r | head -5
# No capinfos, no snaplen check, no drop count, no baseline capture.
# Result: the backup server, the OS update CDN and the video call are the "top three
# threats", and a 96-byte-snaplen capture is reported as containing no file transfers.
```

**High-Signal Grounded Artifact:**

```bash
#!/usr/bin/env bash
# pcap-differential.sh — prove the capture can answer the question, then diff it.
set -euo pipefail
CAP="${1:?usage: $0 incident.pcap baseline.pcap}"

capinfos -M "$CAP" | grep -Ei "encapsulation|snapshot|packet count|capture duration|time precision"
tshark -r "$CAP" -q -z io,phs | sed -n '1,40p'          # what protocols exist at all

# Endpoint-pair volume, both directions, keyed consistently.
tshark -r "$CAP" -q -z conv,tcp |
  awk 'NF>4 && $1 ~ /[0-9]+$/ {print $1" <-> "$3, $4}' | sort -k2 -n -r > conv_incident.txt

tshark -r "${2:?baseline capture required}" -q -z conv,tcp |
  awk 'NF>4 && $1 ~ /[0-9]+$/ {print $1" <-> "$3, $4}' | sort -k2 -n -r > conv_baseline.txt

# The finding is the pair whose rank moved, not the pair at the top of one file.
join -j1 <(awk '{print $1, $2}' conv_baseline.txt | sort) \
         <(awk '{print $1, $2}' conv_incident.txt | sort) |
  awk '$2>0 {printf "%s baseline=%d incident=%d ratio=%.1f\n", $1, $2, $3, $3/$2}' |
  sort -k4 -n -r | head -20
```

**Why this matters:** the strong form refuses to rank a single file, because rank inside one capture reflects the client population rather than hostility. It checks encapsulation and snapshot length to bound which claims are permissible, and it reports a rank and volume shift against a matched baseline so that a permanently busy backup path stays at the top of both lists and cancels out.

## When It Is NOT This Issue

- **The top talker in a single capture:** backup windows, patch distribution, video conferencing and CDN-served application updates all dominate byte rankings. Without a baseline from the same sensor and hour, a high-volume conversation is the expected shape of a normal network, not a finding.
- **A capture with a short snaplen or a full ring buffer:** an empty object-export directory and a low packet count are capture-plane properties. Treating them as endpoint evidence produces a false negative that cannot be distinguished from a clean host later.
- **Half-open connections from a monitoring system:** availability checkers, inventory scanners and load-balancer health probes generate exactly the SYN-without-completion pattern a scan produces. Confirm the source address against the scanner inventory before calling it reconnaissance.
- **Fixed-interval traffic to a single endpoint:** NTP, licensing heartbeats, telemetry agents and EDR check-ins are all machine-cadence by design. The cadence is a lead; the destination reputation and the TLS fingerprint are what separate a heartbeat from a beacon.
- **Byte asymmetry on its own:** a large inbound transfer is how every software update and every streaming session looks. Asymmetry only becomes evidence when paired with an unauthenticated protocol, an unusual destination, or a host that should not be receiving that volume.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `tshark` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Encapsulation and snaplen read:** `capinfos` output is quoted in the report, and every payload claim is checked against the snap length that actually survived.
- [ ] **Observation point documented:** the sensor's position relative to NAT, proxy and load balancer is stated, and addresses are labelled as observation-point addresses.
- [ ] **Loss bounded:** capture-plane drops for the window are recorded, and volumes are presented as floors wherever drops are non-zero.
- [ ] **Baseline matched:** the comparison capture comes from the same sensor, hour and client population, and the finding is a rank or ratio shift rather than an absolute maximum.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: network-forensics-and-pcap
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`network-forensics-and-pcap-protocol-reconstruction`](../network-forensics-and-pcap-protocol-reconstruction/SKILL.md) - Digital Forensics (leaf)
- [`network-forensics-and-pcap-malicious-traffic-identification`](../network-forensics-and-pcap-malicious-traffic-identification/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Capture metadata before content:** the largest single source of wrong pcap conclusions is answering a payload question from a header-only capture. Read `capinfos` first and let it constrain the claims.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; capture files may contain personal data and credentials, so handle, store and share them under the case's evidence handling rules.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 34 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/netresec (12), CYBER_CPT/blackhills (12), Forensic_Toolkit_Dataset (4), OffsecCyber (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 4 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
