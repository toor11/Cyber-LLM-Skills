---
name: network-forensics-and-pcap-protocol-reconstruction
description: Protocol reconstruction from capture. Covers reconstructing HTTP, SMB, DNS and mail sessions to establish what data moved and to whom. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: digital-forensics
tier: leaf
triggers: ["pcap protocol reconstruction", "http reconstruct", "smb session analysis"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [network-forensics-and-pcap, network-forensics-and-pcap-malicious-traffic-identification, disk-forensics-and-artifacts, windows-artifact-forensics]
parent: network-forensics-and-pcap
---

# Network Forensics and PCAP Protocol Reconstruction - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Reconstruction is the process of turning a frame stream back into the byte stream the application saw. TCP does not deliver a message; it delivers an ordered byte sequence per direction per connection, and the dissector rebuilds the application message by concatenating segment payloads in sequence-number order. Everything that makes reconstruction hard follows from that. Out-of-order arrival and retransmission produce duplicate bytes that must be de-duplicated by sequence number, not by arrival order, or a reassembled file gains a repeated block and stops matching its own hash. A gap where a segment was never captured produces a hole, and the dissector either reports a truncated object or silently reassembles around it depending on its heuristics. For HTTP, the message boundary comes from `Content-Length` or chunked transfer encoding; for SMB the boundary comes from the NBSS length prefix; for SMTP and IMAP the boundary is line-oriented and depends on the terminator; for DNS the message is a single datagram and "reconstruction" really means correlating query and response by transaction ID. What the reassembled stream cannot tell you: whether the peer actually accepted the bytes (a reassembled upload is the client's claim, not the server's acknowledgement of a complete write), whether a proxy rewrote the headers along the path, or what an encrypted session contained. TLS 1.3 hides the application message entirely and QUIC hides even the transport framing, so a reassembly claim on such a session is a claim about the handshake only.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `network-forensics-and-pcap-protocol-reconstruction` **THEN** start at parent class [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) first.
2. **IF** the capture is on a non-standard port **THEN** declare the port-to-protocol mapping with `-d tcp.port==8080,http` before reading payload; **IF** the protocol is dissected only by heuristic **THEN** record that the mapping was inferred, not negotiated.
3. **IF** the session is TLS 1.3 or QUIC **THEN** take the metadata branch and restrict claims to handshake, SNI, certificate and byte volume; do not attempt payload reassembly without keys you legitimately hold.
4. **IF** the capture has gaps or a short snaplen **THEN** switch from stream reassembly to object export with an explicit completeness flag, and mark any exported file as potentially truncated.
5. **IF** the protocol is SMB, HTTP or mail and object export is available **THEN** prefer export over manual reassembly, because the dissector applies length semantics you would otherwise have to re-implement.
6. **IF** telemetry source covering `stream reassembly` or `HTTP export` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `network-forensics-and-pcap-protocol-reconstruction` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need to judge whether the reconstructed session was hostile | [`network-forensics-and-pcap-malicious-traffic-identification`](../network-forensics-and-pcap-malicious-traffic-identification/SKILL.md) | Beacon, exfil and scan shape live there |

## Procedure

1. **Confirm the capture and the dissector's own settings before reconstructing.** Record `capinfos` encapsulation and snaplen, then confirm which port-to-protocol mappings are in force (`-d`) and whether the dissector reached the protocol by negotiation or by heuristic. A stream declared as HTTP because it happened to contain the string `GET` is a guess, and every reassembly built on it inherits the guess.
2. **Choose the branch from the transport's visibility.** Clear-text TCP takes the reassembly branch; datagram protocols take the correlation branch (match request to response by transaction ID); encrypted transports take the metadata branch. Write the branch into the output, because "we reconstructed the session" means three different things in those three cases.
3. **Establish a completeness differential per stream.** For every stream you intend to quote, compare the byte count implied by the application framing (the `Content-Length`, the NBSS prefix, the chunked terminator) against the payload bytes the capture actually contains. The delta is your truncation budget. A stream whose reassembled length falls short of its declared length is a partial object and must be labelled as one.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the declared length exceeds the captured payload by more than the de-duplication tolerance, when the object was exported from a heuristic dissection, when the transport is encrypted and unkeyed, or when the capture's snaplen truncated the payload region while leaving headers intact.
5. **State what counts as proof.** Proof of a completed transfer is the exported object's byte length matching the application-declared length exactly, plus a hash of the export matching the hash of a copy obtained from the receiving endpoint or the proxy log. Two independent reconstructions of the same stream disagreeing on length is proof of a capture defect, not of tampering.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Exported HTTP object whose length equals the `Content-Length` header and whose SHA-256 matches the copy on the receiving host | Application-framed TCP payload | Proves the exact bytes crossed the observation point intact on any OS; the hash equality is what makes it evidence rather than an approximation |
| SMB write where the NBSS-prefixed payload total equals the file size later seen in the share | SMB-over-TCP stream | Proves a file of that size was written through this session on Windows file services; it does not prove the server committed all extents to disk |
| DNS response count for one name within a window exceeding the baseline by an order of magnitude, with long encoded labels | UDP datagram correlation | Proves a high-rate name-resolution pattern at the observation point; the label encoding is what distinguishes tunnelling from a cache-miss storm |
| SMTP session where the DATA terminator is never followed by a `250` acceptance | Line-oriented TCP stream | Proves the client sent a message the server did not accept, which is how failed exfil and rejected phishing attempts look; direction matters here |
| Reassembled stream shorter than its declared `Content-Length` by a fixed block size | Framing-versus-capture delta | Proves capture-plane truncation, not a server-side rejection, because the shortfall is exactly the size of the missing segment |
| Two streams from the same client where one carries a `CONNECT` and the other carries the tunnel contents in clear | Proxy-negotiated versus end-to-end | Proves the proxy was the terminating party on the first leg, which changes every attribution statement about the second leg |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: follow the stream, eyeball it, describe what it "looks like".
tshark -r incident.pcap -qz follow,tcp,ascii,3
# Output is a wall of text with dots where binary was.
# No declared length, no completeness check, no port-to-protocol mapping,
# and the file is described as "an executable was downloaded" from the
# presence of the letters MZ somewhere in the middle of the dump.
```

**High-Signal Grounded Artifact:**

```bash
#!/usr/bin/env bash
# stream-completeness.sh — reassemble, then prove the object is whole before quoting it.
set -euo pipefail
CAP="${1:?usage: $0 capture.pcap}"; STREAM="${2:-0}"
OUT="${3:-./objects}"; mkdir -p "$OUT"

# 1. Declare dissection boundaries rather than inheriting heuristics.
tshark -r "$CAP" -d tcp.port==8080,http -Y "tcp.stream==$STREAM" \
  -T fields -e http.request.full_uri -e http.content_length_header -e tcp.len | head -5

# 2. Exported object from the dissector, which applies the framing semantics.
tshark -r "$CAP" --export-objects "http,$OUT" -q

# 3. Completeness differential: declared length versus captured payload bytes.
DECL=$(tshark -r "$CAP" -d tcp.port==8080,http -Y "tcp.stream==$STREAM && http.content_length_header" \
       -T fields -e http.content_length_header | head -1)
PAYLOAD=$(tshark -r "$CAP" -Y "tcp.stream==$STREAM && tcp.len>0" -T fields -e tcp.len |
          awk '{s+=$1} END {print s+0}')
printf 'declared=%s captured_payload=%s delta=%s\n' "${DECL:-unknown}" "$PAYLOAD" "$((PAYLOAD-${DECL:-0}))"

# 4. Hash the export so the object, not the narrative, carries the evidence.
find "$OUT" -type f -maxdepth 1 -exec sha256sum {} + 2>/dev/null
```

**Why this matters:** the weak form asserts a download from a substring and a stream number, which cannot be reproduced or challenged. The strong form declares the dissection mapping, uses the dissector's own framing semantics for the export, prints the declared-versus-captured delta so truncation is visible before anyone quotes the object, and hashes the result so the artefact can be compared byte-for-byte against a copy from the receiving endpoint.

## When It Is NOT This Issue

- **A reassembled stream shorter than its declared length:** this is capture-plane truncation, which happens with a short snaplen or a ring-buffer overrun. It is not server-side rejection and not evasion; check `capinfos` snaplen and the sensor's drop counters before drawing any conclusion from the shortfall.
- **Port 8080 or 8443 traffic declared as HTTP:** many services speak a bespoke protocol on those ports. Without an explicit `-d` mapping or an observed `HTTP/1.1` request line, the dissection is heuristic and every extracted object is speculative.
- **DNS label volume interpreted as tunnelling:** content-delivery, anti-virus lookups and some telemetry agents generate long, random-looking names at high rates. Baseline the resolver's normal query distribution, and check whether the names resolve successfully, before calling it a tunnel.
- **An SMB write that never appears in the share:** an interrupted session, a delete after write, or a write to a path the collector did not capture all produce this. Compare the `$MFT` or the share listing from the receiving host, not the stream alone.
- **TLS 1.3 sessions with no visible payload:** the absence of reassembled content is a property of the protocol, and reporting it as "no data transferred" inverts the meaning of the evidence.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `stream reassembly` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Dissection mapping declared:** every non-standard port used in the finding is mapped explicitly with `-d`, and heuristic dissections are labelled as inferred.
- [ ] **Completeness delta computed:** declared application length versus captured payload bytes is printed for each quoted stream, with the truncation budget stated.
- [ ] **Export hashed:** each exported object carries a SHA-256 so it can be compared against a copy from the receiving endpoint or proxy log.
- [ ] **Transport visibility stated:** clear-text, datagram or encrypted branch is named, and no payload claim is made for an unkeyed encrypted session.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: network-forensics-and-pcap-protocol-reconstruction
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) - Digital Forensics (core)
- [`network-forensics-and-pcap-malicious-traffic-identification`](../network-forensics-and-pcap-malicious-traffic-identification/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Completeness before content:** a reconstructed object that is short by one segment is a different artefact from a complete one, and the difference is invisible unless you compute the delta.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; exported objects may be malicious, so handle them in an isolated workspace and never open them on a production host.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/go_exploitdb (2), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
