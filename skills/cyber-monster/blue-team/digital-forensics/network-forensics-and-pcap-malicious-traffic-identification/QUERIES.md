# Evidence Extraction Artifacts and Queries

> Sub-skill: [`network-forensics-and-pcap-malicious-traffic-identification`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `network-forensics-and-pcap-malicious-traffic-identification`. Each class names the observable structure being measured, the command that extracts it, and the fleet comparison that turns a measurement into a finding. Content reconstruction is owned by [`network-forensics-and-pcap-protocol-reconstruction`](../network-forensics-and-pcap-protocol-reconstruction/SKILL.md); use it instead of duplicating object export here.

## Class 1 — Scope gate: duration and directionality

Expected hit: a capture long enough to contain at least three intervals of the cadence you are testing, with both directions of every scored flow present.

```bash
capinfos -M incident.pcap | grep -Ei "packet count|duration|snapshot"
tshark -r incident.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src | sort -u | wc -l
tshark -r incident.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e ip.dst | sort -u | wc -l
```

False-positive note: a SYN count far exceeding the SYN-ACK count is normal for an egress-only sensor, where replies arrive on a different interface. Confirm the observation point before reading the imbalance as scanning.

## Class 2 — Cadence dispersion per endpoint pair

Expected hit: at least three sessions per pair, with a coefficient of variation small enough that the interval is a property of the client rather than of user activity.

```bash
tshark -r incident.pcap -Y "ip.dst==203.0.113.9" -T fields -e tcp.stream -e frame.time_epoch \
  | awk '!seen[$1]++ {print $2}' | sort -n | \
  awk 'NR>1{d=$1-p; print d} {p=$1}' | sort -n | uniq -c | sort -nr | head
```

False-positive note: measuring one timestamp per stream is essential — a busy session with hundreds of packets produces hundreds of near-zero deltas and a spurious "very stable" result. Deduplicate by `tcp.stream` before computing anything.

## Class 3 — Directional byte ratio

Expected hit: bytes client-to-server versus server-to-client for the same pair, with the ratio stated in the direction you computed it.

```bash
tshark -r incident.pcap -q -z conv,tcp | awk '$1 ~ /203\.0\.113\.9/ || $3 ~ /203\.0\.113\.9/ {print}'
tshark -r incident.pcap -Y "ip.addr==203.0.113.9" -T fields -e tcp.len -e ip.src | \
  awk '{if ($2=="10.0.0.5") out+=$1; else inb+=$1} END {printf "out=%d in=%d ratio=%.2f\n", out, inb, out/inb}'
```

False-positive note: TLS handshake and certificate bytes inflate the server-to-client direction on short sessions, making a tiny upload look balanced. Compute the ratio only over sessions carrying at least a few hundred KB, and state the threshold.

## Class 4 — TLS fingerprint extraction

Expected hit: a JA4 value per ClientHello plus the SNI and ALPN, so a match can be judged against the destination's class.

```bash
tshark -r incident.pcap -Y "tls.handshake.type==1" \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja4 -e tls.handshake.ja3 2>/dev/null | head -20
```

False-positive note: `tls.handshake.ja3` and `ja4` fields require the fingerprint feature to be enabled in the installed build; an empty column is a tooling gap, not an absence of fingerprints. Confirm with `tshark -G fields | grep -i ja4` before concluding anything.

## Class 5 — Half-open and abort patterns

Expected hit: SYN without SYN-ACK, or a session that closes with RST immediately after establishment and carries no application data, clustered from one source across many destinations.

```bash
tshark -r incident.pcap -Y "tcp.flags.reset==1" -T fields -e ip.src -e ip.dst -e tcp.dstport \
  | awk -F'\t' '{print $1" reset->"$2":"$3}' | sort | uniq -c | sort -k1 -nr | head -20
tshark -r incident.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && !tcp.flags.reset" -T fields -e ip.src -e tcp.dstport | sort -u | wc -l
```

False-positive note: RST is how every closed port and every application-level refusal appears, so a high RST count is normal on any host with a firewall. The finding needs the same source hitting many destinations, not many resets from one source.

## Class 6 — DNS as a shape channel

Expected hit: query rate per name and label-length distribution, measured against the resolver's baseline population rather than an absolute threshold.

```bash
tshark -r incident.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | \
  awk -F. '{print $1}' | awk '{print length($0)}' | sort -n | uniq -c | tail -10
tshark -r incident.pcap -Y "dns.flags.response==0" -T fields -e ip.dst -e dns.qry.name | sort | uniq -c | sort -nr | head
```

False-positive note: CDN, telemetry and anti-abuse lookups legitimately send long random labels at high rates. Require the same parent domain, a narrow authoritative server set, and confirmation that names resolve, before calling the pattern tunnelling.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the sensor position (pre- or post-NAT), the capture duration, and the baseline capture used for every cadence or ratio claim.
