# Evidence Extraction Artifacts and Queries

> Sub-skill: [`network-forensics-and-pcap`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `network-forensics-and-pcap`. Each class names the capture-plane artefact being read, the command that extracts it, and the filter that turns rows into a finding. Confirm flags with `tshark -h` on the installed build; Wireshark and tshark 4.4+ are the reference here.

## Class 1 — Capture provenance and completeness

Expected hit: file type, encapsulation, snapshot length, packet count and a duration that matches the incident window. Any mismatch bounds every later claim.

```bash
capinfos -M incident.pcap | grep -Ei "encapsulation|snapshot|packet count|duration|precision"
tshark -r incident.pcap -q -z io,stat,1 | sed -n '1,12p'
```

False-positive note: `io,stat` prints a timeline of observed packets, not of received ones. A flat second in the middle of a busy window is equally consistent with a lull and with a drop; check the sensor's own drop counters before reading it as silence.

## Class 2 — Protocol presence

Expected hit: a protocol hierarchy whose top entries explain the traffic you already expect from that segment. A protocol that should exist and does not is the first anomaly.

```bash
tshark -r incident.pcap -q -z io,phs
tshark -r incident.pcap -Y "dns" -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -20
```

False-positive note: an absent protocol can mean the capture does not include it (wrong VLAN, asymmetric routing, encrypted as QUIC rather than TCP) rather than that it did not happen. Confirm the sensor placement before treating absence as evidence.

## Class 3 — Endpoint-pair volume and asymmetry

Expected hit: a ranked list of pairs by bytes with the direction of dominance, comparable across two captures taken from the same sensor.

```bash
tshark -r incident.pcap -q -z conv,tcp | sed -n '1,30p'
tshark -r incident.pcap -q -z endpoints,ip | sed -n '1,30p'
```

False-positive note: the largest conversation in a capture is almost always backup, patching or streaming. Only a pair whose rank or ratio changed relative to the matched baseline capture is a candidate.

## Class 4 — Connection state and cadence

Expected hit: `tcp.flags.syn` frames without a completing handshake, and inter-arrival deltas that repeat at a fixed value.

```bash
tshark -r incident.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport \
  | awk '{print $1"->"$3}' | sort | uniq -c | sort -k1 -nr | head -20
tshark -r incident.pcap -Y "ip.addr==198.51.100.10" -T fields -e frame.time_epoch | \
  awk 'NR>1{printf "%.3f\n",$1-p} {p=$1}' | sort -n | uniq -c | sort -nr | head
```

False-positive note: availability checkers and inventory scanners produce exactly the same half-open shape. Resolve the source address against the scanner inventory and the load-balancer health-probe list before calling it reconnaissance.

## Class 5 — Flow-record correlation

Expected hit: a Zeek `conn.log` or NetFlow record for the same endpoint pair inside the same UTC minute with a byte count that reconciles to the pcap conversation within header and retransmission overhead.

```bash
zeek -r incident.pcap local
awk '$0 !~ /^#/ {print $3, $5, $6, $10, $17, $18}' conn.log | head -20
```

False-positive note: NetFlow exporters sample (commonly 1 in 1024 or 1 in 4096) and scale their byte counters by the sampling rate. A factor-of-N divergence between a flow record and a pcap is a sampling artefact until the configured rate is checked.

## Class 6 — Timestamp semantics

Expected hit: `frame.time_epoch` aligned to UTC, with the sensor's clock offset to a reference within the tolerance you intend to state.

```bash
tshark -r incident.pcap -T fields -e frame.number -e frame.time_epoch -e frame.interface_id | sed -n '1,5p'
tshark -r incident.pcap -Y "ntp" -T fields -e ntp.offset | head
```

False-positive note: multi-interface captures interleave frames from sensors with independent clocks, so `frame.number` order can disagree with `frame.time_epoch` order. Sort on epoch before quoting a sequence, and state the inter-sensor offset you observed.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the sensor, its position relative to NAT and proxies, and the configured snaplen beside every capture you retain.
