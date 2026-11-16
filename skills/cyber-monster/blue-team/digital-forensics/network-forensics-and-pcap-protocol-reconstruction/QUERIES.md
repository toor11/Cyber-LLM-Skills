# Evidence Extraction Artifacts and Queries

> Sub-skill: [`network-forensics-and-pcap-protocol-reconstruction`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `network-forensics-and-pcap-protocol-reconstruction`. Each class names the transport-level structure being reassembled, the extraction command, and the completeness filter that must pass before an object is quoted. Flags follow tshark 4.4+.

## Class 1 — Dissection boundary declaration

Expected hit: an explicit port-to-protocol mapping and a request line or protocol signature that confirms the mapping. Without one, every later extraction is heuristic.

```bash
tshark -r incident.pcap -Y "tcp.port==8080" -T fields -e tcp.stream -e http.request.method -e http.request.full_uri | head
tshark -r incident.pcap -d tcp.port==8080,http -Y "tcp.port==8080 && http" -T fields -e tcp.stream | head
```

False-positive note: the mapped run returning rows that the unmapped run did not is the definition of a heuristic mapping. Record that you supplied the mapping; a reconstructed object that exists only because you declared it is a hypothesis, not an observation.

## Class 2 — TCP stream reassembly and length accounting

Expected hit: a per-stream payload total that matches the application-declared length, and a follow output whose printable content agrees with the exported object.

```bash
tshark -r incident.pcap -qz follow,tcp,ascii,3 | sed -n '1,40p'
tshark -r incident.pcap -Y "tcp.stream==3 && tcp.len>0" -T fields -e tcp.len | awk '{s+=$1} END {print s+0}'
```

False-positive note: `follow` de-duplicates retransmissions by sequence number, so its byte count can legitimately differ from a naive sum of `tcp.len`. A shortfall against declared length is truncation; a surplus is retransmission, and only the shortfall invalidates the object.

## Class 3 — HTTP object export and completeness

Expected hit: one file per completed response whose size equals the `Content-Length` header, plus a hash that can be compared to the receiving endpoint.

```bash
mkdir -p objects && tshark -r incident.pcap --export-objects "http,objects" -q
tshark -r incident.pcap -Y "http.content_length_header" -T fields -e tcp.stream -e http.content_length_header -e http.request.full_uri
sha256sum objects/* 2>/dev/null
```

False-positive note: object export writes only completed objects, so a transfer that was captured mid-stream produces no file at all and looks like no transfer. Cross-check the `http.content_length_header` list against the exported set; a declared length with no corresponding file is a truncation finding.

## Class 4 — SMB session payload accounting

Expected hit: NBSS-framed writes whose payload total matches the file size later observed on the share, with the tree and file name in the same stream.

```bash
tshark -r incident.pcap -Y "smb2" -T fields -e tcp.stream -e smb2.filename -e smb2.cmd | head -30
tshark -r incident.pcap -Y "smb2" -T fields -e tcp.len | awk '{s+=$1} END {print s+0}'
```

False-positive note: SMB2 compound requests carry several operations in one frame, so a per-frame command count overstates the number of file operations. Count the file-name fields, not the command fields, when reporting how many files moved.

## Class 5 — DNS query and response correlation

Expected hit: query and response paired by transaction ID, with the response code and answer count visible. Tunnelling shape is high rate, long encoded labels, and a narrow set of authoritative servers.

```bash
tshark -r incident.pcap -Y "dns.flags.response==0" -T fields -e dns.id -e dns.qry.name | head -20
tshark -r incident.pcap -Y "dns" -T fields -e dns.qry.name | awk '{print length($0), $0}' | sort -nr | head -20
```

False-positive note: CDN and telemetry hostnames are long and numerous by design. Require both the query rate anomaly and a label-charset anomaly, and confirm the names actually resolve, before describing the pattern as a tunnel.

## Class 6 — Mail session framing

Expected hit: an SMTP `DATA` block terminated by a lone dot, followed by a `250` server acceptance. A missing acceptance is the diagnostic.

```bash
tshark -r incident.pcap -Y "smtp" -T fields -e tcp.stream -e smtp.req.command -e smtp.response.code | head -40
tshark -r incident.pcap -qz follow,tcp,ascii,7 | grep -n "^\.$" | head
```

False-positive note: a `250` can belong to an earlier command in the same stream. Pair each response with the immediately preceding request in the same direction, and confirm the dot terminator's position in the sequence before claiming acceptance or rejection.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the `-d` mappings you supplied beside every exported object; a mapping supplied by the analyst changes what the export represents.
