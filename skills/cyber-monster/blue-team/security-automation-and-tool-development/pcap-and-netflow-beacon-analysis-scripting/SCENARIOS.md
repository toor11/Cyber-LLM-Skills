# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`pcap-and-netflow-beacon-analysis-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative beacon-analysis failures, each with the artifact that proves the diagnosis.

## Case 1: The analyzer was the incident

- **Surface & Preconditions:** a script calls `rdpcap()` on a 12 GB capture to find beacons.
- **Root cause & impact:** the process exhausts host RAM and is killed, taking the analyst's workstation with it; the capture is never analysed and the investigation stalls on infrastructure that was supposed to help it.
- **Verification & fix:** stream with `dpkt.pcap.Reader` and aggregate per flow key; assert peak working set stays bounded on a large fixture.

## Case 2: NTP flagged as command and control

- **Surface & Preconditions:** ranking by coefficient of variation alone over a capture that includes NTP and a monitoring agent.
- **Root cause & impact:** both are perfectly periodic, so they outrank a jittered implant. The report is dominated by benign infrastructure and the real candidate sits at position 40.
- **Verification & fix:** add a sample floor, an interval band, and corroboration (destination reputation, JA3/JA4 consistency, payload uniformity) before a candidate is reportable; baseline known periodic jobs first.

## Case 3: Confident verdict from a ten-minute capture

- **Surface & Preconditions:** a 10-minute capture is analysed for beacons sleeping every 30 minutes.
- **Root cause & impact:** zero or one observation per flow; no statistic can distinguish a 30-minute beacon from a single connection. The absence of candidates is read as absence of beaconing.
- **Verification & fix:** state the capture window beside the candidate list and refuse to score flows with fewer than the minimum connections; extend the window rather than lowering the sample floor.

## Case 4: Retransmissions doubled the count

- **Surface & Preconditions:** connection starts are counted for every packet with the SYN flag, on a lossy link.
- **Root cause & impact:** retransmitted SYNs inflate the count and shorten measured intervals, so the mean and CV describe retransmission behaviour rather than the application's cadence.
- **Verification & fix:** count SYN without ACK and deduplicate per `(src, dst, sport, dport)` within a short window before computing statistics.
