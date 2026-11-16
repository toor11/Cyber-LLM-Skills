# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`botnet-and-application-ddos-mitigation`](SKILL.md) | Family: **Incident Response**

Verified tools for measuring and attesting a DDoS incident. Every command below is read-only: it measures traffic, resolves addresses, or reads capture files. Never invent flags — check `--help` on the installed version, because `mtr`, `nfdump` and `tcpdump` option sets differ across distributions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` (BIND utils) | `dig +short A www.example.com @1.1.1.1` and `dig +short CNAME www.example.com` | Resolve the public record from an external resolver to see whether it points at the edge or leaks the origin | Any host |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{time_total} %{remote_ip}\n' --resolve www.example.com:443:198.51.100.10 https://www.example.com/` | Test whether the origin answers when addressed directly, bypassing the edge — the core origin-shielding check | Any host |
| `mtr` | `mtr -rwzc 200 www.example.com` | Per-hop loss, latency and ASN path for the targeted prefix; separates transit faults from flood | Linux, macOS |
| `nfdump` | `nfdump -r nfcapd.202511141200 -s srcip/bytes -n 20` and `nfdump -r <file> -s srcas/pps -n 20` | Top talkers by source and source AS from NetFlow/IPFIX captures already on disk | Linux |
| `tcpdump` | `tcpdump -nn -r flood.pcap 'tcp[tcpflags] & tcp-rst != 0'` | Count resets and control frames in a capture to confirm a stream-reset flood | Linux, macOS |
| `h2load` (nghttp2) | `h2load -n 2000 -c 20 -m 10 https://staging.example.com/` | Replay realistic HTTP/2 concurrency against a staging target to size rate limits before production | Linux, macOS |
| Edge/CDN mitigation API | `GET /v1/events?from=<iso>&to=<iso>` with a bearer token | Pull provider mitigation event records that attest absorption | Any host with API access |

## Minimal Script Shape

The shape below answers the single question that decides the whole response: is the origin reachable outside the mitigation path, and does the edge actually absorb traffic. It only reads.

```bash
#!/usr/bin/env bash
# origin-shield-attest.sh — read-only origin exposure + absorption check.
set -euo pipefail

HOST="${HOST:?set HOST to the public name, e.g. www.example.com}"
ORIGIN_IP="${ORIGIN_IP:?set ORIGIN_IP from inventory, not from DNS}"
EDGE_CIDR_FILE="${EDGE_CIDR_FILE:?file of published edge CIDRs, one per line}"

echo "== 1. public resolution (what the internet sees) =="
dig +short A "$HOST" @1.1.1.1 | tee /tmp/resolved.txt

echo "== 2. does the origin answer when addressed directly? =="
code=$(curl -sS -o /dev/null -m 5 \
  -w '%{http_code}' \
  --resolve "${HOST}:443:${ORIGIN_IP}" "https://${HOST}/")
echo "direct-to-origin status: ${code}"
case "$code" in
  000) echo "PASS: origin not reachable outside the mitigation path" ;;
  2*|3*|4*|5*) echo "FAIL: origin served a response directly -> shielding gap" ;;
esac

echo "== 3. is the resolved address inside the published edge ranges? =="
resolved=$(head -n1 /tmp/resolved.txt)
if while read -r cidr; do
     python3 - "$resolved" "$cidr" <<'PY'
import ipaddress, sys
try:
    print("in" if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False) else "out")
except ValueError:
    print("out")
PY
   done < "$EDGE_CIDR_FILE" | grep -qx in; then
  echo "PASS: public name resolves into the edge"
else
  echo "FAIL: public name does not resolve into any published edge range"
fi
```

## Notes That Prevent Wrong Runs

- The origin address must come from inventory or configuration, never from a DNS lookup — a lookup that already leaks the origin proves the gap but does not identify the target for the reachability test.
- `curl` exit 7 or status `000` means the connection was refused or timed out. That is a pass for shielding, not a failure of the test; record the elapsed time so a firewall drop and a dead host are distinguishable.
- `mtr -z` annotates hops with AS numbers, which is what makes a per-ASN blocking decision auditable later; without it the path is unlabelled and cannot be reviewed.
- `nfdump` reads captures already written. It cannot fill a gap in flow export coverage, and a top-talker list from a partial capture is biased toward the exporter that was working.
- Never replay load against a production origin with `h2load` during an active incident; the tool exists to size limits on staging, not to add traffic to a saturated service.
