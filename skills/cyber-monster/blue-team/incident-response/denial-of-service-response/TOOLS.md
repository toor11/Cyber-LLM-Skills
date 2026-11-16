# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`denial-of-service-response`](SKILL.md) | Family: **Incident Response**

Verified measurement and coordination entry points for an availability incident. Everything is read-only: counters, paths, DNS state and provider events. Never invent flags — `mtr`, `tcpdump` and `ss` option sets differ across distributions and versions, so confirm with `--help` on the host that will run them.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mtr` | `mtr -rwzc 100 --report-cycles 100 <target>` | Per-hop loss, latency and AS annotation to separate transit fault from flood | Linux, macOS |
| `tcpdump` | `tcpdump -nn -i any -c 5000 -w sample.pcap 'tcp port 443'` | Capture a bounded sample for frame-level analysis without flooding disk | Linux |
| `ss` | `ss -s` and `ss -tan state syn-recv` | Socket summary and half-open count, which is the cheapest protocol-state indicator on a host | Linux |
| `dig` | `dig +short A <host> @1.1.1.1` and `dig +short NS <zone>` | Public resolution from an external resolver, to see what the internet is being told today | Any host |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' --resolve <host>:443:<origin-ip> https://<host>/` | Direct-to-origin reachability test outside the mitigation path | Any host |
| Provider status/API | `GET /v1/events?from=<iso>&to=<iso>` and `GET /v1/status` with a bearer token | Mitigation event records and provider-side status for the window | Any host with API access |
| `nfdump` | `nfdump -r <capture> -s srcas/pps -n 25` | Top source autonomous systems by packet rate from existing flow captures | Linux |

## Minimal Script Shape

The shape below classifies the incident from three cheap measurements and refuses to give a verdict when one of them is missing. It is read-only and adds no traffic.

```bash
#!/usr/bin/env bash
# dos-classify.sh - read-only. Resource family + path check, with an explicit gap.
set -uo pipefail

HOST="${HOST:?public hostname}"
ORIGIN_IP="${ORIGIN_IP:-}"
IFACE="${IFACE:-eth0}"

echo "== 1. local socket state (protocol-state pressure) =="
ss -s || echo "GAP: ss unavailable on this host"

echo "== 2. half-open connections =="
ss -tan state syn-recv 2>/dev/null | wc -l || echo "GAP: cannot count syn-recv"

echo "== 3. public resolution (is DNS pointing at the mitigation path?) =="
dig +short A "$HOST" @1.1.1.1

echo "== 4. direct-to-origin reachability (the path question) =="
if [ -n "$ORIGIN_IP" ]; then
  code=$(curl -sS -o /dev/null -m 5 -w '%{http_code}' \
    --resolve "${HOST}:443:${ORIGIN_IP}" "https://${HOST}/" || true)
  case "$code" in
    000) echo "PASS: origin unreachable outside the mitigation path" ;;
    ""|000) echo "PASS: no response from origin address" ;;
    *)   echo "FAIL: origin answered directly (status $code) - shielding gap" ;;
  esac
else
  echo "SKIP: ORIGIN_IP not supplied; path question unanswered -> INCONCLUSIVE"
fi

echo "== 5. bounded path sample (transit fault vs flood) =="
command -v mtr >/dev/null 2>&1 && mtr -rwzc 50 "$HOST" || echo "GAP: mtr unavailable"
```

## Notes That Prevent Wrong Runs

- `mtr` with `-c` runs a bounded number of cycles; without it the command runs until interrupted and is useless during an incident. `-r` produces a report, `-w` a wide layout, and `-z` adds AS numbers.
- `tcpdump` without `-c` will fill the disk during a flood. Take a bounded sample and record the filter, because a capture without its filter cannot be interpreted afterwards.
- `ss -s` reports aggregate socket counts; the per-state breakdown from `ss -tan state <name>` is what distinguishes a SYN flood from an application backlog.
- `curl --resolve` bypasses DNS but not TLS SNI, so the origin must still present a certificate valid for the hostname; a TLS failure reads as unreachable and is not the same as a filtered port.
- Provider APIs rate-limit during a large event. Cache the event response locally and record the retrieval time rather than re-querying during mitigation.
