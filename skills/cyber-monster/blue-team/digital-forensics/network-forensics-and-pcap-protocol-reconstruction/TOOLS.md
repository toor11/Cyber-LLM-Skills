# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-forensics-and-pcap-protocol-reconstruction`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for reassembling application-layer sessions from a capture. Confirm options with `tshark -h` on the installed build; `--export-objects` supported object types are listed by `tshark --export-objects ?`.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tshark` (stream follow) | `tshark -r cap.pcap -qz follow,tcp,ascii,<stream>` | Ordered per-direction byte stream after sequence-number de-duplication | Cross-platform |
| `tshark` (object export) | `tshark -r cap.pcap --export-objects "http,out" -q` | Completed HTTP/SMB/IMF/TFTP objects with dissector framing applied | Cross-platform |
| `tshark` (mapping and framing) | `tshark -r cap.pcap -d tcp.port==8080,http` then `-Y "http.content_length_header" -T fields -e tcp.stream -e http.content_length_header` | Declare the port mapping and read each stream's declared length, the denominator for the completeness delta | Cross-platform |
| `tshark` (statistics) | `tshark -r cap.pcap -q -z io,phs` and `-z conv,tcp` | Which protocols exist and how much each pair carried | Cross-platform |
| `NetworkMiner` | GUI import of a pcap, then the Files and Credentials tabs | Independent second reconstruction to compare object hashes against | Windows |

## Minimal Script Shape

The shape below exports objects and then publishes, for each stream, the declared length beside the captured payload so truncation is visible before an object is quoted. Read-only; it writes only into its own output directory.

```bash
#!/usr/bin/env bash
# recon-completeness.sh — export application objects and prove they are whole.
set -euo pipefail
CAP="${1:?usage: $0 capture.pcap [port_proto_map]}"
MAP="${2:-}"                       # e.g. "tcp.port==8080,http"
OUT="${3:-./recon}"; mkdir -p "$OUT/objects"

DECL_ARGS=(); [ -n "$MAP" ] && DECL_ARGS=(-d "$MAP")
echo "mapping: ${MAP:-<heuristics only>}" > "$OUT/scope.txt"

# Declared lengths per stream, plus the protocol that produced them.
tshark -r "$CAP" "${DECL_ARGS[@]}" -Y "http.content_length_header" \
  -T fields -e tcp.stream -e http.content_length_header -e http.request.full_uri \
  | sort -u > "$OUT/declared.tsv"

tshark -r "$CAP" "${DECL_ARGS[@]}" --export-objects "http,$OUT/objects" -q || true

# Per-stream captured payload, then the delta against declared length.
while IFS=$'\t' read -r stream declared uri; do
  got=$(tshark -r "$CAP" -Y "tcp.stream==${stream} && tcp.len>0" -T fields -e tcp.len |
        awk '{s+=$1} END {print s+0}')
  printf 'stream=%-6s declared=%-10s captured=%-10s delta=%-10s %s\n' \
    "$stream" "$declared" "$got" "$((got-declared))" "${uri:0:60}"
done < "$OUT/declared.tsv" | tee "$OUT/completeness.txt"

find "$OUT/objects" -maxdepth 1 -type f -exec sha256sum {} + 2>/dev/null | tee "$OUT/objects.sha256" || true
```

## Notes That Prevent Wrong Runs

- `--export-objects` writes only completed objects by design. No file for a stream is not evidence of no transfer; it is evidence the object was never reassembled whole.
- `-d` mappings are analyst assertions. If an export exists only because you supplied the mapping, say so in the report and treat the object as inferred content.
- `follow,tcp,raw` preserves binary; `ascii` replaces non-printables with dots and will corrupt any hash you compute from the console output. Always hash the exported file, never the terminal dump.
- Wireshark can follow TLS, HTTP/2, QUIC and WebSocket streams, but without session keys the output is handshake metadata only; do not describe it as reconstructed application content.
