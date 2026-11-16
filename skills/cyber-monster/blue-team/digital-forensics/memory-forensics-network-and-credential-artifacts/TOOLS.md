# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`memory-forensics-network-and-credential-artifacts`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for recovering network and credential artefacts from a Windows memory image. Never invent undocumented flags — confirm with `vol <plugin> -h` on the installed Volatility build, because plugin names and requirement sets change between releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Volatility 3 (gate) | `vol -f host.dmp windows.info` | Resolve banner, build, KDBG and layer before any other plugin is trusted | Cross-platform |
| Volatility 3 (sockets) | `vol -f host.dmp windows.netscan` and `windows.netstat` | Pool-scanned endpoints versus handle-walked endpoints; the delta is the exited-process population | Cross-platform |
| Volatility 3 (accounts) | `vol -f host.dmp windows.hashdump` and `windows.cachedump` | Local NTLM verifiers from the resident SAM image; DCC2 cache entries from SECURITY | Cross-platform |
| Volatility 3 (secrets) | `vol -f host.dmp windows.lsadump` | LSA secrets, autologon plaintext, `DPAPI_SYSTEM` key | Cross-platform |
| Volatility 3 (attribution) | `vol -f host.dmp windows.dlllist --pid <PID>` and `windows.cmdline --pid <PID>` | Resolve a socket owner to an image path and command line | Cross-platform |
| `winpmem` / Velociraptor `winpmem()` | `winpmem_mini_x64.exe host.dmp` | Acquire the image this pipeline consumes; Velociraptor 0.73+ exposes the same capability as a VQL function | Windows |

## Minimal Script Shape

The shape below refuses to interpret anything until the image gate passes, then reports the socket differential and the credential-source population separately so neither is mistaken for a verdict. It is read-only against the image.

```bash
#!/usr/bin/env bash
# mem-net-cred.sh — symbol gate, socket differential, credential source scope.
set -euo pipefail
IMG="${1:?usage: $0 image.dmp}"
OUT="${2:-./out}"; mkdir -p "$OUT"
VOL="${VOL:-vol}"

# 0. Gate: no KDBG, no conclusions.
"$VOL" -f "$IMG" windows.info > "$OUT/info.txt" 2>"$OUT/info.err" || {
  echo "INCONCLUSIVE: windows.info failed (see $OUT/info.err)"; exit 2; }
grep -q "Kernel Base" "$OUT/info.txt" || { echo "INCONCLUSIVE: no KDBG"; exit 2; }

# 1. Two independent socket sources.
"$VOL" -f "$IMG" windows.netscan > "$OUT/netscan.txt"
"$VOL" -f "$IMG" windows.netstat > "$OUT/netstat.txt" 2>/dev/null || : > "$OUT/netstat.txt"

# 2. Exited-owner population: present in netscan, absent from netstat.
comm -23 \
  <(awk 'NR>2 {print $5":"$6}' "$OUT/netscan.txt" | sort -u) \
  <(awk 'NR>2 {print $5":"$6}' "$OUT/netstat.txt" | sort -u) > "$OUT/exited_owners.txt"

# 3. Credential sources: report population, never a verdict.
for p in hashdump cachedump lsadump; do
  "$VOL" -f "$IMG" "windows.$p" > "$OUT/cred_$p.txt" 2>/dev/null || : > "$OUT/cred_$p.txt"
  printf '%-10s rows=%s\n' "$p" "$(grep -vc '^[[:space:]]*$' "$OUT/cred_$p.txt" || true)"
done
```

## Notes That Prevent Wrong Runs

- `windows.hashdump` is marked deprecated in the 2.26.x source tree but continues to work; confirm the replacement name on your installed build rather than assuming a rename has landed.
- `windows.malfind` and the other malware plugins moved to `windows.malware.*` in 2.26.2 (2025-09-25) and the old names emit a deprecation reminder until roughly 2026-06-07. Use the new names in new scripts.
- Never write plugin output back over the image directory, and never mount the image read-write; all six plugins here are read-only parsers.
