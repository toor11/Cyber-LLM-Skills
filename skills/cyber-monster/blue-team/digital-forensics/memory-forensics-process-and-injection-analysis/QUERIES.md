# Evidence Extraction Artifacts and Queries

> Sub-skill: [`memory-forensics-process-and-injection-analysis`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `memory-forensics-process-and-injection-analysis`. Each class names the in-memory structure being read, the plugin invocation that recovers it, and the comparison that turns rows into a finding. Plugin names follow Volatility 3 2.26.2+, where the malware family lives under `windows.malware.*`.

## Class 1 — Plugin-family gate before any interpretation

Expected hit: every plugin name in your plan resolves and returns a header row. A legacy name that fails to resolve on a 2.26.2+ build looks exactly like a clean run once the error text is filtered out.

```bash
vol -f host.dmp windows.malware.malfind --help > /dev/null && echo "malfind OK"
vol -f host.dmp windows.ldrmodules --help > /dev/null && echo "ldrmodules OK"
vol -f host.dmp windows.info | grep -Ei "Kernel Base|MajorMinor"
```

False-positive note: a failed `--help` on a legacy plugin name means the name relocated, not that the technique is unmeasurable. Record which name actually resolved; a report that cites a plugin which never ran is unreproducible.

## Class 2 — Process enumeration differential

Expected hit: the `psscan`-only set is small on a healthy host and consists of recently exited processes with an exit time set. A `psscan`-only process with no exit time and live threads is the unlinked case.

```bash
vol -f host.dmp windows.pslist > pslist.txt
vol -f host.dmp windows.psscan > psscan.txt
comm -13 <(awk 'NR>2 {print $1}' pslist.txt | sort) <(awk 'NR>2 {print $1}' psscan.txt | sort)
```

False-positive note: terminated processes linger in pool until the page is reused, so a `psscan`-only PID is routine teardown unless the exit time is absent and a thread is still live. Always read the exit-time column before calling it hidden.

## Class 3 — PEB loader-list discrepancy

Expected hit: for a clean process every mapped image appears in all three lists. The finding is a `MappedPath` present with `InLoad` or `InInit` false, or a VAD-mapped image never named in any list.

```bash
PID=1234
vol -f host.dmp windows.ldrmodules --pid "$PID" | awk 'NR>2 && ($5=="False" || $6=="False")'
vol -f host.dmp windows.vadinfo --pid "$PID" | awk 'NR>2 && $0 ~ /\.dll/ {print $0}'
```

False-positive note: `ldrmodules` reports some legitimate entries with a missing initialization-list membership (delay-loaded and manually initialized modules). Require the same path to be absent from `InLoad` as well before treating the gap as concealment.

## Class 4 — Executable region inspection

Expected hit: region protection, `CommitCharge`, and, with the dump flag, the leading bytes of each committed executable region. A `PAGE_EXECUTE_READWRITE` region that starts with `MZ` in a non-JIT process is the strict-branch signal.

```bash
vol -f host.dmp windows.malware.malfind --pid 1234 --dump --dump-dir ./dumps
vol -f host.dmp windows.vadinfo --pid 1234 | awk 'NR>2 && $0 ~ /PAGE_EXECUTE_READWRITE/'
```

False-positive note: `--dump` writes files into a directory you choose; never point it at the acquisition directory, and never treat the dumped bytes as malware without an independent second structure agreeing.

## Class 5 — Thread origin and ghosting state

Expected hit: every thread start address resolves inside a mapped image. An address outside all images, or a populated `windows.suspended_threads` row on a process with no loader entry, is the anomaly.

```bash
vol -f host.dmp windows.threads --pid 1234 | awk 'NR>2 {print $2, $3, $4}'
vol -f host.dmp windows.suspended_threads
vol -f host.dmp windows.malware.processghosting
```

False-positive note: threads created by `CreateRemoteThread` into a legitimate broker process and threads parked in `NtTestAlert` show unusual start addresses without being malicious. Corroborate with the owning process's image path before escalating.

## Class 6 — In-memory image identity versus on-disk binary

Expected hit: the mapped image hash matching the on-disk binary of the same path. A mismatch on a path that should be immutable is the hollowing/replacement signal.

```bash
vol -f host.dmp --renderer json windows.dlllist --pid 1234 \
  | python -c "import json,sys; [print(r['Base'], r['Path'], r.get('LoadTime')) for r in map(json.loads,sys.stdin) if r.get('Path')]"
sha256sum ./evidence/C/Windows/System32/kernel32.dll
```

False-positive note: a mismatch is expected for binaries updated by servicing between image capture and disk acquisition, and for files on a volume that was restored from a different build. Compare build stamps before concluding replacement.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the Volatility build and resolved plugin names beside every exported row set, because the `windows.malware.*` relocation changes which name produces a valid run.
