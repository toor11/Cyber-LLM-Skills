# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`anti-forensics-detection`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for reading tamper evidence out of an acquired source. Never invent undocumented flags — check `<tool> --help` on the installed build, because option names differ between releases of the Zimmerman tools and between TSK major versions. All invocations here are read-only; none writes to the evidence source.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `MFTECmd` (Eric Zimmerman) | `MFTECmd.exe -f <$MFT> --csv <out> --at` | Parse both `$SI` and `$FN` sets from a copied `$MFT` so the two can be compared | Windows |
| `MFTECmd` (USN mode) | `MFTECmd.exe -f <$J> -m <$MFT> --csv <out>` | Resolve change-journal records to parent paths as they were when written | Windows |
| `EvtxECmd` | `EvtxECmd.exe -d <Logs dir> --csv <out> --csvf evtx.csv` | Bulk-parse evacuated EVTX files, including 1102/104 and `EventRecordID` continuity | Windows |
| `The Sleuth Kit` | `fls -r -m / -o <sector> <image> > body.txt` then `mactime -b body.txt -d -y` | Filesystem-level timeline including deleted entries, independent of the OS view | Cross-platform |
| `Volatility 3` | `vol -f <image> windows.psscan` / `windows.cmdline` | Recover processes absent from the active list, and the command lines that cleared logs | Cross-platform |
| `Get-WinEvent` | `Get-WinEvent -LogName Security -Oldest -MaxEvents 1` | Bookend a live or mounted channel and read its configuration without parsing EVTX by hand | Windows |

## Minimal Script Shape

The shape below produces the one comparison that matters and refuses to guess when the evidence to make it is absent: it hashes the source, reads the channel boundary and its configuration, and reports rollover separately from clearing.

```powershell
# anti-forensic-channel-boundary.ps1 — read-only. No writes, no clearing, no config changes.
param(
  [Parameter(Mandatory)][string]$LogName = 'Security',
  [Parameter(Mandatory)][string]$EvidenceManifest = 'D:\evidence\HOST01\hashes.sha256'
)

$manifestOk = Test-Path $EvidenceManifest
$cfg  = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
$old  = Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue

if (-not $cfg -or -not $old) {
  "INCONCLUSIVE (Telemetry Gap): {0} absent, disabled, or unreadable." -f $LogName
  return
}

[pscustomobject]@{
  Log            = $LogName
  ManifestHashed = $manifestOk
  OldestAt       = $old.TimeCreated
  OldestRecordId = $old.RecordId
  OldestProvider = $old.ProviderName
  BoundaryIsClear = ($old.Id -in 1102, 104, 1100)
  RecordCount    = $cfg.RecordCount
  MaxSizeBytes   = $cfg.MaximumSizeInBytes
  RetentionMode  = $cfg.LogMode
  IsEnabled      = $cfg.IsEnabled
}
# Reading: a clear record AS the oldest survivor means the channel was refreshed.
# A small MaxSizeBytes with a full RecordCount means ordinary rollover instead.
```

## Notes That Prevent Wrong Runs

- Always parse a **copy**. `MFTECmd` reading `$MFT` on the live volume through raw access will still work, but the volume keeps writing while you parse, so the result is a moving picture with no defensible boundary.
- `--at` is mandatory for timestomp work. Without it the CSV collapses `$FN` values that match `$SI`, which is precisely the comparison you need to see.
- `EvtxECmd` reports `EventRecordId` as written in the record; do not confuse it with the file offset. A gap is only meaningful inside a single channel file set.
- `fls` output is a bodyfile, not an answer. `mactime -y` renders UTC and is the only safe rendering for cross-source correlation.
- `vol` plugin names moved: from 2.26.2 the injection and process-hiding plugins live under `windows.malware.*`, and the old names still resolve with a deprecation reminder for about a year. Record which namespace you used, because a 2.26.0 image report and a 2.27.0 report will otherwise look inconsistent.
