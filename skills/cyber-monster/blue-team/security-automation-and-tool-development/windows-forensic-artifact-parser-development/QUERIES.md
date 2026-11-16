# Detection Queries and Telemetry Artifacts

> Sub-skill: [`windows-forensic-artifact-parser-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Artifact-parsing and chain-of-custody artifacts owned by this slug. Record the input hash and the library version with every row set.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | SHA-256 manifest over hive plus `.LOG1`/`.LOG2` | High | The parsed artifact is the received artifact, and recent writes are recoverable |
| 2 | Prefetch layout tag (`v17-68byte`, `v30-212byte`, `v30-220byte`) | High | Fields were read from the layout that file actually uses |
| 3 | Raw FILETIME beside the ISO-8601 rendering | High | Precision survived conversion and the value is re-derivable |
| 4 | `$MFT` row carrying entry number and attribute type | High | A timestamp is attributable to one attribute, not a flattened MACB set |
| 5 | Zero rows for a class known to be populated | High | Something failed — logs, version support, or a partial hive |

## Detection Artifacts

```text
[windows-forensic-artifact-parser-development:rule-spec] copy + hash, apply transaction logs, then parse read-only
[windows-forensic-artifact-parser-development:filter-fp] an unapplied hive reports stale values, not tampering
[windows-forensic-artifact-parser-development:correlate] entry/offset + raw timestamp ties a row to one artefact record
```

Chain-of-custody manifest for every input before parsing (Windows PowerShell 5.1):

```powershell
$artifacts = @(
  "C:\evidence\C\Windows\System32\config\SOFTWARE",
  "C:\evidence\C\Windows\System32\config\SOFTWARE.LOG1",
  "C:\evidence\C\Windows\Prefetch\CMD.EXE-1234ABCD.pf"
)
$artifacts | Where-Object { Test-Path $_ } | ForEach-Object {
  $h = Get-FileHash $_ -Algorithm SHA256
  "{0}  {1}  {2}" -f $h.Hash, (Get-Item $_).Length, $_
} | Set-Content .\build\manifest.txt
Get-Content .\build\manifest.txt
```

Hive values without mutating the source, reading only from a copy:

```powershell
New-Item -ItemType Directory -Force -Path C:\work\hive | Out-Null
Copy-Item "C:\evidence\C\Windows\System32\config\SOFTWARE*" C:\work\hive\
python -c "from regipy.registry import RegistryHive; r=RegistryHive(r'C:\work\hive\SOFTWARE'); print(len(list(r.recurse_subkeys(as_json=True))))"
```

Prefetch layout detection before reading counters:

```powershell
python -c "import struct,sys; d=open(sys.argv[1],'rb').read(); v=struct.unpack_from('<I',d,0)[0]; m=struct.unpack_from('<I',d,84)[0] if v>=17 else 0; print('version',v,'metrics_offset',m)" "C:\work\pf\CMD.EXE-1234ABCD.pf"
```

FILETIME plausibility check, which must reject 1601 and future values:

```powershell
python -c "import datetime as dt; e=dt.datetime(1601,1,1,tzinfo=dt.timezone.utc); raw=132000000000000000; print((e+dt.timedelta(microseconds=raw/10)).isoformat())"
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Store the manifest with the parsed output; a report without the input hash is not attributable.
- Label partial parses explicitly in the output schema so a downstream timeline does not treat them as complete.
