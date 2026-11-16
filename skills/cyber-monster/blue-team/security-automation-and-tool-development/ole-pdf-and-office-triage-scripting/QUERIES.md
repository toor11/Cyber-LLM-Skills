# Detection Queries and Telemetry Artifacts

> Sub-skill: [`ole-pdf-and-office-triage-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Static document-inspection artifacts owned by this slug. Nothing here executes, renders, or fetches anything from the document.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `analyze_macros()` returning an `AutoExec` entry | High | The macro runs without user interaction beyond enabling content |
| 2 | `TargetMode="External"` relationship target | High | The document pulls remote content, a live payload path |
| 3 | `/OpenAction` or `/AA` in a PDF | High | An action is bound to document open |
| 4 | `/JS` or `/JavaScript` object present | Medium | Script exists; reachability from an action still needs checking |
| 5 | Declared uncompressed size above the cap | High | A decompression bomb is refused before expansion |

## Detection Artifacts

```text
[ole-pdf-and-office-triage-scripting:rule-spec] static extraction only: macro streams, relationship targets, PDF construct counts
[ole-pdf-and-office-triage-scripting:filter-fp] unreadable macro stream is not "no macros"; report the distinction
[ole-pdf-and-office-triage-scripting:correlate] defanged external URL plus file sha256 links the lure to its delivery infrastructure
```

Macro findings and auto-exec triggers, printed rather than executed (Windows PowerShell 5.1 invoking Python):

```powershell
python -c "from oletools.olevba import VBA_Parser; p=VBA_Parser(r'C:\evidence\doc\sample.docm'); print(p.detect_vba_macros()); [print(t,k) for t,k,d in p.analyze_macros()]; p.close()"
```

Structural PDF scan without a renderer:

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\evidence\doc\lure.pdf")
foreach ($kw in @('/OpenAction','/AA','/JavaScript','/JS','/Launch','/EmbeddedFile')) {
    $text = [Text.Encoding]::Latin1.GetString($bytes)
    $count = ([regex]::Matches($text, [regex]::Escape($kw))).Count
    Write-Output "$kw=$count"
}
```

External relationship target extraction, defanged before it reaches a report:

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead("C:\evidence\doc\sample.docm")
$zip.Entries | Where-Object { $_.FullName -like '*_rels*' } | ForEach-Object {
    $reader = New-Object IO.StreamReader($_.Open())
    $content = $reader.ReadToEnd()
    $reader.Close()
    if ($content -match 'Target="(https?://[^"]+)"') { Write-Output $Matches[1].Replace('.', '[.]') }
}
$zip.Dispose()
```

Size-cap check before any extraction:

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead("C:\evidence\doc\sample.docm")
$total = ($zip.Entries | Measure-Object -Property Length -Sum).Sum
$zip.Dispose()
Write-Output ("uncompressed_bytes={0} over_cap={1}" -f $total, ($total -gt 209715200))
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Keep triage on an isolated analysis host with no outbound network path for the document parser.
- Store the hash and the raw report together; the report is only meaningful for that byte sequence.
