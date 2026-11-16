# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ransomware-response-strain-and-actor-identification`](SKILL.md) | Family: **Incident Response**

Verified victim-side artifact handling. Everything here describes or preserves artifacts; nothing executes a sample, decodes with an actor-supplied tool, or modifies an original. Confirm flags with `<tool> --help`.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-FileHash` | `Get-FileHash -Algorithm SHA256 <path>` | Identity anchor for a note or sample before any copy is made | Windows |
| `sha256sum` | `sha256sum <path>` | Same anchor on Linux hosts; record alongside the acquisition time | Linux |
| `strings` | `strings -n 8 sample.bin` | ASCII strings from a sample for family-compatible markers; read-only, no execution | Linux / macOS |
| `yara` | `yara -r -s rules.yar <samplepath>` | Match a preserved sample against family rules without running it | Cross-platform |
| `Get-AuthenticodeSignature` | `Get-AuthenticodeSignature <path>` | Signer and trust state of a Windows binary without executing it | Windows |
| `Get-ChildItem` + `Measure-Object` | `Get-ChildItem <root> -Recurse -File -Include *README*,*RESTORE*` | Locate notes for preservation; count first, then copy | Windows |

## Minimal Script Shape

The shape below preserves artifacts, produces a description, and refuses to state a family unless two artifact classes agree. It never executes a sample and never writes to the source location.

```powershell
# strain-preserve.ps1 — preservation and description only. No execution of any sample.
[CmdletBinding()] param(
    [Parameter(Mandatory)][string]$SearchRoot,
    [string]$CaseDir = ".\case\strain"
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $CaseDir | Out-Null

# 1. Locate candidate notes without copying yet; count first.
$notes = Get-ChildItem -Path $SearchRoot -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '(?i)readme|restore|decrypt|how.?to|recover' -and $_.Length -lt 200KB }
if (-not $notes) { Write-Warning "No note-like artifact found. State this in the report; do not infer a family." }

# 2. Hash then copy — order matters, the hash must describe the original.
$manifest = foreach ($n in $notes | Select-Object -First 5) {
    $h = Get-FileHash $n.FullName -Algorithm SHA256
    $dest = Join-Path $CaseDir ("note-" + $h.Hash.Substring(0,12) + $n.Extension)
    Copy-Item $n.FullName $dest -Force
    [pscustomobject]@{
        Original = $n.FullName
        Sha256   = $h.Hash
        Bytes    = $n.Length
        Written  = $n.LastWriteTimeUtc
        Copy     = $dest
    }
}
$manifest | Export-Csv -NoTypeInformation "$CaseDir\notes-manifest.csv"

# 3. Describe, never execute: signature and string markers from the preserved copy.
foreach ($m in $manifest) {
    $sig = Get-AuthenticodeSignature $m.Copy
    [pscustomobject]@{
        Copy   = $m.Copy
        Signer = $sig.SignerCertificate.Subject
        Status = $sig.Status
    }
} | Export-Csv -NoTypeInformation "$CaseDir\note-signatures.csv"

# 4. State the confidence ceiling from what was actually collected.
$classes = @()
if ($manifest) { $classes += 'note' }
if (Test-Path "$CaseDir\..\ext-after.csv") { $classes += 'extension' }
if ($classes.Count -lt 2) {
    Write-Warning "Only $($classes.Count) artifact class(es) available. Report as a single-class hypothesis."
}
```

## Notes That Prevent Wrong Runs

- Never run a recovered binary to "see what it does". Family behaviour is derived from strings, signatures, notes and your own telemetry — execution belongs only in an isolated analysis environment, never on the incident host.
- Hash before copying, always. A copied file's hash describes the copy; the original's hash is the artifact that survives in the case record.
- `strings` on a preserved copy is safe; `strings` on a live malicious process memory region is a different action with different risk and belongs to memory forensics.
- A YARA match is a signal, not an attribution. Rules are written by many parties with different naming conventions, and several families share rule fragments.
- Signature state of a note file is almost always unsigned, which proves nothing. Signature state of a *dropped binary* is meaningful; do not conflate the two in the report.
