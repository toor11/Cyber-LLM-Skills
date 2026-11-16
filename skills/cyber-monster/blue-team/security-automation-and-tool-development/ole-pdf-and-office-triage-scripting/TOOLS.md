# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ole-pdf-and-office-triage-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed package version if a signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `oletools` (`olevba.VBA_Parser`, `olevba.VBA_Scanner`, `oleid`) for Office containers, `pdfid`-style byte scanning plus `pypdf` for PDF object inspection — all static
- **Validation Gate:** `python -m py_compile doc_triage.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `oletools` (Python) | `VBA_Parser(path)` / `VBA_Parser(name, data=raw_bytes)` | Parse OLE and OpenXML containers for VBA streams | Python |
| `oletools` (Python) | `detect_vba_macros()`, `analyze_macros()`, `get_vba_code_all_modules()`, `close()` | Detect, characterise, and extract macro source | Python |
| `oletools` (CLI) | `olevba sample.docm` | Extract macros and findings from the command line | Cross-platform |
| `oletools` (CLI) | `oleid sample.doc` | Summary of risk indicators | Cross-platform |
| `oletools` (CLI) | `mraptor sample.doc` | Score auto-exec plus write plus execute | Cross-platform |
| `pdfid` | `pdfid.py sample.pdf` | Count `/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFile` without rendering | Cross-platform |
| `pypdf` | `PdfReader(path)` then inspect `/Root` and page `/Annots` | Object-level detail for a specific finding | Python |
| Python `zipfile` | `ZipFile(path).infolist()` summing `file_size` | Uncompressed-size check before extraction | Python 3.11+ |

## Minimal Script

```powershell
python -m py_compile .\doc_triage.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\doc_triage.py .\evidence\doc\sample.docm | Set-Content .\build\doc-report.json
$triage = $LASTEXITCODE

$live = Select-String -Path .\build\doc-report.json -Pattern '"https?://' -Quiet
if ($live) { Write-Output "report contains a live URL"; exit 1 }

Write-Output "triage_exit=$triage"
exit $triage
```

Exit-code contract: `0` characterised with no suspicious constructs, `1` suspicious constructs present or the file was refused for size, `2` unreadable file or unsupported format.
