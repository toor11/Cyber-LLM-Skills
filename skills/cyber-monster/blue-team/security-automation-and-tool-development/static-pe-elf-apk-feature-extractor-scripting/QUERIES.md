# Detection Queries and Telemetry Artifacts

> Sub-skill: [`static-pe-elf-apk-feature-extractor-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Static extraction artifacts owned by this slug. Record the parser name and version with every feature record so a vector is reproducible.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Identical output across two runs on the same sample | High | The feature vector is deterministic and usable as a model input |
| 2 | `imphash` with preserved import order | High | The feature is comparable across samples |
| 3 | Section entropy above ~7.2 with a large raw size | Medium | Packing or encryption; intent is not implied |
| 4 | `skipped_structures` entry naming a section and reason | High | A declared size was refused rather than trusted |
| 5 | Parser name and version in the record | High | The vector can be reproduced or explained after an upgrade |

## Detection Artifacts

```text
[static-pe-elf-apk-feature-extractor-scripting:rule-spec] bounded reads only: cap sample size, cap section size, validate declared lengths
[static-pe-elf-apk-feature-extractor-scripting:filter-fp] imphash collisions and high entropy occur in benign software built on the same framework
[static-pe-elf-apk-feature-extractor-scripting:correlate] sha256 + parser version + feature hash identifies one vector unambiguously
```

Determinism check, which must produce zero differences (Windows PowerShell 5.1):

```powershell
python .\feature_extract.py .\samples\sample.exe | Set-Content .\build\vec1.json
python .\feature_extract.py .\samples\sample.exe | Set-Content .\build\vec2.json
$diff = Compare-Object (Get-Content .\build\vec1.json) (Get-Content .\build\vec2.json)
if ($diff) { Write-Output "non-deterministic output"; exit 1 }
Write-Output "deterministic"
```

Independent `imphash` check for one known sample:

```powershell
python -c "import pefile,sys; pe=pefile.PE(sys.argv[1], fast_load=True); print(pe.get_imphash()); pe.close()" .\samples\sample.exe
```

Cap behaviour: a section declaring an oversized raw length must be skipped and reported, not read.

```powershell
python .\feature_extract.py .\samples\packed.exe | Select-String -Pattern 'skipped_structures|declared_size_over_cap'
```

Capability labels, kept separate from the numeric vector:

```powershell
capa -r .\capa-rules -s .\capa-sigs .\samples\sample.exe | Set-Content .\build\capa.txt
Select-String -Path .\build\capa.txt -Pattern '^[a-z]' | Select-Object -First 15
```

Android vector extraction with the decompression guard applied first (reuse the `zipfile` guard described in [`ole-pdf-and-office-triage-scripting`](../ole-pdf-and-office-triage-scripting/SKILL.md) before parsing):

```powershell
python -c "import sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); t=sum(i.file_size for i in z.infolist()); z.close(); print('uncompressed_bytes', t, 'over_cap', t > 209715200)" .\samples\sample.apk
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Pin parser versions and record them; a silent upgrade changes features under an unchanged model.
- Keep one labelled known-good and one labelled known-bad sample as a permanent extraction regression pair.
