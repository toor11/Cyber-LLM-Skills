# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`phishing-email-and-header-triage-automation`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed package version if a signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python 3.11+ `email` with `email.policy.default` (`message_from_bytes`, `raw_items`, `walk`, `get_payload(decode=True)`), `mail-parser` >= 4.10 for `.msg`/`.eml` normalization, `idna` for Punycode decoding
- **Validation Gate:** `python -m py_compile phish_triage.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Python `email` | `email.message_from_bytes(raw, policy=email.policy.default)` | Parse with ordered, decoded headers | Python 3.11+ |
| Python `email` | `msg.raw_items()` | Walk headers in original order — required for trust-boundary logic | Python 3.11+ |
| Python `email` | `msg.walk()` / `part.get_payload(decode=True)` | Iterate parts and get decoded attachment bytes | Python 3.11+ |
| Python `email` | `part.get_content()` | Decoded text body for URL extraction | Python 3.11+ |
| `mail-parser` | `MailParser().parse_from_string(raw)` | Normalize `.msg`/`.eml` variants into one object | Python >= 3.9 |
| `idna` | `idna.decode(label)` / `idna.encode(text)` | Punycode decode for lookalike comparison | Python |
| Python `hashlib` | `hashlib.sha256(payload).hexdigest()` | Attachment fingerprint without execution | Python 3.11+ |
| PowerShell | `Get-FileHash -Algorithm SHA256` | Independent hash for verification | Windows PowerShell 5.1 |
| `authresults` | `parse(field_value)` / `parse_arc(field_value)` | Structured RFC 8601/8617 parsing without doing DNS or crypto | Python >= 3.11 |

## Minimal Script

```powershell
python -m py_compile .\phish_triage.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\phish_triage.py .\evidence\phish\sample.eml | Set-Content .\build\verdict.json
$triage = $LASTEXITCODE

$live = Select-String -Path .\build\verdict.json -Pattern '"https?://' -Quiet
if ($live) { Write-Output "report contains a live URL"; exit 1 }

$attachments = (Select-String -Path .\build\verdict.json -Pattern '"sha256"' | Measure-Object).Count
Write-Output "triage=$triage attachments=$attachments"
exit $triage
```

Exit-code contract: `0` verdict produced from trusted headers, `1` needs human review (no trust boundary, no trusted auth result), `2` message unparseable or missing.
