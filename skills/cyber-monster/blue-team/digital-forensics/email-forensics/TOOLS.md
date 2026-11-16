# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`email-forensics`](SKILL.md) | Family: **Digital Forensics**

Parsers and read-only entry points for message and mailbox evidence. Never invent undocumented flags — confirm with `<tool> --help` on the installed build. Nothing here opens an attachment, executes a macro, or renders HTML with network access.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Python `email` | `email.message_from_binary_file(open(p,'rb'))` | Parse raw MIME without re-serialising or losing headers | Cross-platform |
| `readpst` (libpst) | `readpst -D -o <dir> <store.pst>` | Walk a PST/OST read-only and emit per-item files | Linux, macOS |
| `pffexport` (libyal) | `pffexport -m all <store.pst>` | Detailed PST/OST export including item metadata | Cross-platform |
| `msgconvert` | `msgconvert --outdir <dir> <file.msg>` | Convert an MSG (OLE/MAPI) item to RFC 5322 for header review | Linux, macOS |
| `olevba` (oletools) | `olevba --decode <attachment.docm>` | Read macro source from an attachment without executing it | Cross-platform |
| `exiftool` | `exiftool -json <attachment>` | Extract document and image metadata from an attachment | Cross-platform |

## Minimal Script Shape

The shape below extracts the three things that decide most email questions — the normalised hop chain, the authentication provenance, and per-attachment hashes — and refuses to print a verdict header without its origin.

```python
#!/usr/bin/env python3
"""eml-triage.py — read-only triage of one RFC 5322 message."""
import email
import email.utils
import hashlib
import sys
from datetime import timezone

path = sys.argv[1]
with open(path, "rb") as fh:
    msg = email.message_from_binary_file(fh)

hops = msg.get_all("Received") or []
print(f"hops={len(hops)} from={msg.get('From','?')[:80]!r} subject={msg.get('Subject','?')[:60]!r}")

prev = None
for i, h in enumerate(reversed(hops)):                     # lowest hop is earliest
    try:
        ts = email.utils.parsedate_to_datetime(h.rsplit(";", 1)[-1].strip()).astimezone(timezone.utc)
    except (TypeError, ValueError):
        print(f"{i:02d} UNPARSED  {h[:80]}")
        continue
    order = "" if prev is None or ts >= prev else "  OUT-OF-ORDER"
    print(f"{i:02d} {ts.isoformat()}{order}")
    prev = ts

for ar in msg.get_all("Authentication-Results") or []:
    print("authserv-id:", ar.split(";")[0].strip(), "   (verify this is YOUR boundary)")

for i, part in enumerate(msg.walk()):
    if part.get_content_maintype() == "multipart":
        continue
    data = part.get_payload(decode=True) or b""
    print(i, part.get_content_type(), len(data),
          hashlib.sha256(data).hexdigest(), part.get_filename())
```

## Notes That Prevent Wrong Runs

- `message_from_file` on a text-mode handle can normalise line endings and break DKIM body-hash comparison. Use `message_from_binary_file` and keep the raw bytes.
- `readpst -D` writes one file per item and re-serialises them; byte-exact attachment hashes must come from a store-level parser or from the original transport copy.
- A `.msg` is an OLE compound file. Treating it as text with `grep` finds strings but no reliable header structure; convert or parse it properly.
- `olevba` reads macro source and does not execute it. Never run `--exec`, never open the document in an office suite, and never let a preview handler touch the evidence.
- Authentication headers are text until you re-verify them. If you did not query DNS for the selector's key and check the body hash yourself, say "stored verdict" in the report.
