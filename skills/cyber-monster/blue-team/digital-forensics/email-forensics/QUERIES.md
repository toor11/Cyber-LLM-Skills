# Artifacts and Queries

> Sub-skill: [`email-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction commands owned by `email-forensics`, grouped by evidence layer. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Nothing here opens an attachment, renders HTML, or writes into a mailbox store; parsers read copies.

## Class 1 — Integrity and format gate

Expected hit: a recorded digest per message or store, and an identified format. The format determines whether original headers even exist, so this runs before any header work.

```bash
file suspect.eml; sha256sum suspect.eml | tee manifest.txt
head -c 200 suspect.eml | tr -d '\r'      # confirm RFC 5322 text, not MSG/OLE

# Mailbox stores: identify before parsing.
file mailbox.pst mailbox.ost mailbox.mbox
xxd -l 64 mailbox.pst | sed -n '1,4p'     # MS-PST magic '!BDN'
```

False-positive note: a `file` result of "data" for a store usually means the export is encrypted or truncated, not corrupt. Confirm against the exporting platform's own size and checksum before declaring the store unreadable.

## Class 2 — Received chain, bottom-up and normalised

Expected hit: a chain whose hops increase monotonically once each is converted to UTC with its own offset, with the first hop matching a host the sender domain plausibly controls.

```bash
python3 - <<'PY_EMAIL'
import email, email.utils
from datetime import timezone
msg = email.message_from_binary_file(open('suspect.eml','rb'))
hops = msg.get_all('Received') or []
prev = None
for i, h in enumerate(reversed(hops)):
    ts = email.utils.parsedate_to_datetime(h.rsplit(';',1)[-1].strip()).astimezone(timezone.utc)
    flag = "" if prev is None or ts >= prev else "  <-- OUT OF ORDER"
    print(f"{i:02d} {ts.isoformat()}{flag}  {h.rsplit(';',1)[0].strip()[:100]}")
    prev = ts
PY_EMAIL
```

False-positive note: a single backwards hop is usually clock skew on one MTA, and a chain with extra hops at the bottom is usually a forwarder or a list. Only a hop written by your own boundary that contradicts your own queue log is a finding.

## Class 3 — Authentication verdicts and their provenance

Expected hit: an `Authentication-Results` header whose first token is your boundary's `authserv-id`, with SPF, DKIM and DMARC results that you can explain from the connecting IP and the signing domain.

```bash
python3 - <<'PY_EMAIL'
import email
msg = email.message_from_binary_file(open('suspect.eml','rb'))
for h in msg.get_all('Authentication-Results') or []:
    print('authserv-id:', h.split(';')[0].strip())
    print(h.replace(';', ';\n  ')[:900])
for h in msg.get_all('ARC-Seal') or []:
    print('ARC:', h[:160])
PY_EMAIL
```

False-positive note: a verdict header with no `authserv-id` (some providers omit it) or one that does not match your boundary proves only that someone wrote the header. Record which tokens you actually re-verified against DNS, and never present a stored `pass` as your own verification.

## Class 4 — MIME structure and attachment extraction

Expected hit: a part tree with content types, filenames and per-attachment SHA-256. An attachment whose declared type disagrees with its signature is the candidate; the hash is what pivots to host evidence.

```bash
mkdir -p parts
python3 - <<'PY_EMAIL'
import email, hashlib, pathlib
msg = email.message_from_binary_file(open('suspect.eml','rb'))
for i, part in enumerate(msg.walk()):
    if part.get_content_maintype() == 'multipart':
        continue
    data = part.get_payload(decode=True) or b''
    name = part.get_filename() or f'part-{i}'
    p = pathlib.Path('parts') / f'{i:02d}-{name}'
    p.write_bytes(data)
    print(i, part.get_content_type(), len(data), hashlib.sha256(data).hexdigest(), name)
PY_EMAIL
file parts/*
```

False-positive note: a `.docx` is a ZIP and `file` reports it as one; that is not a mismatch. Compare the *inner* structure (OLE versus OOXML) and check for double extensions and right-to-left override characters in the filename rather than trusting the extension list.

## Class 5 — Mailbox store items and their transport headers

Expected hit: per-item transport headers for internet-received mail, and their absence for sent or internal mail — which is expected, not suspicious.

```bash
# Read-only inventory of a PST/OST; never open it with a mail client.
readpst -D -o /cases/09/pst-out mailbox.pst 2>&1 | tail -5
grep -l -r '^Received:' /cases/09/pst-out | wc -l
find /cases/09/pst-out -type f -name '*.eml' -newermt "$START" | head
```

False-positive note: `readpst` re-serialises messages, so a hash taken from its output does not match the store's original bytes. Use it for structure and header review, and use a store-level parser when byte-exact attachment hashes matter.

## Class 6 — Delivery and mailbox audit corroboration

Expected hit: the platform's own record of the message arriving, being delivered to a mailbox, and being read or moved — matching the message's hop times within the platform's ingest delay.

```bash
# Example shape for a mail platform export; field names vary by provider.
jq -r 'select(.Operation -in ["Deliver","MoveToDeletedItems","MailItemsAccessed"])
       | [.CreationTime, .Operation, .UserId, .MailboxOwnerUPN,
          (.AffectedItems.Url // ""), .ClientIPAddress] | @tsv' audit.json | head -40
```

False-positive note: mailbox auditing records the operation, not the content, and a gap in it is a retention or licensing artifact as often as tampering. Confirm the audit policy was enabled for that mailbox before interpreting an empty result.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, beside every email finding, the message hash, whether headers were original, and which boundary produced each authentication verdict.
