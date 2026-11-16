# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`email-security-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Header inspection, authentication verification, and link expansion. Everything below reads a saved message or metadata; none of it sends mail or contacts a suspicious domain from a corporate address. Verify flags with `--help` on the installed versions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `swaks` | `swaks --to test@contoso.com --server mail.contoso.com --quit-after RCPT` | Check transport reachability without delivering a message | Cross-platform |
| `python3` + `email` stdlib | `email.message_from_binary_file` then `msg.get_all("Received")` and `msg.get_all("Authentication-Results")` | Parse headers in order, which is what makes the trusted-boundary determination possible | Cross-platform |
| `opendkim-testmsg` | `opendkim-testmsg < saved.eml` | Verify a DKIM signature against the published key for the `d=` domain | Linux |
| `dig` | `dig +short TXT _dmarc.contoso.com` and `dig +short TXT selector._domainkey.contoso.com` | Read the DMARC policy and the DKIM key actually published, which decides what a failure means | Cross-platform |
| `dig` | `dig +short TXT contoso.com` | Read the SPF record and its mechanisms | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{url_effective} %{http_code}\n' -L --max-redirs 5 <url>` against an isolated egress | Follow a redirect chain to its final host; use only from an isolated range | Cross-platform |
| Microsoft 365 message trace | `Get-MessageTraceV2 -StartDate 2026-11-13 -EndDate 2026-11-14 -SenderAddress <addr> -ResultSize 1000` | Locate deliveries for an account, including post-delivery actions | Windows PowerShell with Exchange Online module |
| Microsoft 365 content search | `New-ComplianceSearch -Name <n> -ExchangeLocation All -ContentMatchQuery '<query>'` then `Start-ComplianceSearch` | Scope a purge without executing it; the search is read-only | Windows PowerShell with compliance module |

## Minimal Script Shape

The script orders headers, identifies the trusted boundary, and prints the alignment facts a verdict depends on.

```bash
#!/usr/bin/env bash
# header-facts.sh — trusted boundary plus authentication alignment facts.
set -euo pipefail

EML="${EML:?set EML to a saved message file}"
OWN="${OWN_DOMAIN:?set OWN_DOMAIN to the domain you own}"

python3 - "$EML" "$OWN" <<'PY'
import email
import email.policy
import re
import sys

path, own = sys.argv[1], sys.argv[2].lower()
msg = email.message_from_binary_file(open(path, "rb"), policy=email.policy.default)

received = msg.get_all("Received") or []
print(f"received_hops={len(received)}  (the BOTTOM-most element in a mail client view is the edge hop)")

ar = msg.get_all("Authentication-Results") or []
for line in ar:
    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{proto}=(\w+)", line, re.I)
        if m:
            print(f"{proto}: {m.group(1)}")
    for dom in re.findall(r"header\.(?:d|i)=([^;\s]+)", line):
        print(f"  signed_or_envelope_domain: {dom}")

from_hdr = msg.get("From", "")
m = re.search(r"@([^>\s]+)", from_hdr)
from_domain = m.group(1).lower() if m else ""
print(f"from_domain={from_domain}  display={from_hdr}")
reply_to = msg.get("Reply-To") or ""
return_path = msg.get("Return-Path") or ""
print(f"reply_to={reply_to}")
print(f"return_path={return_path}")
if from_domain != own:
    print("NOTE: From domain is not an owned domain; a DMARC pass here says nothing about your brand.")
else:
    print("NOTE: From domain is owned; a DMARC fail is a forgery of your brand.")
PY
```

## Notes That Prevent Wrong Runs

- `Received` headers appear top-down newest-first in a raw file and bottom-up oldest-first in most clients; state which order you used before naming the edge hop.
- DMARC passes when either SPF or DKIM passes *and aligns*; report the aligned domain rather than the pass/fail token alone.
- A DKIM failure can be a rotated selector rather than a forgery; check the published key for the `d=` and `s=` values before drawing a conclusion.
- Never expand a suspicious URL from a corporate network: use an isolated egress and record the final host and status code rather than the visible link text.
- A compliance search is read-only; the purge is a separate, approved action. Keep the two steps distinct in the ticket so evidence is preserved before removal.
