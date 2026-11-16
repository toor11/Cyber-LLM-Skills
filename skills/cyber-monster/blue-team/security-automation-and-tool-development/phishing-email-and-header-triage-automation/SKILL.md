---
name: phishing-email-and-header-triage-automation
description: "Writes automated `.eml`/`.msg` phishing triage pipelines using Python `email`/`mail-parser`: Received-hop latency/spoof reconstruction, Authentication-Results (SPF/DKIM/DMARC/ARC) verification, defanged URL/attachment SHA-256 extraction, and lookalike-domain Punycode/Levenshtein scoring without fetching live tracking pixels. Use when automating SOC phishing queues."
family: security-automation-and-tool-development
tier: core
triggers: ["phishing triage script", "eml parser python", "spf dkim dmarc parser", "extract urls eml"]
cwe: [CWE-290]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Phishing Email and Header Triage Automation - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Phishing triage is header forensics plus artefact extraction, and the header part has a subtlety that decides most cases: `Authentication-Results` is only trustworthy when written by your own receiving host. Senders can add any such header they like, and a message can contain several, so a parser must walk the headers top-down, find the position of the `Received` field your own MTA added on arrival, and only trust `Authentication-Results` fields above that point — matching also on the `authserv-id` it expects. Below that boundary, everything is attacker-controlled. Within that boundary, the header carries the real verdict: `spf`, `dkim`, and `dmarc` results, the DKIM signing domain (`header.d`, or derived from `header.i`), and the ARC chain for forwarded mail. `Received` fields are read bottom-up to reconstruct the delivery path and the hop latencies — large gaps indicate queueing or a delayed replay. The artefact half is extraction without contact: URLs from the body, attachment SHA-256 hashes, and lookalike-domain scoring. Nothing in triage should fetch a URL or load a remote image, because both confirm to the sender that the mailbox is live and can leak the analyst's infrastructure. Defang every extracted URL before it lands in a report.

- **CWE-290 (Authentication Bypass by Spoofing):** a triage pipeline that trusts a sender-written `Authentication-Results` header concludes the opposite of the truth on exactly the messages that matter.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are reading authentication results **THEN** locate your own `Received` field first, trust only `Authentication-Results` above it whose `authserv-id` matches your expected host, and treat everything below as attacker-supplied.
2. **IF** you parse the header with the standard library **THEN** use `email.message_from_bytes(data, policy=email.policy.default)` and walk `raw_items()`, because `policy.default` preserves the header order and decoding you need.
3. **IF** you extract URLs or images **THEN** never fetch them; defang (`hxxp`, `[.]`) in the output and hash attachments locally.
4. **IF** you score lookalike domains **THEN** apply `idna`/Punycode decoding before comparison and combine edit distance with a homoglyph check; a Unicode display name that renders as a known brand is the finding.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `phishing-email-and-header-triage-automation` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable triage extraction shapes | [`QUERIES.md`](QUERIES.md) | Header walk, authserv-id matching, artefact extraction, hashing |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `email.policy`, `mail-parser`, `idna`, hashing |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Forged-header and live-fetch incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Mailbox-scope handoff for a live campaign |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11+ `email` with `email.policy.default`, `mail-parser` for `.msg`/`.eml` normalization, `idna` for Punycode, and local hashing for attachments
- **Mandatory Self-Validation Command:** `python -m py_compile phish_triage.py`

1. **Confirm the inputs.** Establish the expected receiving MTA identity (`authserv-id`), the mailbox or message set in scope, whether ARC is in use, and the report format the SOC consumes. Confirm that triage runs offline against stored messages, not against a live mailbox connection.
2. **Choose the branch.** Full triage → header trust boundary plus artefacts. Header-only question → stop after the auth results and `Received` chain. Attachment-focused → hashing plus type detection, still without execution. Lookalike analysis → Punycode plus edit distance against the protected brand list.
3. **Define how to validate the triage.** Fixtures: a message with a legitimate `Authentication-Results` above your `Received` (trusted), one with a forged header below it (must be ignored), one with a defanged URL in the body (must defang correctly and not fetch), and one with a Unicode lookalike domain (must score above the threshold).
4. **Name the stop condition.** Stop when the trust boundary cannot be located (no recognizable own `Received`), when `Authentication-Results` has no `authserv-id`, when a URL would require a network fetch to resolve, or when an attachment exceeds the size cap for hashing.
5. **State what counts as a working tool.** A working triage exits `0` when it produced a complete verdict from trusted headers plus artefacts, `1` when the message needs human review (ambiguous chain, unparseable auth results), and `2` when the message cannot be parsed at all. Its output contains no live URLs and no remote references.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Position of own `Received` relative to `Authentication-Results` | Proves the auth result was written by the receiving host, not by the sender |
| `authserv-id` match on the parsed field | Proves the field belongs to your infrastructure even if it is above the boundary |
| `Received` chain read bottom-up with hop deltas | Proves the delivery path and exposes delayed or replayed delivery |
| `idna` decode plus edit distance to a brand domain | Proves the lookalike claim is measured, not asserted from visual similarity |
| Attachment SHA-256 computed locally | Proves the artefact is identified without opening or transmitting it |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: trusts the first Authentication-Results header, fetches remote
# images from the body, and reports the raw URL.
import re

import requests

def triage(raw_bytes, msg):
    auth = msg.get("Authentication-Results", "")        # whichever one comes first
    urls = re.findall(r"https?://[^\s\"'>]+", raw_bytes.decode("utf-8", "ignore"))
    for url in urls:
        status = requests.get(url, timeout=5).status_code   # announces the analyst
    return {"auth": auth, "urls": urls, "final_status": status}
```

**Production-Grade Starter Skeleton (USE):**

```python
# phish_triage.py - Exit 0 verdict produced, 1 needs review, 2 unparseable
import hashlib
import json
import re
import sys
from email import message_from_bytes, policy

EXPECTED_AUTHSERV = "mx.example.internal"
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
MAX_ATTACHMENT_BYTES = 25_000_000

def defang(url: str) -> str:
    return url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")

def header_positions(msg) -> tuple[int | None, list[tuple[int, str, str]]]:
    """Return the index of our own Received field and every Authentication-Results above it."""
    own_index = None
    auth_fields = []
    for index, (name, value) in enumerate(msg.raw_items()):
        lowered = name.lower()
        if lowered == "received" and own_index is None:
            own_index = index
        elif lowered == "authentication-results":
            auth_fields.append((index, name, value))
    return own_index, auth_fields

def trusted_auth_results(own_index, auth_fields) -> list[str]:
    if own_index is None:
        return []
    trusted = []
    for index, _name, value in auth_fields:
        if index > own_index:
            continue
        if EXPECTED_AUTHSERV.lower() not in value.lower():
            continue
        trusted.append(value)
    return trusted

def received_chain(msg) -> list[str]:
    hops = [value for name, value in msg.raw_items() if name.lower() == "received"]
    return list(reversed(hops))          # bottom-up: oldest hop first

def extract_artefacts(msg) -> dict:
    urls, attachments = [], []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True) or b""
            if len(payload) <= MAX_ATTACHMENT_BYTES:
                attachments.append({
                    "filename": filename,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                })
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            body = part.get_content()
            for found in URL_RE.findall(body):
                urls.append(defang(found.strip()))
    return {"urls": sorted(set(urls)), "attachments": attachments}

def triage(raw_bytes: bytes) -> tuple[dict, bool]:
    msg = message_from_bytes(raw_bytes, policy=policy.default)
    own_index, auth_fields = header_positions(msg)
    trusted = trusted_auth_results(own_index, auth_fields)
    verdict = {
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "trust_boundary_found": own_index is not None,
        "trusted_auth_results": trusted,
        "untrusted_auth_results": [
            value for index, _n, value in auth_fields if own_index is None or index > own_index
        ],
        "received_hops": len(received_chain(msg)),
        **extract_artefacts(msg),
    }
    needs_review = own_index is None or not trusted
    return verdict, needs_review

def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: phish_triage.py <message.eml>\n")
        return 2
    try:
        raw = open(sys.argv[1], "rb").read()
        verdict, review = triage(raw)
    except OSError as exc:
        sys.stderr.write(f"fatal: {exc}\n")
        return 2
    print(json.dumps(verdict, indent=2))
    return 1 if review else 0

if __name__ == "__main__":
    raise SystemExit(main())
```

**Why this matters:** the trust boundary is computed from header order rather than assumed, so a forged `Authentication-Results` below your `Received` is reported as untrusted instead of believed, and every extracted URL is defanged without a single outbound request.

## When It Is NOT This Issue

- **A message "passes" DMARC but is clearly phishing** — the trusted header may be absent (mail arrived via a path that strips it) or the display name is spoofed while the authenticated domain is a lookalike; check the authenticated domain, not the From display name.
- **`Authentication-Results` shows `pass` twice with different values** — one was written by the sender; only the field above your own `Received` with the expected `authserv-id` counts.
- **The URL is unreachable** — deliberately so in triage; fetching it confirms the mailbox and can leak analyst infrastructure, so unreachability is expected, not a defect.
- **A lookalike domain scores below the threshold** — homoglyphs may be Punycode-encoded; decode with `idna` before computing distance.
- **An attachment hash matches clean-ware** — that is a real result; it means the lure relied on content rather than a unique payload.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER trust an `Authentication-Results` header below your own receiving `Received` field.
- NEVER fetch a URL or remote image during triage.
- NEVER report a raw (non-defanged) URL in a phishing report.
- NEVER assert DKIM validity from the header alone; the header records the receiving host's conclusion, and cryptographic verification needs the signing domain's DNS key and canonicalized message data.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Expected `authserv-id`, message source, and ARC usage for `phishing-email-and-header-triage-automation` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The header walk, extractor, or scorer is specific and runnable (no generic 'inspect the headers' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: phishing-email-and-header-triage-automation
- **Target Stack & Schema**: Python email with email.policy.default, mail-parser for .msg, idna for Punycode, local hashing
- **Safety, Scope & Exit-Code Guards**: [Header trust boundary, no outbound fetch, defanged output, attachment size cap, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Forged auth headers, stripped headers, homoglyph domains, clean-ware attachments]
- **Implementation**:
  [Runnable triage script following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile phish_triage.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`stix-taxii-and-misp-ioc-pipeline-scripting`](../stix-taxii-and-misp-ioc-pipeline-scripting/SKILL.md) - Publishes the observables this triage extracts
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - Scans extracted attachments by signature
- [`ole-pdf-and-office-triage-scripting`](../ole-pdf-and-office-triage-scripting/SKILL.md) - The document-analysis step for attachments that are Office or PDF files
- [`soar-playbook-and-webhook-connector-development`](../soar-playbook-and-webhook-connector-development/SKILL.md) - Automates mailbox purge and block actions from the verdict

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `phishing-email-and-header-triage-automation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-290`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
