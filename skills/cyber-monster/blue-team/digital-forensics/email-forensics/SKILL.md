---
name: email-forensics
description: "Analyses email evidence: header analysis, attachment examination, mailbox artefacts and delivery path reconstruction. Use when investigating phishing or mailbox abuse."
family: digital-forensics
tier: leaf
triggers: ["email forensics", "header analysis email", "mailbox forensics"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
corpus_sparse: true
---

# Email Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

An email is a header block and a body, and every hop that handled it prepended its own `Received:` line — so the chain reads bottom-up, with the lowest line written by the earliest hop. That inversion is the source of most misreadings: analysts read top-down and conclude the message originated at the last server rather than the first. Each `Received:` line carries the receiving server's own timezone, and only the lines written by infrastructure you control are trustworthy; anything below the first hop your organisation wrote was supplied by the sender and can be fabricated wholesale, including a padded set of fake lower hops. Authentication verdicts have the same rule: `Authentication-Results` (RFC 8601) is evidence only when its `authserv-id` is your own boundary server, because a sender can insert a plausible-looking one lower in the block. SPF passing says the connecting IP was authorised for the envelope domain and says nothing about the `From:` domain; DKIM passing proves the `d=` domain signed the covered headers and body and says nothing about alignment; DMARC is the only one of the three that ties the two together, and it fails when SPF and DKIM both pass for a domain that does not align with `From:`. ARC preserves earlier hops' verdicts and is only meaningful if its instance numbering and `cv=` values form an unbroken chain. After the transport layer, the mailbox store determines what survives: EML keeps the raw message including its original bytes, MSG keeps MAPI properties with transport headers present mainly for internet-received items, and PST/OST hold whole mailboxes where sent and internal items may carry no `Received:` chain at all. Attachments are content: hashing them gives you a pivot to endpoint and sandbox evidence, while the message itself can tell you only what was claimed, by whom, and through which servers.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is a single message **THEN** work from the EML or the raw item with full headers preserved, and never from a forwarded copy or a screenshot — forwarding rewrites `Received:` chains and re-encodes the body, which breaks both the routing history and any DKIM body hash.
2. **IF** the artifact is a mailbox store **THEN** branch by format: EML (raw RFC 5322), MSG (OLE compound file with MAPI properties), PST/OST (whole store), MBOX (concatenated with `From ` separators), EMLX (Apple, byte count then RFC 822 then plist). Each has a different extraction path and a different notion of "original headers".
3. **IF** you are reconstructing routing **THEN** read `Received:` bottom-up, convert each hop's local time to UTC using its own offset, and check monotonicity; **IF** a hop goes backwards in time or a chain is implausibly short for the apparent origin, that is the finding, not a formatting curiosity.
4. **IF** authentication matters **THEN** confirm the `authserv-id` is your boundary before trusting any verdict, and re-verify DKIM against the signing domain's published key — a stored `dkim=pass` is a claim by whoever wrote the header, not a cryptographic result you have reproduced.
5. **IF** the question is whether a user received, opened or replied to a message **THEN** leave the message and go to the mailbox store and the mail platform's audit log; the message itself has no record of delivery or reading.
6. **IF** a `Received:` timestamp uses an offset other than UTC **THEN** record the conversion you applied beside the evidence; a mixed-zone timeline is the most common way an email investigation produces a wrong order.
7. **IF** telemetry source covering `Received header` / `attachment hash` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need header, hop and attachment extraction commands | [`QUERIES.md`](QUERIES.md) | One class per evidence layer |
| Need parser and analyser flags | [`TOOLS.md`](TOOLS.md) | Header analysers, store parsers, MIME tools |
| Business email compromise pattern question | [`business-email-compromise-response`](../../incident-response/business-email-compromise-response/SKILL.md) | Response ownership for BEC |
| Need to triage a suspicious message at scale | [`phishing-email-and-header-triage-automation`](../../security-automation-and-tool-development/phishing-email-and-header-triage-automation/SKILL.md) | Automation ownership |
| Need the mailbox host's own logs | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) or [`linux-forensics`](../linux-forensics/SKILL.md) | Client and server host artifacts |
| Need to examine an attachment that executed | [`malware-triage-for-ir`](../../malware-analysis/malware-triage-for-ir/SKILL.md) | Sample handling and triage |
| Need the workspace audit trail for the mailbox | [`saas-workspace-and-entra-unified-audit-forensics`](../saas-workspace-and-entra-unified-audit-forensics/SKILL.md) | Unified audit log ownership |
| Need known phishing and BEC case shapes | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |

## Procedure

1. **Confirm the evidence source and its integrity.** Record the SHA-256 of the message file or store, the acquisition method (platform export, mailbox export, device image), and whether headers are the originals. An export that re-encoded the message invalidates body-hash comparison and may have dropped headers the exporting system did not understand.
2. **Choose the branch from the artifact's format and the question.** Routing questions read `Received:` and `Authentication-Results`; content questions read the MIME structure and attachments; behavioural questions leave the message for the mailbox store and the platform's audit log. Write the branch into the output.
3. **Establish a baseline-versus-probe differential.** Baseline is the same sender's or the same tenant's normal mail patterns — the usual hops, the usual authentication results, the usual attachment types. Probe is the suspect message. The finding is the deviation, not the presence of a hop.
4. **Name the stop condition.** Declare `Inconclusive` when the only copy is a forwarded or re-saved version, when the mailbox store is a cache whose server-side copy is authoritative and unavailable, when the message's `Date:` and its first `Received:` disagree beyond plausible clock skew, or when DKIM cannot be re-verified because the selector's key has rotated out of DNS.
5. **State what counts as proof.** Proof is two independent sources agreeing: a `Received:` hop written by your boundary plus that server's own transport log for the same queue ID, or an attachment hash matching an endpoint record of the file being written. The message's own headers alone prove what the sending side claimed, and must be labelled as such.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Lowest `Received:` line naming a host and IP not in the sender domain's published ranges | RFC 5322 header chain | The earliest hop the header claims; only reliable if written by a server you control, otherwise it is sender-supplied text |
| `Authentication-Results` whose `authserv-id` is your boundary, showing `dmarc=fail` with `spf=pass` for a non-aligning domain | RFC 8601 authentication header | Your own boundary evaluated the message and found the envelope and header domains misaligned |
| `DKIM-Signature` with `d=` and `s=` re-verified against DNS, and a body hash that no longer matches | MIME entity plus DNS key record | The signed content changed after signing, on that message and selector; proves tampering in transit or on re-save |
| ARC chain with a gap in instance numbering or a `cv=` that does not follow | ARC header set | The preserved-authentication chain is broken, so earlier hops' verdicts cannot be relied on for this message |
| Attachment with a signature that disagrees with its extension, and a SHA-256 matching an endpoint write record | MIME attachment plus host filesystem record | The exact bytes were delivered and landed on that host at that time |
| `Message-ID` duplicated across messages with differing bodies | RFC 5322 `Message-ID` | At least one message is a copy or a forgery; a genuinely generated ID is not reused |
| Store item in PST/OST whose transport headers are absent for a sent or internal message | MAPI store item | The message never traversed an internet transport, so no `Received:` chain exists to analyse |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`Received header`):**

```text
# Reads the topmost Received line and trusts the stored verdict verbatim.
grep -m1 '^Received:' message.eml
grep -m1 '^Authentication-Results:' message.eml
# Top-down read identifies the wrong origin hop; the stored verdict may have
# been written by the sender; and no timestamp is converted, so no hop can be
# ordered against anything else.
```

**High-Signal Grounded Artifact:**

```text
# Parse the chain bottom-up, normalise every hop to UTC, and check monotonicity.
$ python3 - <<'PY'
import email, email.utils, sys
msg = email.message_from_file(open(sys.argv[1], encoding="utf-8", errors="replace"))
hops = msg.get_all("Received") or []
for i, h in enumerate(reversed(hops)):          # lowest line first
    when = email.utils.parsedate_to_datetime(h.rsplit(";", 1)[-1].strip())
    print(f"{i:02d} {when.astimezone(__import__('datetime').timezone.utc).isoformat()} "
          f"{h.rsplit(';', 1)[0].strip()[:110]}")
for ar in msg.get_all("Authentication-Results") or []:
    print("AUTH:", ar.split(";")[0].strip(), "|", ar[:160])
PY
```

**Why this matters:** the strong form reverses the header list before printing, converts every hop to UTC with its own offset, and prints the authentication header's `authserv-id` so a reader can judge whether the verdict came from a boundary that can be trusted.

## When It Is NOT This Issue

- **Forwarding and mailing-list rewriting:** a forwarder adds hops and can break DKIM body hashes while leaving the signature intact; mailing lists legitimately re-sign and rewrite subject lines. A broken signature after a known list is expected, not forgery.
- **Clock skew between MTAs:** a server with a drifting clock produces a `Received:` timestamp earlier than the hop before it, with no adversary involved. Check the sending server's own NTP history and the magnitude of the skew before calling it manipulation.
- **Time-zone rendering of `Date:` versus `Received:`:** `Date:` is written by the sender's client in its own zone; `Received:` times come from servers. A disagreement between them is normal and proves nothing about tampering.
- **Legitimate bulk senders and ESPs:** marketing platforms send from shared infrastructure with SPF and DKIM for their own domain and `From:` alignment handled by configuration. A non-aligning envelope is a policy observation, not evidence of a phishing attempt.
- **Mailbox cache versus server state:** an OST or a mobile cache holds a subset of what the server has, and its deletion of an item does not mean the item was deleted server-side. Read the platform's audit log before concluding that a message was removed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `Received header` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the message file or store carries a recorded SHA-256, and the output states whether headers are originals or a re-saved copy.
- [ ] **Format and branch stated:** EML, MSG, PST/OST, MBOX or EMLX is named, along with the extraction path used and what that format does or does not preserve.
- [ ] **Timeline normalised:** every `Received:` timestamp was converted to UTC with its own offset, and monotonicity was checked and reported.
- [ ] **Stop condition cleared or declared:** forwarded copies, cache-only stores, rotated DKIM keys and implausible skew were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: email-forensics
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `email-forensics` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — never open an attachment from a suspect message on an analysis host, and never let a mail client or previewer touch the evidence store.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
