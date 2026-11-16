---
name: saas-workspace-and-entra-unified-audit-forensics
description: "Acquires and analyses Microsoft Purview Unified Audit Logs (UAL), Entra SignIn/Audit logs, and Google Workspace Admin/Token logs: reconstructing OAuth consent grants, `MailItemsAccessed` throttling/completeness checks, inbox forwarding rules, and session-token replay timelines. Use during BEC or SaaS tenant forensics."
family: digital-forensics
tier: core
triggers: ["unified audit log forensics", "mailitemsaccessed", "google workspace token audit", "entra signin forensics"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
corpus_sparse: true
---

# Saas Workspace and Entra Unified Audit Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`azure-and-entra-attacks`](../../../red-team/cloud-container-supply-chain/azure-and-entra-attacks/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A SaaS tenant's forensic record is a set of independently-scoped audit streams that share identifiers but not retention. Microsoft Purview's unified audit log is a single query surface over Exchange, SharePoint, OneDrive, Teams and Entra activity, retained 180 days by default under Audit (Standard) and one year for Entra/Exchange/SharePoint activity for users holding an E5-class licence, extendable to ten years with the add-on — and each record's retention is decided at ingest time by the licence in force then, so a later licence upgrade does not extend records already written. Entra writes sign-in events to two separate stores: interactive sign-ins and non-interactive sign-ins, which means a single authentication flow commonly produces two records with the same `SessionId` and different `Unique Token Identifier` values. That is the pivot that makes BEC reconstruction possible: the `sid` claim is generated at interactive authentication and inherited by every access token issued from the same session, and Exchange, SharePoint and Teams audit records carry it as `AppAccessContext.AADSessionId` alongside `UniqueTokenId` and `IssuedAtTime`. `MailItemsAccessed` is the mailbox-read audit action, covering both `Bind` (an individual message access) and `Sync` (a batch download) across all mail protocols. What these streams cannot tell you: linkable identifiers are absent from some aggregated and background records, so a session-only search misses activity; an AiTM attack reuses the victim's own session, so the session ID does not separate attacker from victim and only the network origin does; UAL ingestion can lag by minutes to hours, so a search run too early under-reports; and with Defender XDR advanced-hunting tables streaming into a Sentinel data lake, the lake copy is not visible to analytics rules, so a query against the wrong store returns a false zero.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the incident window is inside 180 days **THEN** query the UAL directly; **IF** it reaches past the retention boundary **THEN** state which records are out of coverage by licence class rather than reporting a quiet period.
2. **IF** the question concerns a single authentication flow **THEN** search both interactive and non-interactive sign-in stores and join on `SessionId`, because `UniqueTokenIdentifier` differs between the authorization code and the bearer token and will not link them.
3. **IF** the tenant streams Defender XDR tables into a Sentinel data lake **THEN** query the lake for history beyond Defender's retention and remember that lake-only data is invisible to analytics rules, so a rule-based zero is not evidence.
4. **IF** the artefact is Google Workspace **THEN** pivot to Admin audit, login audit and OAuth token audit streams and state the platform change; Entra identifiers do not exist there.
5. **IF** `MailItemsAccessed` returns fewer records than expected **THEN** check the licence class of each mailbox owner and whether the ingestion window has closed before concluding the mailbox was not read.
6. **IF** telemetry source covering `Search-UnifiedAuditLog` or `MailItemsAccessed` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`azure-and-entra-attacks`](../../../red-team/cloud-container-supply-chain/azure-and-entra-attacks/SKILL.md).
8. **IF** required preconditions for `saas-workspace-and-entra-unified-audit-forensics` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need the endpoint side of a token replay | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | Sign-in origin, device artefacts and execution history |
| Need to see what traffic the session produced | [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) | Proxy and flow evidence for the same session window |

## Procedure

1. **Confirm which audit streams exist for this tenant and what each retains before querying.** Establish whether unified audit ingestion is enabled, the licence class of each mailbox and user in scope, whether the Advanced Hunting tables retain 30 days while a lake copy holds longer, and whether Google Workspace audit streams are in scope. A query against a stream that was never enabled returns an empty set that reads exactly like a clean tenant.
2. **Choose the branch from the question's subject.** Identity branch for sign-in and consent events, using both sign-in stores. Mailbox branch for `MailItemsAccessed`, inbox-rule operations and forwarding changes. Data branch for `FileDownloaded`, `FileSyncDownloadedFull` and sharing operations. Token branch for `AppAccessContext` correlation across workloads. Record the branch and the retention that applies to it.
3. **Establish the differential on session and on origin network.** For each candidate session, compare the set of operations against the same user's normal operation set over a baseline window, and compare the source network of each operation within the session. An AiTM session shows the victim's own session ID used from two different networks; a legitimate session shows one network throughout.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the window reaches past the applicable retention, when ingestion for the tail of the window has not completed, when linkable identifiers are absent for the records in question, or when the records exist only in a data-lake tier that analytics rules cannot see.
5. **State what counts as proof.** Proof is the same `SessionId` appearing in the Entra sign-in record and in at least one workload audit record, plus a network origin for the workload operation that differs from the interactive sign-in's origin, within the token's validity window. A consent record alone proves a grant occurred; it does not prove the grant was used.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `Consent to application.` record with `IsAdminConsent` false and a delegated permission set, and its `SessionId` reappearing in workload audit records | Entra audit plus workload audit | Proves a user granted delegated consent and that tokens from that session were subsequently used against a workload |
| Same `SessionId` in an interactive sign-in and a non-interactive sign-in from a different network inside roughly ten minutes | Entra sign-in pair | Proves the authorization code was redeemed from a network other than the one that authenticated, which is the AiTM shape |
| `New-InboxRule` with `ForwardTo` or `RedirectTo` populated, correlated to the same `AADSessionId` as a preceding sign-in | Exchange mailbox audit | Proves the rule was created inside that authentication session and names the exfiltration destination |
| `MailItemsAccessed` with `MailAccessType` of `Sync` and a high `OperationCount` for one mailbox inside the session window | Exchange mailbox audit | Proves a bulk mailbox download occurred in that session; `Bind` entries separately indicate individual message reads |
| `Set-Mailbox` with `ForwardingSmtpAddress` populated and `DeliverToMailboxAndForward` true | Exchange mailbox audit | Proves server-side forwarding was configured, which survives password resets and client sign-out |
| `FileDownloaded` or `FileSyncDownloadedFull` carrying `AppAccessContext.AADSessionId` matching the suspect session | SharePoint or OneDrive audit | Proves file content left the tenant inside the same authentication session as the mailbox activity |

## Worked Contrast

**Weak / Noisy Practice:**

```powershell
# ANTI-PATTERN: one stream, one operation, no retention check, no session join.
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -Operations MailItemsAccessed -ResultSize 5000
# 5000 rows is the cap, not the total. No licence class recorded, no check that
# ingestion caught up, no SessionId join to sign-ins, and no non-interactive
# sign-in store searched. Conclusion: "the mailbox was read 5000 times."
```

**High-Signal Grounded Artifact:**

```powershell
# ual-session-pivot.ps1 — licence/retention gate, then session-scoped correlation.
param(
  [Parameter(Mandatory)][datetime]$Start,
  [Parameter(Mandatory)][datetime]$End,
  [Parameter(Mandatory)][string]$User,
  [string]$OutDir = "C:\case\ual"
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 0. Retention gate: state the boundary before trusting any absence.
$age = (Get-Date) - $Start
"window_start=$Start  age_days=$([math]::Round($age.TotalDays,1))" |
  Tee-Object "$OutDir\retention.txt"
if ($age.TotalDays -gt 180) {
  "WARNING: window exceeds the 180-day Audit (Standard) retention; non-E5 records are out of coverage" |
    Tee-Object "$OutDir\retention.txt" -Append
}

# 1. Pull the full operation set for the user, paging past the 5000-row cap.
$all = @(); $offset = 0
do {
  $batch = Search-UnifiedAuditLog -StartDate $Start -EndDate $End -UserIds $User `
             -ResultSize 5000 -SessionId "ual-$User" -SessionCommand ReturnLargeSet
  $all += $batch; $offset += $batch.Count
} while ($batch.Count -eq 5000 -and $offset -lt 50000)

$rows = $all | ForEach-Object { $_.AuditData | ConvertFrom-Json }
$rows | Group-Object Operation | Sort-Object Count -Descending |
  Select-Object Count, Name | Format-Table -AutoSize | Out-String |
  Tee-Object "$OutDir\operations.txt"

# 2. Session pivot: which operations share a session with a consent or sign-in?
$sessions = $rows | Where-Object { $_.AppAccessContext.AADSessionId } |
            Select-Object -ExpandProperty AppAccessContext |
            Select-Object AADSessionId, UniqueTokenId, IssuedAtTime -Unique

foreach ($s in $sessions) {
    $members = $rows | Where-Object { $_.AppAccessContext.AADSessionId -eq $s.AADSessionId }
    [pscustomobject]@{
        SessionId  = $s.AADSessionId
        Operations = ($members.Operation | Sort-Object -Unique) -join '; '
        FirstSeen  = ($members.CreationTime | Sort-Object | Select-Object -First 1)
        LastSeen   = ($members.CreationTime | Sort-Object | Select-Object -Last 1)
        ClientIPs  = ($members.ClientIP | Sort-Object -Unique) -join '; '
    }
} | Export-Csv "$OutDir\session_pivot.csv" -NoTypeInformation
```

**Why this matters:** the weak form mistakes a result cap for a total, never states the retention boundary, and never joins records across streams — so it can neither see a session nor notice that the window it queried was partly out of coverage. The strong form pages past the cap with `ReturnLargeSet`, prints the retention arithmetic before anything is interpreted, and produces one row per session carrying the operation set and the distinct client IPs, which is precisely the structure that separates an AiTM replay from ordinary use.

## When It Is NOT This Issue

- **A result set that stops at a round number:** `Search-UnifiedAuditLog` caps a single call, and a result of exactly 5000 or 50000 records is a truncation, not a total. Page with `ReturnLargeSet` before treating the set as complete.
- **An empty `MailItemsAccessed` result for a non-E5 mailbox outside a short window:** retention is 180 days by default for non-E5 users, and the licence in force at ingest governs each record. An empty result from a 200-day window is a retention outcome.
- **A session ID appearing with two client IPs:** mobile carriers, corporate proxies and cloud egress all change the observed origin inside one legitimate session. Require a network that does not belong to the user's normal set and a workload action timing consistent with attacker use before calling it replay.
- **A consent grant that was never used:** `Consent to application.` proves a grant was recorded. Without a matching `SessionId` in workload audit records, nothing establishes that the application acted on it.
- **Defender advanced-hunting queries returning nothing for an old window:** the table retains 30 days while a configured data lake may hold up to twelve years, and lake-only data is invisible to analytics rules. A rule-based zero from a long window reflects the store, not the tenant.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `Search-UnifiedAuditLog` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Retention arithmetic shown:** the window start, its age in days, and the applicable retention per affected user's licence class are recorded before any absence is interpreted.
- [ ] **Result completeness proven:** every query either paged past the platform cap with `ReturnLargeSet` or explicitly states the cap it hit.
- [ ] **Both sign-in stores searched:** interactive and non-interactive sign-ins were queried, and the join key used (`SessionId` rather than `UniqueTokenIdentifier`) is stated.
- [ ] **Session pivot produced:** each finding names a `SessionId`, the operations sharing it, and the distinct client origins observed within it.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: saas-workspace-and-entra-unified-audit-forensics
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`azure-and-entra-attacks`](../../../red-team/cloud-container-supply-chain/azure-and-entra-attacks/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)

## Operating Notes

- **Session first, operation second:** an operation list without session grouping cannot distinguish the user's own client from a replayed token, which is the single question BEC forensics exists to answer.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; audit exports contain message subjects, file names and personal data, so handle them under the case's data-handling rules.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
