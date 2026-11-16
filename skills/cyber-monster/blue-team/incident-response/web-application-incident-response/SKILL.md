---
name: web-application-incident-response
description: "Responds to web application compromise: web shell discovery, access log analysis, source integrity checks and identifying the exploited vulnerability. Use when a web server or application is suspected compromised."
family: incident-response
tier: core
triggers: ["web incident response", "webshell incident", "web compromise", "application breach"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [web-application-incident-response-webshell-discovery, web-app-incident-access-log-exploitation-analysis, incident-response-playbooks, ir-triage-and-timeline]
---

# Web Application Incident Response - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`cross-site-scripting`](../../../red-team/web-and-application/cross-site-scripting/SKILL.md)

## Mechanism and Preconditions

A web application compromise is two incidents wearing one costume: what the operator placed on the tier, and what the operator did with it. The placement comes through something the application was supposed to allow — an upload handler, a template evaluator, a file-inclusion path, a deserialiser, an administrative console — and the use comes afterwards, as command execution under the service identity, data reads through the application's own database connection, or a second stage fetched outbound. The organising principle that keeps the response tractable is the distinction between entry at the edge and entry in the application tier: an edge-device entry means the tier was reached from outside through the appliance, and the appliance's configuration and session state are evidence; an application-tier entry means the request itself carried the exploit, and the request is the evidence. Both end at the same place — the service account's reachable credentials — which is why credential rotation is the containment step that matters more than file cleanup. The precondition that makes this class scoped rather than sprawling is knowing what the deployment process wrote: a release manifest, an image digest or a package hash list turns an unbounded file hunt into a finite diff.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves locating or analysing a placed file **THEN** switch to [`web-application-incident-response-webshell-discovery`](../web-application-incident-response-webshell-discovery/SKILL.md) (1 hop).
2. **IF** the target specifically involves reconstructing the exploited request **THEN** switch to [`web-app-incident-access-log-exploitation-analysis`](../web-app-incident-access-log-exploitation-analysis/SKILL.md) (1 hop).
3. **IF** the earliest corroborated artifact is an edge appliance — a WAF, load balancer, reverse proxy or CDN origin — **THEN** take the edge-entry branch: preserve the appliance configuration, its version and its sessions before any change, because a firmware update erases the state you need.
4. **IF** the earliest artifact is inside the application — a new file, a modified template, an unexpected child process — **THEN** take the app-tier branch and anchor on the artifact's ctime rather than on the alert time.
5. **IF** the tier authenticates to data stores, object storage or cloud roles **THEN** treat the application identity as compromised and enumerate its reachable credentials before deciding on rebuild, because a rebuilt host reuses the same identity.
6. **IF** the application serves user-uploaded or runtime-written content with executable extensions **THEN** prioritise that path over developer directories; it is where placed files actually land.
7. **IF** telemetry covering the request or file window is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`cross-site-scripting`](../../../red-team/web-and-application/cross-site-scripting/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `web-application-incident-response-webshell-discovery` | [`web-application-incident-response-webshell-discovery`](../web-application-incident-response-webshell-discovery/SKILL.md) | File-differential discovery and capability analysis |
| Target matches `web-app-incident-access-log-exploitation-analysis` | [`web-app-incident-access-log-exploitation-analysis`](../web-app-incident-access-log-exploitation-analysis/SKILL.md) | Request reconstruction and dwell window |
| Need the evidence classes and attestation queries | [`QUERIES.md`](QUERIES.md) | Deployment baseline, worker lineage, egress, source integrity |
| Need collection and integrity flags | [`TOOLS.md`](TOOLS.md) | Preserve the tier before any change |
| Need the entry-branch decision and sequencing | [`PLAYBOOK.md`](PLAYBOOK.md) | Edge versus app tier, identity scope, rebuild criteria |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Tier connects to cloud data planes | [`cloud-incident-response`](../cloud-incident-response/SKILL.md) | Identity containment across providers |
| Credentials must be revoked enterprise-wide | [`compromised-credentials-and-token-revocation-playbook`](../compromised-credentials-and-token-revocation-playbook/SKILL.md) | Revocation ordering without lockout |

## Procedure

1. **Confirm the evidence source for both the artifact and the request before concluding anything.** Enumerate the release manifest or image digest, the web-root file-integrity coverage, the access and error logs across their full rotation, and the worker process telemetry. Record which of these existed during the window. A web investigation missing any one of them can still reach a conclusion, but the conclusion must be labelled with the missing plane.
2. **Choose the branch from where the entry occurred.** Edge-entry when an appliance event precedes everything; app-tier when an application artifact does; identity-entry when a stolen application or administrative session precedes both. The branch determines whether you preserve appliance state, application files, or session tokens first, and those three have different lifetimes.
3. **Define the integrity differential against the deployment record.** Compare the current tier against the last known-good release by path and hash, then separately examine runtime-writable directories against their own content expectations. This produces a finite candidate set where a keyword scan produces an unusable one, and it is the only way to catch a shell concealed inside a legitimate file.
4. **Bound the dwell window and name the stop condition.** State the window from the earliest of the artifact ctime, the first request to its path, and the earliest worker child process. Stop and declare `Inconclusive` when the log rotation does not reach the anchor, when file-integrity monitoring was off for the served tree, when the worker's process telemetry has no retention across the window, or when the appliance's configuration was changed after the event so its state can no longer be inspected.
5. **State what counts as proof.** Proof of placement is a file whose hash differs from the release record, corroborated by a request or a write process. Proof of execution is a request plus a worker child process, or a response body containing command output. Proof of data access is the application identity's own query or object-read record. A placed file alone is capability, not compromise, and the report must use that distinction.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| File in the served tree whose hash differs from the release record | source integrity | Placement occurred on this host, with the ctime bounding the window |
| Worker process spawning a shell, downloader or scripting host | process lineage | Execution under the application identity, which converts capability into compromise |
| Access-log request to the placed path with repeated small 200s to one client | request history | Interactive use, and the client to scope the rest of the investigation around |
| Outbound connection from the tier to a destination absent from its 14-day history | network egress | Second-stage retrieval or output exfiltration |
| Application identity's read of a data store or object bucket outside its baseline | data access | Data loss rather than only code execution, which changes the obligation |
| Appliance configuration or session state altered inside the window | edge state | Whether the entry came through the appliance and whether it can be re-entered |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK: the investigation starts from the alert and trusts the alert's timestamp.
alert: "webshell detected" at 14:22
-> grep the last hour of access.log for "shell"
-> conclude "no evidence of exploitation"
# The file's ctime was three days earlier; the log rotation ended two days ago.
```

**High-Signal Grounded Artifact:**

```text
WEB TIER EVIDENCE PACKAGE — case IR-2026-0391

1  DEPLOYMENT BASELINE      release manifest web-2026.11.07, built 2026-11-07T22:10Z
                            image digest sha256:9f3c...  (recorded, not inferred)
2  FILE DIFFERENTIAL        untracked executables in served paths : 2
                            modified tracked files (hash mismatch) : 1
3  PROCESS LINEAGE          w3wp.exe -> cmd.exe /c whoami  at 2026-11-11T09:14:02Z
4  REQUEST ANCHOR           POST /uploads/avatar.aspx  202  at 2026-11-11T09:13:51Z
                            GET  /uploads/avatar.aspx  200  x17, one client, 09:14-09:41Z
5  EGRESS                   tier -> 198.51.100.7:443 at 09:15Z (absent from 14d baseline)
6  IDENTITY REACH            app pool identity -> sql-prod (read), blob-prod (write)
7  LIMITS                    FIM enabled 2026-11-09 (2 days of the window uncovered)
                            access logs retained 30d (window covered)
```

**Why this matters:** the strong form states which planes covered which interval and refuses to let an alert timestamp define the window, so the two-day FIM gap is visible in the same document as the findings; the weak form inherits the alert's time, searches an hour of one rotated file, and reports the absence of evidence it never had the coverage to find.

## When It Is NOT This Issue

- **A deployment outside the release pipeline:** a hotfix applied by hand, a config change by an engineer or a framework's own cache rebuild writes files the manifest does not know about. Confirm with the change record before treating an untracked file as placement.
- **A web application firewall alert that never reached the origin:** a blocked request is not exploitation. Confirm from the origin's own log that the request was processed, because WAF and origin logs disagree routinely under load.
- **Normal web traffic that looks like traversal:** percent-encoded slashes, `file` parameters and deep relative paths appear in legitimate rich-content and file-manager features. Decoding alone is not evidence.
- **An application-level error burst:** a bad release or a misconfigured dependency produces 5xx storms and unfamiliar stacks with no adversary. Check the deployment timeline before treating a spike as an attack.
- **A monitoring or backup agent scanning the web root:** agents that hash files, index content or take snapshots touch every file and spawn child processes from the tier. Exclude the agent inventory before ranking process-lineage matches.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude the tier is clean when file-integrity monitoring, access logging or worker process telemetry was absent for the window.**
- **NEVER present a placed file as proof of execution** — execution requires a request or a child process, and the label must match the evidence.
- **NEVER request a discovered shell's path or execute a recovered sample on any production or corporate-connected host.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Deployment baseline obtained:** the release manifest or image digest was used as the diff source, and its build time is stated.
- [ ] **Entry branch stated:** edge-entry, app-tier or identity-entry was identified from the earliest corroborated artifact and named.
- [ ] **Coverage stated per plane:** file integrity, access logs and process telemetry each have a stated coverage interval, and gaps are declared.
- [ ] **Identity reach enumerated:** the credentials, data stores and object buckets reachable by the application identity are listed as the rotation and scope set.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: web-application-incident-response
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`cross-site-scripting`](../../../red-team/web-and-application/cross-site-scripting/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`web-application-incident-response-webshell-discovery`](../web-application-incident-response-webshell-discovery/SKILL.md) - Incident Response (leaf)
- [`web-app-incident-access-log-exploitation-analysis`](../web-app-incident-access-log-exploitation-analysis/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`cloud-incident-response`](../cloud-incident-response/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-application-incident-response` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Blind spots to disclose:** file telemetry misses in-memory shells and appended code, access logs miss request bodies, and appliance logs miss what the origin did with the request. Every report should say which blind spot applied.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 26 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (10), CYBER_CPT/L5/ctf_search (7), CYBER_CPT/mitre_attack_enterprise (4), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
