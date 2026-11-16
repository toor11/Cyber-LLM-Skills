---
name: web-application-incident-response-webshell-discovery
description: Web shell discovery and analysis. Covers locating web shells through file integrity, log correlation and content review, then analysing their capability. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: incident-response
tier: leaf
triggers: ["webshell discovery", "find webshell", "web shell analysis"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [web-application-incident-response, web-app-incident-access-log-exploitation-analysis, incident-response-playbooks, ir-triage-and-timeline]
parent: web-application-incident-response
---

# Web Application Incident Response Webshell Discovery - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`file-upload-and-webshell`](../../../red-team/web-and-application/file-upload-and-webshell/SKILL.md)

## Mechanism and Preconditions

A web shell is a file inside the served tree that turns an HTTP request into code execution under the web server's identity. Its whole value is that it needs no listener, no beacon and no privileged binary: the request arrives on an allowed port, to an allowed path, carrying the command in a parameter or a body, and the response returns the output. That design defeats three of the most common detection surfaces at once — there is no malicious process to find until a child spawns, no anomalous port to flag, and no signature if the shell is a few hundred bytes of `eval`. Discovery therefore cannot rely on one plane. It works by correlating four: a file that appeared in a served directory outside the deployment process, a request to that path, a response whose size or timing matches command execution, and — critically — any child process the worker spawned. The precondition that makes discovery tractable is deployment knowledge: an organisation that knows exactly which files the release pipeline last wrote can enumerate everything else in the web root, and one that does not will be reduced to grepping for `eval` across ten thousand vendored files and finding nothing useful.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `web-application-incident-response-webshell-discovery` **THEN** start at parent class [`web-application-incident-response`](../web-application-incident-response/SKILL.md) first.
2. **IF** a file is found in a served directory that the release pipeline did not write **THEN** preserve and hash it before anything else, and treat the request history to that path as the dwell window.
3. **IF** the finding is a file only — no request to it, no child process, no matching access-log entry **THEN** take the dormant-shell branch: it is staged capability, not proof of execution, and the report must say which.
4. **IF** the worker spawned a child process — `sh`, `bash`, `cmd`, `powershell`, `curl`, `wget`, a scripting host **THEN** the shell executed and the host is compromised at the application identity's privilege level; pivot immediately to what that identity reaches.
5. **IF** the finding is a modification of a legitimate framework or plugin file rather than a new file **THEN** take the integrity-diff branch, because a clean file listing will not show it and hashes against a known-good release are the only reliable detector.
6. **IF** the application serves uploads, cache, session or vendor directories with executable extensions **THEN** prioritise that path — the majority of shells live where user content lands, not where developers work.
7. **IF** telemetry covering the web-tier window is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`file-upload-and-webshell`](../../../red-team/web-and-application/file-upload-and-webshell/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`web-application-incident-response`](../web-application-incident-response/SKILL.md) | Overall web compromise sequencing |
| Need the discovery and attestation evidence classes | [`QUERIES.md`](QUERIES.md) | File-vs-deployment diff, request history, worker lineage, response shape |
| Need hashing, string and integrity-diff flags | [`TOOLS.md`](TOOLS.md) | Describe a shell without executing it |
| Need the discovery-to-containment sequence | [`PLAYBOOK.md`](PLAYBOOK.md) | Order of preservation, scoping and credential rotation |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need to reconstruct the exploited request | [`web-app-incident-access-log-exploitation-analysis`](../web-app-incident-access-log-exploitation-analysis/SKILL.md) | The upload or injection that placed the file |
| Need to know what the app identity could reach | [`containment-and-eradication`](../containment-and-eradication/SKILL.md) | Blast radius from the service account |

## Procedure

1. **Confirm the evidence source for the file-population question before searching.** Establish what the release pipeline wrote and when — a deployment manifest, a container image digest, a package hash list, a build artifact record. Without it, every file in the web root is equally suspicious and the search produces an unranked list of thousands. Record whether file-integrity monitoring covers the web root and whether it was enabled during the window.
2. **Choose the branch from what the artifact population shows.** New-file branch when a file exists that the pipeline did not write. Modified-file branch when a pipeline file's hash differs from its released hash. Dormant branch when a file exists with no request history. Execution branch when a request and a worker child process both appear. Name the branch; each has a different containment consequence.
3. **Define the deployment-versus-artifact differential.** Compare the current web root against the last known-good release manifest by path and hash, and exclude the runtime-writable directories that are legitimately noisy — uploads, cache, sessions, logs — then examine those excluded directories separately against their own content-type expectations. The differential, not a keyword scan, is what produces a short defensible list.
4. **Bound the dwell window and name the stop condition.** The window opens at the earlier of the file's creation time and the first request to its path, and closes at containment. Stop and declare `Inconclusive` when the access log does not reach back to the file's creation time, when the application logs only errors and not successful requests, when the file's timestamps are unreliable because the filesystem was restored or the file was deliberately touched, or when no deployment manifest exists to diff against.
5. **State what counts as proof.** Proof of a web shell is a served file whose content contains command execution under the application runtime, corroborated by either a request to that path in the access log or a worker child process in endpoint telemetry. Proof of execution is the request plus the child process together, or a response body that contains command output. A file match alone is proof of staged capability and must be reported as such, not as compromise.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| File in a served path absent from the release manifest, with its creation timestamp | file integrity | Staged capability; the creation time bounds the dwell window from above |
| Access-log request to that exact path, with status, size and user agent | request history | The shell was addressed; repeated small responses to one client indicate interactive use |
| Worker process spawning a shell, downloader or scripting host | process lineage | Execution occurred under the application identity, which is compromise rather than staging |
| Hash mismatch on a legitimate framework or plugin file against its released hash | integrity diff | The shell is concealed inside a file that a listing would consider normal |
| Request with a parameter whose decoded value is a command or a base64 blob | request content | The command channel, which is the difference between a scanner hit and a live shell |
| Outbound connection from the web tier to an unfamiliar destination after the request | network egress | Post-exploitation staging; the shell fetched a second stage or exfiltrated output |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`file integrity`):**

```bash
# ANTI-PATTERN: grep for shell keywords across the whole web root.
# Every vendored library, minified bundle and framework test file matches.
grep -rIl -E 'eval\(|system\(|shell_exec|passthru' /var/www/
```

**Behavior-Anchored Detection & Guarded Triage (`file integrity` — CWE-778):**

```bash
# Differential first: what exists now that the release did not write?
set -euo pipefail
WEBROOT="${WEBROOT:-/var/www/app}"
MANIFEST="${MANIFEST:?path to the last known-good release manifest (path<TAB>sha256)}"
OUT="${OUT:-./webshell-candidates.txt}"

# 1. Files not in the manifest at all — the highest-value set.
find "$WEBROOT" -type f -printf '%P\n' | sort > /tmp/present.txt
cut -f1 "$MANIFEST" | sort > /tmp/released.txt
comm -23 /tmp/present.txt /tmp/released.txt > /tmp/untracked.txt

# 2. Files in the manifest whose hash changed — the harder set to notice.
while IFS=$'\t' read -r rel want; do
  [ -f "$WEBROOT/$rel" ] || continue
  got="$(sha256sum "$WEBROOT/$rel" | cut -d' ' -f1)"
  [ "$got" = "$want" ] || printf 'MODIFIED\t%s\n' "$rel"
done < "$MANIFEST" > /tmp/modified.txt

# 3. Rank candidates: untracked files in executable-served paths first.
awk -F/ '{n=split($0,a,"/"); print a[n]"\t"$0}' /tmp/untracked.txt |
  grep -E '\.(php|phtml|phar|jsp|jspx|aspx|ashx|asmx|cfm|cgi|pl|py|rb)$' |
  sort > "$OUT" || true

printf 'untracked=%s modified=%s executable_candidates=%s\n' \
  "$(wc -l < /tmp/untracked.txt)" "$(wc -l < /tmp/modified.txt)" "$(wc -l < "$OUT")"
printf 'State web-root FIM coverage and the deployment manifest timestamp before interpreting.\n'
```

**Why this matters:** the strong form derives its candidate set from what the deployment process did and did not write, so every row is defensible and short enough to review by hand, and it separates modified legitimate files from new files because the two require different detection; the weak form matches keywords that appear throughout legitimate software and produces a list nobody can act on.

## When It Is NOT This Issue

- **Legitimate framework and plugin files:** `eval`, `system` and dynamic include patterns appear throughout WordPress plugins, templating engines and code generators. Diff against released hashes before treating a keyword match as a shell.
- **Developer leftovers in a shared or staging directory:** a `test.php`, a `phpinfo()` page or a debug endpoint left by an engineer is a hygiene finding, not a compromise. Check the file's author, deployment context and whether the environment is production.
- **A monitoring or health probe:** uptime checkers and APM agents often request PHP paths in upload or cache directories, which mimics the access-log signature of a shell. Verify the user agent and source against the monitoring inventory.
- **A file that changed because of a legitimate runtime write:** session files, compiled template caches and log rotation all modify files in the served tree. Exclude runtime-writable paths from the modified-file set before ranking.
- **A WAF block that looked like success:** a request to a shell path returning 403 is a blocked attempt, not execution; confirm the status code and whether the origin ever received the request.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude the web tier is clean when file-integrity monitoring, access logging or worker process telemetry was absent for the window.**
- **NEVER present a file match as proof of execution** — execution requires a request or a child process, and the report must distinguish the two.
- **NEVER execute a discovered shell, or issue a request to its path, to "confirm" it works** on any production or corporate-connected host.
- **NEVER delete a discovered shell before hashing, copying and capturing the request history** — the artifact is the evidence.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Deployment baseline obtained:** the last known-good release manifest or image digest was used as the diff source, and its timestamp is stated.
- [ ] **Coverage confirmed:** web-root file integrity monitoring, access logging and worker process telemetry each have a stated presence or absence for the window.
- [ ] **Differential performed:** untracked and modified files were separated, and runtime-writable directories were examined against their own content expectations.
- [ ] **Execution state stated:** each finding is labelled staged or executed with the specific artifact that supports the label.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: web-application-incident-response-webshell-discovery
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`file-upload-and-webshell`](../../../red-team/web-and-application/file-upload-and-webshell/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`web-application-incident-response`](../web-application-incident-response/SKILL.md) - Incident Response (core)
- [`web-app-incident-access-log-exploitation-analysis`](../web-app-incident-access-log-exploitation-analysis/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-application-incident-response-webshell-discovery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Detection blind spot to disclose:** file telemetry cannot see an in-memory shell or code appended to a file that already existed legitimately, and access logs cannot see a request body. A clean result from both is weaker than it appears and must be described that way.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 10 |
| Top sources | cyber-security/CyberSec-Dataset (2), CYBER_CPT/hacktricks (2), SecEval/owasp_mastg (1), SecEval/d3fend (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 1 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
