---
name: path-traversal-and-lfi-log-and-cache-poisoning
description: Log and cache poisoning for inclusion. Covers planting payloads in access logs, mail spools, error logs and cache files, then including them, including log-rotation and format constraints. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["log poisoning", "log injection lfi", "access log payload", "mail log include"]
cwe: [CWE-22, CWE-98]
owasp: [A01:2021, A03:2021]
attack: [T1005]
capec: [CAPEC-126]
related: [path-traversal-and-lfi, path-traversal-and-lfi-encoding-bypass, path-traversal-and-lfi-php-wrappers, path-traversal-and-lfi-lfi-to-rce]
parent: path-traversal-and-lfi
---

# Path Traversal and LFI Log and Cache Poisoning - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)

## Mechanism and Preconditions

This variant is the write half of an inclusion-to-execution chain where the controllable artefact is a server-managed log or cache file. The Apache or Nginx access log records a request-controlled User-Agent or Referer, the error log captures malformed request lines and PHP warnings, the mail spool stores injected envelope fields, and FastCGI, opcache, or application cache files hold serialized responses. The attacker writes an inert payload into one of these files through its normal ingestion path, then uses a separate file-inclusion sink to interpret it. The decision point is whether the inclusion path is confined and whether the log format neutralizes control bytes; success also depends on rotation timing and on surviving the log's field delimiters intact.

- **Precondition chain:** a request field is written verbatim into a predictable server file (access or error log, mail spool, cache), a file-inclusion or templating sink can resolve that file's path, the log format does not encode or strip the payload's control characters, and rotation does not truncate the file before inclusion.
- **Readable differential:** include the candidate log before versus after planting the marker line; the finding holds when the included output changes only after the marker is written and reverts once the inclusion path is pinned or the log field is encoded.
- **Empirical grounding:** This maps to CWE-22 and CWE-98 under OWASP Top 10:2025 A01 Broken Access Control; SOURCES.md lists no log-and-cache-poisoning-specific advisory, so grounding stays at the CWE and OWASP class level without inventing a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to be a writable-log-plus-include chain **THEN** start at parent class [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) (1 hop) to confirm an include sink exists at all
2. **IF** the recorded field is a User-Agent or Referer in access.log versus a malformed request line in error.log **THEN** treat access.log and error.log as two different sinks because their escaping and format constraints differ
3. **IF** the write channel is an SMTP envelope stored in a mail spool **THEN** plant the marker through the mail path and include the spool file by its predictable path
4. **IF** the includable artefact is a FastCGI or opcache or application cache file **THEN** confirm the cache key is attacker-influenced before treating the cache entry as a writable sink
5. **IF** log rotation may truncate the file between write and include **THEN** time the include to the current log generation and account for the rotation interval
6. **IF** the log format escapes or encodes quotes and control bytes **THEN** test whether PHP open tags and delimiters survive the format before claiming interpretability
7. **IF** the write is confirmed but the interpret step is unverified **THEN** switch to [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) (1 hop) to prove the inclusion half
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)
9. **IF** no file-inclusion sink can resolve the poisoned file's path **THEN** STOP and record a verified non-finding; a poisonable log with no include is not this issue

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The interpret half is unproven and you need the full execution chain | [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) | Focus shifts from planting bytes to proving interpretation, a distinct step |
| The poisoned artefact is a shared HTTP cache entry rather than a log file | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | The invariant becomes cache keying, not inclusion of a filesystem log |
| You can write a file directly instead of poisoning a log | [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) | The control to fix is upload storage, not log format or inclusion |
| Need parent class methodology | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Identify the ingestion path that writes a request field into a server file, and name the file: access.log, error.log, mail spool, or a cache entry.
2. Classify the recorded field (User-Agent, Referer, request line, envelope-from) and read the log format to learn how quotes, newlines, and open tags are stored.
3. Capture a baseline read of the target file through the include sink before planting anything, so the differential is attributable to your marker line.
4. Plant an inert marker through the file's normal ingestion channel, then verify the marker survives the log's delimiters and encoding intact.
5. Define the baseline-versus-probe differential: include the file before and after the marker write; the included output must change only after the write and only because of your line.
6. Account for rotation: confirm the include targets the live generation of the file and that the write lands before truncation.
7. **Stop condition.** Stop when (a) the included output reflects the planted marker and reverts after encoding or path confinement, (b) the marker never appears because the format neutralizes it or no include resolves the path, or (c) proceeding would require writing an executing payload into a production log; (a) is confirmation of the write-plus-include chain, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a named log file whose included output gains your inert marker only after the ingestion write, plus the include line that resolves it, and the structural fix: encode log fields and move logs off every includable path, then confirm the marker returns as encoded text.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| User-Agent or Referer reflected verbatim into a readable access.log | Proves the access log is an attacker-writable sink on Apache or Nginx, pending an include that resolves its path |
| Malformed request line stored in error.log with control bytes intact | Proves the error log preserves injected delimiters, a usable write channel when access.log is encoded |
| SMTP envelope fields stored verbatim in a mail spool file | Proves the mail spool is a predictable write surface reachable through the mail path on Postfix or Sendmail hosts |
| Application or opcache cache file whose key is request-influenced | Proves a cache entry can be shaped and later included, distinct from an HTTP cache |
| Log rotation interval shorter than the write-to-include window | Proves a timing constraint that can invalidate the chain, so it bounds reliability rather than impact |
| PHP open tags surviving the log's quote and newline escaping | Proves the format does not neutralize the payload, the precondition for interpretation after inclusion |

## Worked Contrast

**Vulnerable pattern:**

```python
import logging

logger = logging.getLogger("access")

def record(req):
    # Raw request fields appended to a log that sits under the web-served template root.
    line = f'{req.remote_addr} "{req.headers.get("User-Agent", "")}" {req.path}'
    with open("/var/www/app/templates/access.log", "a") as fh:
        fh.write(line + "\n")
```

**Hardened pattern:**

```python
import json
import logging

logger = logging.getLogger("access")

def record(req):
    # Structured, encoded fields written outside any includable or templated path.
    entry = {
        "ip": req.remote_addr,
        "ua": req.headers.get("User-Agent", ""),
        "path": req.path,
    }
    with open("/var/log/app/access.jsonl", "a") as fh:
        fh.write(json.dumps(entry) + "\n")  # control bytes JSON-escaped, path non-includable
```

**Why this matters:** The defect writes a raw-field log inside the template root, so a file-inclusion sink can resolve and interpret it. The fix encodes every field as JSON, neutralizing PHP open tags and delimiters, and writes to a directory no inclusion or template loader can reach, removing the writable-then-includable surface.

## When It Is NOT This Issue

- **Encoded log fields:** a log that stores request values as JSON-escaped or percent-encoded text cannot carry live PHP tags, so inclusion returns inert data.
- **Logs outside the include root:** a poisonable log that no file-inclusion sink can resolve is not reachable for interpretation.
- **Rotation truncates first:** if the file rotates before the include runs, the planted line is gone and the chain does not complete.
- **No inclusion sink at all:** a log that records attacker input is only relevant when a dynamic include can target its path.
- **Cache entry that is keyed and isolated:** a cache file whose key the attacker cannot influence is not a controllable write surface.
- **WAF strips open tags at ingress:** a gateway that removes PHP markers from headers prevents the marker from ever reaching the log.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `path-traversal-and-lfi-log-and-cache-poisoning` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `path-traversal-and-lfi-log-and-cache-poisoning` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: path-traversal-and-lfi-log-and-cache-poisoning
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-22, CWE-98 | Mapping: T1005]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) - Blue Detection/Defense Counterpart
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)
- [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `path-traversal-and-lfi-log-and-cache-poisoning` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-22, CWE-98, T1005`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/ctf_search (3), OffsecCyber (2), CYBER_CPT/expku (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
