---
name: zip-slip-and-archive-extraction-attacks
description: Audits archive extraction routines (ZIP, TAR, 7z, APK, Helm/OCI layers) for Zip-Slip path traversal, symlink/hardlink escape, decompression bombs, and tar header confusion. Use when an application unpacks user-supplied archives.
family: web-and-application
tier: leaf
triggers: ["zip slip", "tar symlink escape", "archive traversal", "decompression bomb", "extractall vulnerability"]
cwe: [CWE-22, CWE-409]
owasp: [A01:2021]
attack: []
capec: []
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Zip Slip and Archive Extraction Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

An archive extractor walks each stored entry and builds an output path by joining the entry name to a destination directory, then writes the entry's bytes there. The security decision is whether the final resolved path still sits inside the intended extraction root, and that decision is made (or skipped) at the moment the destination path is computed, not when the archive is parsed. Three distinct defects break it: an entry name that is absolute or carries `../` segments so the join climbs out of the root; a symlink or hardlink member whose target points outside the root, through which a later regular entry is then written; and a validate-then-canonicalise ordering bug where the containment check runs on the raw name before normalisation rewrites it into an escaping path. The attacker gains an arbitrary file write, or through a planted link an arbitrary read, at a location the application never intended, which on a web-served or configuration directory escalates to code execution or privilege change. Nothing about the archive bytes is malformed; the extractor simply trusts entry metadata it should have resolved and contained.

- **Precondition chain:** The application unpacks an attacker-supplied archive, the extractor joins each entry name or follows each link member against a destination without resolving the final path back to that root, and the extracting process has permission to write to or read the location the escaping entry reaches.
- **Readable differential:** An archive whose entries all resolve under a benign subfolder extracts entirely inside the root, while an otherwise identical archive carrying one parent-relative, absolute, or symlinked entry lands a benign marker outside it; adding a resolve-the-path-against-the-root check keeps both archives contained, which proves the escape came from missing canonicalisation rather than from the archive bytes.
- **Empirical grounding:** CWE-22 and CWE-23 cover the path-escape modes and CWE-409 the decompression-amplification mode; OWASP Top 10:2025 files archive traversal under A01 Broken Access Control. Disclosed 2025 cases anchor each mode: CVE-2025-3445 and CVE-2025-4748 for absolute and parent-relative name escapes, CVE-2025-55188 and GHSA-94vh-gphv-8pm8 for symlink-based writes, and CVE-2025-32103 for a UNC-path escape.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an archive entry name contains `../` segments, a leading `/`, a `C:\` drive, or a `\\server\share` UNC prefix that climbs out of the extraction root **THEN** treat it as the name-escape failure mode and drive the resolve-against-root fix before testing the other two modes
2. **IF** an archive entry is a symbolic or hard link whose target points outside the extraction root and a later entry is written through that link **THEN** treat it as the symlink-escape failure mode and defer or refuse link creation until every regular entry is written
3. **IF** the extractor validates the raw entry name and only afterwards calls `realpath`, `Path.resolve`, or `normpath` **THEN** treat it as the validate-then-canonicalise ordering bug and move the containment check onto the resolved path
4. **IF** the archive is a TAR whose header carries an absolute `name` or a `..`-prefixed `linkname` **THEN** inspect the tar member typeflags, since GNU and PAX link targets carry escape metadata the flat ZIP model lacks
5. **IF** the extraction root is a web-served or upload directory where an escaped file could be executed **THEN** also read [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) (1 hop) because the escaped write becomes an execution-context finding
6. **IF** the archive is an OCI image layer, Helm chart, or APK consumed by an automated pipeline rather than an interactive upload **THEN** assess the extractor the pipeline invokes, since the same containment invariant applies without a request-derived input
7. **IF** a single small entry inflates to an enormous output or the archive is deeply nested **THEN** switch to the decompression-amplification (CWE-409) check and cap the output size and ratio rather than the entry name
8. **IF** the user asks how to detect, hunt, or remediate archive-extraction escapes **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every entry resolves inside the extraction root after canonicalisation and no link member escapes it **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Extraction root is a web-served or upload directory where an escaped file becomes executable | [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) | Routes to the execution-context invariant: the escape is only a write, and impact comes from the file being served and run |
| A path escape on an appliance is chained into command execution through the written file | [`os-command-injection`](../os-command-injection/SKILL.md) | Routes to the command-execution invariant where the dropped file feeds a shell, a distinct control from extraction containment |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the extraction call and the destination join.** Find where the code iterates archive members and builds an output path, typically `os.path.join(dest, entry.name)`, `ZipEntry.getName()`, `tarfile.extractall`, or a library `Unarchive` call. Record whether the final path is resolved with `realpath` or `Path.resolve` and compared to the root, or written directly.
2. **Classify the failure mode from the archive, not a guess.** Read three things per entry: the raw name for `..` segments, leading slashes, or a drive/UNC prefix; the member type for symlink or hardlink flags and its link target; and whether the code's validation runs before or after canonicalisation. Each observation maps to exactly one of the three modes.
3. **Build a paired baseline archive.** Create one archive whose entries all resolve under a benign subfolder of the extraction root and record where every file lands. This containment baseline is what a probe must visibly break, and it is the reference the fix must preserve.
4. **Choose the probe that matches the observed mode.** For a name-escape sink add one entry named `../<marker>`; for a link sink add a symlink member pointing to a sibling directory plus a later regular entry written through it; for an ordering bug supply a name that only escapes once normalised. Send the single probe the code path can actually reach.
5. **Differential on where the byte lands, not on whether a string was blocked.** Extract the baseline and the probe into fresh disposable roots and compare the resulting file trees. The signal is a benign marker appearing outside the extraction root, or a benign file readable through a link the archive created; a rejected entry or an in-root landing is not.
6. **Stop condition.** Halt when the probe (a) places or exposes the marker outside the extraction root and that stops once the extractor resolves each entry against the root, (b) leaves every entry contained across two independent baselines, or (c) would require overwriting a real system file to demonstrate. Case (a) confirms, (b) is a non-finding, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is the resolved absolute path of the escaping entry plus the on-disk location of the benign marker outside the root, tied to the exact member and the source line that joins name to destination without a containment check. A tool warning or a `..` visible in a listing is not proof; the marker must actually land or be readable outside the root and stop doing so once the fix is applied.
8. **Apply the structural fix per mode.** Resolve each entry against the canonical destination root and reject any result whose resolved path is not a descendant of it; refuse absolute, drive, and UNC names; and defer or refuse symlink and hardlink members until every regular entry is written, dropping links whose target leaves the root. Do not rely on stripping `..` from the raw string.
9. **Verify the fix against the same probes.** Re-run the name-escape, link, and ordering probes against the patched extractor and confirm every entry now lands inside the root and link members with external targets are refused, while the benign baseline still extracts unchanged.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An entry name beginning with `/`, `C:\`, or `\\server\share` reaching the destination join | Proves an absolute or UNC path-escape sink on Windows extractors and transfer tools such as CrushFTP, where the drive or share prefix discards the destination root entirely |
| `os.path.join(dest, member.name)` or `ZipEntry.getName()` written with no subsequent resolved-path containment check | Proves the classic Zip-Slip name escape on Python `tarfile`, Java `ZipInputStream`, and Go archiver libraries, because the join preserves a `..` prefix that climbs out of the root |
| A tar member whose typeflag marks a symlink or hardlink with a `linkname` pointing outside the extraction root | Proves the symlink-escape mode on POSIX tar and 7-Zip extractors, where a later entry written through the created link lands at the external link target |
| Validation of the raw entry string that runs before `Path.resolve` or `normpath` is ever called | Proves the validate-then-canonicalise ordering bug on any stack, since the check inspects a name that later normalisation rewrites into an escaping path |
| A Rust `zip` crate, Erlang `zip:unzip`, or mholt archiver call extracting without per-entry containment | Proves the traversal invariant is missing at the extraction-library layer rather than in application glue code, so the fix belongs in or around the unpack call itself |
| A single archive entry whose decompressed size dwarfs its stored size, or an archive nested many layers deep | Proves a decompression-amplification exposure (CWE-409) rather than a path escape, affecting any extractor that does not cap output size or ratio |
| An extraction root that is itself a web-served, cron, or interpreter-enabled directory | Proves that a successful escape or even an in-root write becomes an execution-context finding on any server that runs files from that tree |

## Worked Contrast

**Vulnerable pattern:**

```python
import tarfile


def extract(archive_path, dest):
    # extractall honours absolute names, '..' prefixes, and symlink members
    # exactly as stored, so a single crafted entry can land outside dest
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest)
    return dest
```

**Hardened pattern:**

```python
import os
import tarfile


def extract(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        safe = [m for m in tar.getmembers() if not (m.issym() or m.islnk())]
        for member in safe:
            resolved = os.path.realpath(os.path.join(root, member.name))
            if resolved != root and not resolved.startswith(root + os.sep):
                raise ValueError("archive entry escapes extraction root: " + member.name)
        tar.extractall(root, members=safe)
    return root
```

**Why this matters:** The vulnerable version calls extractall, which writes absolute names, parent-relative prefixes, and symlink members as stored, so one crafted entry escapes dest. The fix canonicalises each entry against the resolved root, rejects any member whose resolved path is not a descendant of it, and drops link members so a later entry cannot be written through a created link. Containment is decided on the resolved path, not on the raw name.

## When It Is NOT This Issue

- **Containment already enforced on the resolved path:** the extractor calls `realpath` on each joined entry and rejects anything that is not a descendant of the root. A `..` visible in the archive listing is harmless once the resolved path is checked.
- **Trusted, self-generated archives:** a backup or export produced by the application itself and never influenced by an attacker is out of scope even if the extractor is naive. The archive source must cross a trust boundary.
- **Marker still landed inside the root:** an entry with `..` segments that resolves back under the extraction root (because the path has enough leading components) is contained; only a byte that lands outside the root is a finding.
- **Link member refused by the extractor:** a library configured to skip or error on symlink and hardlink entries is safe, and a `linkname` in the archive is not proof unless a later entry is actually written through a created link.
- **Decompression bomb mistaken for traversal:** a resource-amplification entry (CWE-409) stresses memory or disk but never escapes the root. It is a different invariant with a different fix (size and ratio caps), not a path escape.
- **Extraction into a per-request disposable sandbox:** output written to a throwaway tmpdir that is deleted and never served, with symlink following disabled, has no cross-boundary impact.
- **Platform-inert prefix:** a Windows drive or UNC prefix in an archive extracted only on POSIX, or a POSIX absolute path on an extractor that strips the leading slash, may not escape; confirm on the actual target OS before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `zip-slip-and-archive-extraction-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `zip-slip-and-archive-extraction-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: zip-slip-and-archive-extraction-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-22, CWE-409 | Mapping: A01:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `zip-slip-and-archive-extraction-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-22, CWE-409`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 1 |
| Top sources | OffsecCyber (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | multi-dataset corpus-grounded |
