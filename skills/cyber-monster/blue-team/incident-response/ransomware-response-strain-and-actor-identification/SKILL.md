---
name: ransomware-response-strain-and-actor-identification
description: Ransomware strain and actor identification. Covers identifying the family from artefacts and notes, mapping to known actor playbooks and anticipating next moves. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: incident-response
tier: leaf
triggers: ["ransomware strain", "ransom note analysis", "actor identification ransomware"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [ransomware-response, ransomware-response-containment-and-scoping, ransomware-response-recovery-and-restore, incident-response-playbooks]
parent: ransomware-response
---

# Ransomware Response Strain and Actor Identification - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Strain identification matters to a victim for one reason only: it predicts what the operator has probably already done, so containment and recovery can be ordered against the family's known behaviour instead of against a generic checklist. A family name is an inference from correlated artifacts — an extension appended to filenames, a note filename and its structure, a service name, a mutex, a driver component, a leak-site naming convention — and those artifacts overlap between families and get copied between affiliates. The correct posture is therefore hypothesis-then-corroboration: match multiple independent artifacts, test the hypothesis against what the family is documented to do, and confirm or discard it by checking whether that predicted behaviour is present in your own telemetry. The precondition is preserved artifacts. A note deleted by a helpful administrator, an encrypted sample overwritten by a restore, or a binary quarantined and purged is an identification opportunity destroyed; preserving them costs nothing and is the only thing that makes family attribution possible at all.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `ransomware-response-strain-and-actor-identification` **THEN** start at parent class [`ransomware-response`](../ransomware-response/SKILL.md) first.
2. **IF** only one artifact class matches a family — an extension, or a note filename, both without corroboration **THEN** label the result a hypothesis and seek a second independent artifact class; extensions are the most copied and least reliable single indicator.
3. **IF** the match is against a current #StopRansomware advisory — Medusa (AA25-071A), Gunra (AA26-222A), SafePay (AA26-293A) — **THEN** use that advisory's documented behaviour as the prediction set and look for each predicted behaviour in your own telemetry before accepting the attribution.
4. **IF** the notes differ in structure across hosts **THEN** consider two distinct deployments rather than one, and scope them separately; a second operator on the estate changes containment entirely.
5. **IF** the identity matters only for reporting and notification **THEN** stop at the evidence-supported level and record the confidence; do not spend containment time on attribution that does not change a decision.
6. **IF** the family is identified and it is documented to exfiltrate before encryption **THEN** treat the exfiltration question as already live and route it to [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/SKILL.md) rather than waiting for the note's claim to be assessed.
7. **IF** telemetry covering the artifact-discovery window is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`ransomware-response`](../ransomware-response/SKILL.md) | Onset clock and disclosure routing |
| Need the artifact and corroboration evidence classes | [`QUERIES.md`](QUERIES.md) | Extension inventory, note structure, predicted-behaviour checks |
| Need hashing, string and sample-handling flags | [`TOOLS.md`](TOOLS.md) | Preserve and describe artifacts without executing them |
| Need the attribution decision matrix | [`PLAYBOOK.md`](PLAYBOOK.md) | Confidence levels and when attribution changes an action |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Family known, need scope | [`ransomware-response-containment-and-scoping`](../ransomware-response-containment-and-scoping/SKILL.md) | Containment breadth per predicted behaviour |
| Family documented to exfiltrate first | [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/SKILL.md) | Exfiltration attestation and disclosure routing |

## Procedure

1. **Confirm the evidence source before interpreting any artifact.** Enumerate which artifact classes actually exist: a preserved note file, an encrypted sample with its original name recoverable, a binary in quarantine, endpoint telemetry for the encrypting process, and directory-listing history for the extension inventory. A family name derived from a note filename alone is a guess wearing a label.
2. **Choose the branch from the artifact mix.** Artifact-rich when a binary, a note and endpoint telemetry all exist — identify from binary characteristics and confirm from behaviour. Artifact-poor when only notes and extensions survive — restrict the claim to a family-compatible hypothesis and record what would have been needed. Single-host when the estate appears to hold one deployment; multi-deployment when note structure or extensions differ across hosts.
3. **Define the corroboration differential.** For each candidate family, write down two or three behaviours it is documented to perform — a specific persistence shape, a specific discovery tool, a specific egress channel — and check whether each is present in your telemetry inside the intrusion window. A candidate that predicts three behaviours you can confirm outranks one that matches a filename.
4. **Bound the claim and name the stop condition.** State the highest confidence the available artifacts support. Stop and declare `Inconclusive (Identification)` when only the extension matches, when the note is a generic template reused across families, when the sample is too damaged to yield strings or a hash, or when two candidates predict the same observed behaviour equally well.
5. **State what counts as proof.** Proof of family is at least two independent artifact classes agreeing, plus at least one documented behaviour confirmed present in your own telemetry. Proof of a second deployment is a structural difference in the note or a disjoint extension set across host groups. Proof of exfiltration-first is a completed transfer record, not a family's reputation — reputation tells you where to look, not what happened.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Extension appended to filenames, compared against the pre-incident estate inventory | artifact | A family-compatible marker; on its own it is a hypothesis because extensions are widely copied |
| Note filename plus its internal structure and contact mechanism | artifact | Family-compatible template; structural differences across hosts suggest more than one deployment |
| Binary hash, service name or mutex from the encrypting process | artifact | A concrete identity anchor that can be matched against advisory indicators |
| Documented family behaviour confirmed in local telemetry (persistence shape, discovery tool, egress channel) | behavioural corroboration | Turns an artifact match into a supported attribution |
| Completed outbound transfer before onset, for a family documented to double-extort | network egress | Data left before encryption; a disclosure question independent of the family label |
| Disjoint extension sets or differing note structures across host groups | deployment boundary | Two operators or two stages, which changes containment scope |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK: "the note filename matches a known family, so we know who it is"
# No hash, no second artifact class, no behavioural check, no sample preserved.
filename: "README_RESTORE.txt" -> family = <candidate>
```

**High-Signal Grounded Artifact:**

```powershell
# Preserve first, describe second, corroborate third. Read-only throughout.
$case = ".\case\strain"
New-Item -ItemType Directory -Force -Path $case | Out-Null

# 1. Preserve the artifacts before anything else is done to them.
$notes = Get-ChildItem -Path C:\ -Recurse -File -Include *README*,*RESTORE*,*DECRYPT* `
             -ErrorAction SilentlyContinue | Select-Object -First 3
$notes | ForEach-Object {
    $h = Get-FileHash $_.FullName -Algorithm SHA256
    Copy-Item $_.FullName (Join-Path $case "note-$($h.Hash.Substring(0,12)).txt") -Force
    [pscustomobject]@{ Path=$_.FullName; Sha256=$h.Hash; Size=$_.Length }
} | Export-Csv -NoTypeInformation "$case\notes.csv"

# 2. Describe the extension set against the pre-incident inventory, not in isolation.
$pre  = Import-Csv ".\case\ext-before.csv"
$post = Import-Csv ".\case\ext-after.csv"
$post | Where-Object { $_.Name -notin $pre.Name } |
    Export-Csv -NoTypeInformation "$case\new-extensions.csv"

# 3. Corroborate: a family claim needs a behaviour, not just a filename.
#    Check whether the predicted persistence shape exists in your own telemetry.
Get-Service | Where-Object { $_.Status -eq 'Running' -and -not $_.PSStartName } |
    Select-Object Name, DisplayName, BinaryPathName |
    Export-Csv -NoTypeInformation "$case\unusual-services.csv"
```

**Why this matters:** the strong form preserves the artifacts before touching them, derives the extension set from the estate's own prior inventory, and demands a behavioural corroboration before any family is named; the weak form matches one filename against a public list and produces a label that will be quoted in a notification as though it were established fact.

## When It Is NOT This Issue

- **A note without encryption:** a hoax, a scareware artifact, a leftover from an earlier incident or an insurance-fraud attempt. A note is a claim by an unverified party; the file state is the evidence.
- **A shared extension across families:** several families append the same short suffix, and affiliates reuse another family's note template. An extension match with no second artifact class is not an identification.
- **A legitimate application-level encryption feature:** whole-disk encryption, database transparent encryption, or an archiver's native format changes filenames and content without any actor. Compare against the sanctioned-encryption baseline for the estate.
- **A quarantine that renamed files:** an endpoint agent quarantining and renaming a widely deployed binary produces an unfamiliar extension across many hosts with a clean action log. Read the agent's own quarantine record.
- **Attribution pressure from outside:** an insurer, a customer or a journalist may arrive with a family name already asserted. Treat that as a hypothesis to test against preserved artifacts, never as an input to your report.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER name a family from a single artifact class** — a filename or extension match is a hypothesis and must be labelled as one.
- **NEVER attribute to a named group or individual from technical artifacts alone** — report family-level compatibility and the confidence it carries.
- **NEVER execute, unpack or run a recovered sample outside an isolated analysis environment**, and never on the host under investigation.
- **NEVER conclude a host or tenant is clean when telemetry covering the artifact-discovery window was disabled, rotated out, or uncollected.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Artifacts preserved:** at least one note and one encrypted sample were hashed and copied off-host before any cleanup action.
- [ ] **Multiple classes checked:** the claim rests on at least two independent artifact classes, or is explicitly labelled single-class.
- [ ] **Behaviour corroborated:** at least one documented family behaviour was searched for in local telemetry, and the result is stated whether found or not.
- [ ] **Confidence bounded:** the output states what would raise or lower the identification confidence, and does not present attribution as fact.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: ransomware-response-strain-and-actor-identification
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`ransomware-response-containment-and-scoping`](../ransomware-response-containment-and-scoping/SKILL.md) - Incident Response (leaf)
- [`ransomware-response-recovery-and-restore`](../ransomware-response-recovery-and-restore/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ransomware-response-strain-and-actor-identification` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Victim-side scope:** artifact preservation and family-level characterisation for reporting only. No actor contact, no attribution to named persons, no negotiation content.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/ctftime (6), CYBER_CPT/gh_security_lab (2), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
