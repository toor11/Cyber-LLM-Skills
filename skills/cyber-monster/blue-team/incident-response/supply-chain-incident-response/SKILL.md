---
name: supply-chain-incident-response
description: "Responds to supply chain compromise: identifying affected versions, blast radius across consumers, coordinated disclosure and rebuild strategy. Use when a dependency or vendor is compromised."
family: incident-response
tier: leaf
triggers: ["supply chain incident", "dependency compromise response", "vendor breach"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-437]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Supply Chain Incident Response - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

A supply-chain compromise differs from every other incident class in one structural way: the malicious artifact arrived through a channel you deliberately authorised. That inverts the usual response logic. The package was not smuggled past a control; it was installed by a build pipeline with legitimate credentials, at a version that a lockfile pinned, on a runner whose entire purpose was to hold secrets. The consequence is that the blast radius is not where the code executed but where the credentials and identity material it could reach during install are valid — a single `preinstall` hook on a CI runner can reach cloud roles, registry tokens, SSH keys, Vault paths and OIDC trust, and removing the package afterwards removes nothing that was already taken. The 2026 Shai-Hulud / ChainDrop npm campaign is the clearest recent illustration: a hijacked maintainer account republished hundreds of packages whose install hook harvested credentials and used stolen publish tokens to propagate itself further, so the response question was never "did the malicious code run" but "which runners executed an install and what could that identity reach".

The precondition that makes this class containable is an inventory that can answer "which version, where, on what identity" from a record rather than from memory — a bill of materials, a lockfile corpus and CI run history going back far enough to cover the campaign's publication dates.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an affected version appears in any lockfile **THEN** treat every environment that could install from that lockfile — developer workstation, CI runner, build agent, container image, artifact cache — as credential-exposed, not merely code-exposed.
2. **IF** a CI runner executed an install of an affected version **THEN** take the identity-first branch: enumerate the runner's federated and stored credentials and rotate from a known-clean machine before rebuilding anything.
3. **IF** only developer workstations are affected **THEN** take the endpoint-first branch but include browser sessions, package-manager tokens and SSH agents in the credential set; a workstation holds more standing access than a runner.
4. **IF** the compromise is at a vendor rather than a public registry **THEN** take the vendor-evidence branch: obtain the vendor's affected-version list and timeline in writing, and reconcile it against your own inventory rather than accepting it as complete.
5. **IF** the malicious artifact reached a published container image or release **THEN** treat downstream consumers as a disclosure question and route it to [`legal-and-regulatory-notification`](../legal-and-regulatory-notification/SKILL.md) once the affected set is known.
6. **IF** a newer version is available **THEN** do not assume it is clean — campaigns republish repeatedly, and the safe pin is the last version published before the campaign window, verified by hash.
7. **IF** telemetry covering the install window is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the inventory, install-window and persistence evidence classes | [`QUERIES.md`](QUERIES.md) | Lockfile resolution, runner install events, persistence artifacts |
| Need package-manager and SBOM inspection flags | [`TOOLS.md`](TOOLS.md) | Enumerate resolution without installing anything |
| Need the rebuild and rotation sequencing | [`PLAYBOOK.md`](PLAYBOOK.md) | What rotates before what rebuilds |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Downstream consumers affected | [`legal-and-regulatory-notification`](../legal-and-regulatory-notification/SKILL.md) | Coordinated disclosure and obligation routing |
| Need the identity evidence for the build system | [`cloud-incident-response-identity-containment`](../cloud-incident-response-identity-containment/SKILL.md) | Federated credential and session revocation |
| Evidence must survive scrutiny | [`evidence-handling-and-chain-of-custody`](../evidence-handling-and-chain-of-custody/SKILL.md) | Preserving build logs and artifact hashes |

## Procedure

1. **Confirm the evidence source before believing an advisory's scope.** Enumerate what can answer the inventory question: lockfiles per repository, SBOMs per image, the CI run history, the artifact proxy's download log, and container registry manifests. An advisory states what the vendor published; only your own records state what you resolved and when. Record the coverage window of each source, because a campaign published before your CI history begins is unanswerable from CI.
2. **Choose the branch from where the artifact executed.** Runner-first when a build system installed it — the identity reachable from that runner is the blast radius. Workstation-first when only developer machines did — sessions and standing tokens are the blast radius. Image-first when it was baked into a published image — downstream consumers are the blast radius. Name the branch.
3. **Define the resolution-versus-execution differential.** Compare, per repository, the versions resolved in lockfiles against the versions the artifact proxy actually served, and against the install-script execution events on each runner. A package present in a lockfile but never fetched from the proxy was resolved and not installed; a package fetched but with install scripts disabled executed no code. The three states require different responses and are routinely conflated.
4. **Bound the window and name the stop condition.** State each campaign's publication window from a source you actually read, and the last clean pin. Stop and declare `Inconclusive` when the CI history does not reach back to the campaign window, when install scripts were enabled but execution auditing was off, when the proxy log retention is shorter than the window, or when the artifact was pulled from a cache whose contents cannot be enumerated.
5. **State what counts as proof.** Proof of exposure is a proxy or registry record showing the affected artifact was fetched by a specific identity inside the campaign window, corroborated by a lockfile resolution. Proof of credential misuse is an authentication or API call by a credential that identity could read, from a location or at a time that does not match its baseline. A lockfile entry alone proves resolution, not execution, and must be reported as resolution.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Lockfile entry pinning an affected version, with the resolve timestamp | dependency record | The version was selected; it does not prove the install hook executed |
| Artifact proxy record showing the tarball served to a named runner identity | package fetch | The malicious artifact reached that environment and that identity could reach its credentials |
| Install-hook child process on a runner (node spawning a script, a shell, or a downloader) | process telemetry | The payload executed, which is the difference between exposure and compromise |
| New file in an IDE or agent configuration path referencing an unexpected command | persistence artifact | The payload left a re-execution mechanism behind, so removal alone is insufficient |
| Stolen publish token used to republish another package | registry audit | Propagation occurred through your identity, which obliges registry-side notification and token revocation |
| Credential inventory reachable from the affected identity | identity record | The rotation set; this, not the package list, is the actual scope of work |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`affected version`):**

```bash
# ANTI-PATTERN: grep package.json, bump the version, call it remediated.
# package.json is a range, not a resolution; nothing here proves what was installed,
# on which identity, or whether the install hook ran.
grep -n '"keyv"' package.json
npm install keyv@latest
```

**Behavior-Anchored Detection & Guarded Triage (`affected version` — CWE-778):**

```bash
# Resolution, provenance and execution are three separate questions. Answer each.
set -euo pipefail
REPO="${REPO:-.}"
AFFECTED="keyv@6.0.0 flat-cache@6.1.24 file-entry-cache@11.1.6 cacheable-request@13.0.20"

# 1. Resolution: what did this repository actually pin? Lockfiles, not manifests.
for f in package-lock.json yarn.lock pnpm-lock.yaml; do
  [ -f "$REPO/$f" ] || continue
  echo "== $f"
  for pkg in $AFFECTED; do
    grep -F -- "$pkg" "$REPO/$f" && echo "  RESOLVED: $pkg"
  done
done

# 2. Provenance: did the proxy actually serve it, to whom, and when?
#    Query the artifact proxy for the package name and the published window.
echo "== proxy: request served-artifact records for the window, not just lockfile hits"

# 3. Execution: did an install-time hook run on a runner?
#    Presence in a lockfile is resolution. Execution requires a process record.
echo "== runner: search process telemetry for install-hook children inside the window"
```

**Why this matters:** the strong form separates the three questions that determine whether an organisation was exposed, compromised, or merely resolved a bad version, and it treats a lockfile hit as the weakest of the three; the brittle form changes a range in a manifest and closes the ticket while the install hook's harvested credentials remain valid for their full lifetime.

## When It Is NOT This Issue

- **A version range that never resolved to the bad version:** a manifest with a caret range is not a resolution. A repository whose lockfile pins an older version was never exposed, even if its manifest would permit the affected version on the next install.
- **A transitive dependency present but not installed:** optional dependencies, peer dependencies and platform-excluded packages appear in metadata without ever being fetched. Confirm the proxy record before treating a tree entry as exposure.
- **A lockfile hit on a build that ran with install scripts disabled:** `--ignore-scripts`, a package-manager version that blocks lifecycle hooks by default, or a hardened CI image means the artifact arrived without executing its hook. That is still a supply-chain event worth recording, but it is not a credential compromise.
- **A dependency-confusion lookalike rather than the genuine package:** an internal scope shadowed by a public name produces a malicious package that is not the one in the advisory. Check the registry and scope before applying an advisory's version list.
- **A vendor's "no impact" statement taken at face value:** vendors under disclosure obligations frequently publish a scope narrower than reality, sometimes because they cannot see their own build history. Reconcile against your own records and record the discrepancy.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a build system or developer fleet is clean when install-script execution auditing, proxy logs or CI history was absent for the campaign window.**
- **NEVER present a lockfile match as proof that malicious code executed** — resolution and execution are different findings.
- **NEVER install, upgrade or run an affected package to "test" whether it is malicious** on any host inside the estate.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five required checks before emitting your final output:

- [ ] **Inventory coverage stated:** lockfiles, SBOMs, proxy logs and CI history each have a stated coverage window, and gaps against the campaign window are declared.
- [ ] **Three states separated:** resolution, fetch and execution are reported separately per repository and per runner, not collapsed into "affected".
- [ ] **Identity reach enumerated:** the credentials and roles readable by each affected runner or workstation identity are listed as the rotation set.
- [ ] **Clean pin established:** the replacement version is the last one published before the campaign window, verified by hash, not the latest available.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: supply-chain-incident-response
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)
- [`legal-and-regulatory-notification`](../legal-and-regulatory-notification/SKILL.md) - Incident Response (leaf)
- [`cloud-incident-response-identity-containment`](../cloud-incident-response-identity-containment/SKILL.md) - Incident Response (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `supply-chain-incident-response` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Detection-continuity trap:** where Defender XDR streams advanced-hunting tables into the Microsoft Sentinel data lake, lake-only tables retain far longer than the 30-day Defender window but are invisible to Sentinel analytics rules and the Logs blade. A supply-chain hunt that reaches back 90 days must query the lake directly, not the workspace, or it will report a clean result from an empty table.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 8 |
| Top sources | bugbounty-hunter-v1 (3), CYBER_CPT/go_exploitdb (3), ctf-solver-dataset (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
