---
name: supply-chain-attack-recon
description: "Maps an organization's software supply chain: dependencies, registries, CI providers, maintainers and trust relationships to find reachable attack paths. Use when the objective is supply chain rather than the target directly."
family: cloud-container-supply-chain
tier: core
triggers: ["supply chain recon", "dependency mapping", "software supply chain", "third party risk recon"]
cwe: [CWE-1357]
owasp: []
attack: [T1195]
capec: [CAPEC-437]
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
---

# Supply Chain Attack Recon - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Supply-chain reconnaissance in an authorised review is the mapping of what an attacker could learn about how software reaches production. Four channels carry it. Public repository metadata: commit history, contributor lists, release cadence, and the CI badges that name the platform and the workflow. Package metadata: the maintainer list, the publish timestamps, and the dependency graph of every published version, which is enough to identify a package whose maintainer account is worth targeting. Build infrastructure: a repository's `.github/workflows` is public in an open-source project, so the runner type, the secrets it references by name, and the registry it pushes to are all visible. Certificate and DNS metadata: the registry hostnames, the artefact store, and the internal package index are often discoverable through certificate transparency and subdomain enumeration. The 2025 npm campaign is the case study for why this matters: the worm's spread depended on stolen maintainer tokens, so maintainer-account security is a supply-chain control at least as important as the code review, and CISA's response names phishing-resistant MFA for exactly that reason.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the goal is the dependency graph **THEN** read the published metadata per version rather than the repository; the graph is authoritative at the registry.
2. **IF** the goal is the build path **THEN** the workflow files are public in open-source projects and give away the runner, the secret names, and the registry.
3. **IF** the goal is maintainer accounts **THEN** the finding is account security (MFA, token scope), not code, and the 2025 campaign is the evidence.
4. **IF** the finding is a dependency resolution path **THEN** switch to [`ci-cd-and-dependency-attacks-dependency-confusion`](../ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md).
5. **IF** the finding is a live credential **THEN** switch to [`secrets-hunting-and-source-leak`](../secrets-hunting-and-source-leak/SKILL.md).
6. **IF** the finding is a specific vulnerable package **THEN** the branch is vulnerability triage, and the supply-chain question is whether that package is in the critical path.
7. **IF** every maintainer has phishing-resistant MFA, publish tokens are short-lived and scoped, and the build path is not publicly enumerable **THEN** record `Verified Safe` with the three facts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the software's path to production.** Source repository, CI platform, artefact registry, and deployment mechanism. Each hop is a place where an attacker with the previous hop's authority can inject.
2. **Enumerate the published metadata.** Maintainers per package, publish cadence, and the dependency graph. A package with one maintainer and a large dependent set is the highest-value target.
3. **Choose the branch.** Maintainer-account risk, build-path exposure, dependency-graph concentration, or artefact-integrity gap.
4. **Define the baseline-vs-probe differential.** Baseline: the published metadata for the current version — maintainers, dependencies, and publish time. Probe: the same for the previous version. A maintainer added, a dependency added, or a publish outside the cadence is the change worth investigating.
5. **Name the stop condition.** Stop when the path is mapped and the concentration points are named. Do not attempt to access a maintainer account or a private registry.
6. **State the proof.** Report the path with each hop, the concentration points (single-maintainer packages, shared publish tokens, unsigned artefacts), and the control that would bound each. If the path is mapped with every hop controlled, record the negative with the map.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A package with one maintainer and thousands of dependents | A single account compromise reaches every dependent, which is the concentration point | Registry metadata |
| A new maintainer added shortly before a publish | Account takeover or a rushed handover, which is the pattern behind several registry compromises | Registry metadata history |
| A published workflow file naming the runner and secret names | Build-path exposure from public source, requiring no access at all | `.github/workflows` in public repos |
| A publish token shared across repositories | One compromise covers every package the token can publish | CI configuration |
| An artefact published without a signature or attestation | Nothing binds the artefact to the build that produced it | Registry and CI configuration |
| Phishing-resistant MFA enforced on the registry account | The control that stops the token-theft and phishing path the 2025 campaign used | Registry account settings |

## Worked Contrast

**Vulnerable: shared publish token, single-maintainer critical package, unsigned artefacts**

```yaml
# One long-lived token used by every package in the organisation, exposed to any
# workflow that runs in the repository.
- run: npm publish
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}   # account-scoped, never expires
```

```json
{
  "name": "@acme/critical-lib",
  "version": "4.2.1",
  "maintainers": [{ "name": "one-person" }],
  "dependencies": { "tiny-invariant": "^1.3.1" }
}
```

**Hardened: per-package scoped automation tokens, provenance attestation, and MFA on the account**

```yaml
# A granular token scoped to one package, minted for the job, with provenance.
- run: npm publish --provenance --access public
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN_CRITICAL_LIB }}   # package-scoped, rotated
permissions:
  contents: read
  id-token: write        # enables provenance attestation
```

```json
{
  "name": "@acme/critical-lib",
  "version": "4.2.1",
  "maintainers": [
    { "name": "primary-maintainer", "mfa": "webauthn" },
    { "name": "backup-maintainer", "mfa": "webauthn" }
  ]
}
```

**Why this matters:** The left configuration means one stolen token publishes every package in the organisation, the single-maintainer package is the concentration point that makes the token worth stealing, and unsigned artefacts cannot be traced back to a build. The right configuration scopes each token to one package, publishes with a provenance attestation tied to the workflow identity, and puts two phishing-resistant MFA holders on the critical package.

## When It Is NOT This Issue

- **A single-maintainer package with no dependents inside the estate.** The concentration matters only for packages in the path.
- **A public workflow file that references secret names but publishes nothing.** Secret names are not secret values.
- **An unsigned artefact in an internal registry reachable only from the build network.** The transport is the control; note it.
- **A maintainer list that includes a bot account.** Bots are expected; check the token scope instead.
- **A dependency added in a patch release.** Worth a look, but not automatically a finding; read the changelog.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `supply-chain-attack-recon` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `supply-chain-attack-recon` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: supply-chain-attack-recon
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1357 | Mapping: T1195]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `supply-chain-attack-recon` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1357, T1195`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 40 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (17), CYBER_CPT/atomic_red_team (14), CYBER_CPT/oxdf (4), bugbounty-hunter-v1 (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
