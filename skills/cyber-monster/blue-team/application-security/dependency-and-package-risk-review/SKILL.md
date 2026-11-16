---
name: dependency-and-package-risk-review
description: "Assesses third-party dependency risk: provenance verification, version pinning, transitive risk and response to advisories. Use when reviewing supply chain exposure in code."
family: application-security
tier: core
triggers: ["dependency risk", "third party review", "package provenance"]
cwe: [CWE-1357]
owasp: []
attack: []
capec: [CAPEC-437]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Dependency and Package Risk Review - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Dependency risk is a question about the artefact you actually run: which version, from which registry, built by which pipeline, and whether the vulnerable code is reachable from your call paths. The review therefore works in that order — inventory with real versions and integrity hashes, then advisory matching, then reachability, then the decision to upgrade, replace, or accept with a compensating control. OWASP Top 10:2025 promoted this to its own category, A03 Software Supply Chain Failures, which explicitly covers build systems and distribution rather than only outdated packages.

- **CWE-1357 (Reliance on Insufficiently Trustworthy Component):** trust is a property of the whole chain, so an untrusted build pipeline taints a perfectly patched library.
- SLSA v1.1 (approved April 2025, backwards compatible with v1.0) is the provenance vocabulary; verification is a `slsa-verifier` run against the artefact you deploy, not a badge on a README.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the repository ships a lockfile **THEN** review the resolved graph, not the manifest; ranges in `package.json` or `requirements.txt` are intent, the lockfile is the deployment.
2. **IF** the finding is a credential inside a package or its build script **THEN** pivot to `secrets-management-and-key-custody` for rotation and to `security-testing-in-ci-cd` for the install hook exposure.
3. **IF** the same package appears in several services **THEN** check for a shared base image or internal mirror before proposing per-service upgrades; the fix is usually one layer up.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Build the inventory from the deployed artefact.** SBOM from the image or lockfile hash in the build, including transitive packages and their integrity digests. Anything you cannot attribute to a lock entry is unreviewed.
2. **Match advisories against resolved versions, then discard unreachable ones.** A vulnerable function in a code path your service never calls is a lower priority than the same advisory in a hot path; record the reasoning rather than the CVSS alone.
3. **Choose the branch on available action.** Direct upgrade, transitive override, replacement, or accept-with-control. Only the first two close the finding; the last two need an owner and an expiry.
4. **Define the baseline-vs-probe differential.** Baseline: the build resolves the current lockfile and passes. Probe: introduce a known-vulnerable version in a scratch branch and confirm the scanner flags it. A pipeline that cannot reproduce the finding cannot be trusted to clear it.
5. **State the stop condition and the proof.** Stop when every direct dependency has an integrity hash, every advisory has a disposition with a reason, and the probe has been observed failing; proof is the scan output plus the lockfile diff.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Lockfile absent or integrity hashes stripped | Proves the build can resolve different bytes than the review saw; common where CI runs `npm install` instead of `npm ci`. |
| Install-time script in a transitive package | Proves code execution at build time on npm/PyPI/Cargo; the dependency can act before your application starts. |
| Package name one edit away from a popular library | Proves dependency-confusion exposure when an internal package name is unclaimed on the public registry. |
| Artefact deployed without a verified provenance attestation | Proves the deployed image may not be the one that was scanned, which is the A03 failure mode. |

## Worked Contrast

**Vulnerable dependency practice (range in manifest, no lock, no integrity):**

```json
{
  "name": "checkout-api",
  "dependencies": {
    "express": "^5.1.0",
    "body-parser": "^2.2.0",
    "lodash": "*"
  }
}
```

**Hardened dependency practice (pinned lock, integrity, CI installs the lock):**

```json
{
  "name": "checkout-api",
  "dependencies": {
    "express": "5.1.0",
    "body-parser": "2.4.0",
    "lodash": "4.17.21"
  },
  "scripts": { "preinstall": "node -e \"process.exit(process.env.npm_config_user_agent.includes('npm')?0:1)\"" },
  "lockfileVersion": 3,
  "engines": { "node": ">=22.11.0" }
}
```

**Why this matters:** The first manifest floats every dependency and one of them (`body-parser` below 2.4.0) carries the compressed-body denial of service fixed in CVE-2026-111181; the second pins exact versions and ships a lockfile whose integrity hashes the build must consume. The CI step that matters is `npm ci`, which refuses to resolve outside that lockfile.

## When It Is NOT This Issue

- **Advisory matches a function the service never imports.** A path-traversal fix in a static-file helper is irrelevant to a worker that only uses the queue client; record the reachability argument rather than escalating.
- **Distro-backported patch not reflected in the version string.** RHEL and Debian carry fixes without bumping upstream versions; check the distro advisory before filing.
- **Dev-only dependency in a non-shipped graph.** Test frameworks in a `devDependencies` graph that never enters the image belong in build hygiene, not the runtime finding list.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `dependency-and-package-risk-review` based solely on surface keywords (`provenance`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `dependency-and-package-risk-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: dependency-and-package-risk-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-1357`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `dependency-and-package-risk-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1357`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 25 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (16), CYBER_CPT/github_security_md (5), CYBER_CPT/osv (1), CYBER_CPT/oxdf (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
