---
name: ci-cd-and-dependency-attacks-dependency-confusion
description: Dependency confusion and typosquatting. Covers publishing internal package names to public registries, typosquatting and version pinning gaps. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["dependency confusion", "typosquatting", "package substitution"]
cwe: [CWE-1357]
owasp: []
attack: [T1195]
capec: [CAPEC-437]
related: [ci-cd-and-dependency-attacks, ci-cd-and-dependency-attacks-pipeline-injection, cloud-recon-and-enumeration, aws-attacks]
parent: ci-cd-and-dependency-attacks
---

# Ci Cd and Dependency Attacks Dependency Confusion - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Dependency confusion works because package managers resolve names in an order the attacker can exploit. A build that lists an internal package `@acme/utils` with a version range and no registry pin will, if the internal registry is unreachable or the range is unsatisfied, fall back to the public registry — where anyone can publish `@acme/utils` at a higher version. The attacker needs only the scope name, which is usually visible in a public lockfile, a Dockerfile, or an error message. The variant that needs no fallback is version shadowing: the resolver picks the highest version across both sources, so a `99.0.0` on the public registry beats `1.4.2` on the internal one. The defences are structural rather than procedural: a scoped registry configuration that maps a scope to the internal registry only (`@acme:registry=https://npm.internal/`), `--require-hashes` or a lockfile with integrity digests for Python, and a private proxy that refuses to proxy unknown names. In 2025 this class merged with worm behaviour: the Shai-Hulud npm campaign compromised over 500 packages and used stolen npm tokens to republish, so a build that resolves a name from the public registry is exposed to whatever the registry holds at that moment.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a scope or package name has no registry pin **THEN** that is the finding; the resolver's fallback is the mechanism, not a hypothesis.
2. **IF** the configuration has a default registry plus an internal one without scope mapping **THEN** the public registry is consulted for internal names.
3. **IF** the package manager supports hash pinning and the build does not use it **THEN** the finding is the missing integrity check, which is separate from the registry order.
4. **IF** the internal registry is reachable only from inside the network and the build runs outside it **THEN** the fallback is guaranteed; that is the most exploitable configuration.
5. **IF** the ecosystem is Python **THEN** check `--index-url`, `extra-index-url`, and `--require-hashes` separately, because `extra-index-url` does not replace the default index.
6. **IF** the question is which credentials a compromised dependency would reach **THEN** start at [`ci-cd-and-dependency-attacks`](../ci-cd-and-dependency-attacks/SKILL.md).
7. **IF** every internal name is scope-pinned and every install uses a lockfile with integrity hashes **THEN** record `Verified Safe` with both facts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`ci-cd-and-dependency-attacks`](../ci-cd-and-dependency-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the resolver configuration.** Every `.npmrc`, `pip.conf`, `pyproject.toml` index section, `nuget.config`, and `cargo` source replacement. The effective order and which names map where is the whole finding.
2. **Identify the internal names and their visibility.** A scope, a prefix, or a package name that appears in a public artefact is a target. Names visible only inside the repository are less exposed but not safe.
3. **Choose the branch.** Missing scope pin, missing hash pin, default-plus-extra index, or a proxy that proxies unknown names.
4. **Define the baseline-vs-probe differential.** Baseline: resolve the internal name with the internal registry available, which returns the internal version. Probe: resolve with the internal registry unreachable, or with a higher public version published for a lab scope. A resolution that succeeds from the public registry is the finding.
5. **Name the stop condition.** Stop at the first successful resolution of an internal name from a public source. Do not publish anything to a real registry; use a lab scope.
6. **State the proof.** Report the configuration line, the name, the source that answered, and the minimal fix (`@scope:registry=`, `--require-hashes`, a proxy that denies unknown names). If every name is pinned, record the negative with the config excerpt.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `.npmrc` with `registry=https://registry.npmjs.org/` and no `@scope:registry=` lines | Internal scopes resolve from the public registry when the internal one misses | npm, pnpm, yarn |
| `pip install` with `--extra-index-url` and no `--require-hashes` | The extra index does not replace PyPI, so a higher public version wins | pip, uv |
| A lockfile with `"resolved"` URLs pointing at the public registry for an internal package | The name was already resolved from the public source at least once | npm lockfiles, poetry lock |
| `@acme:registry=https://npm.internal/` with `always-auth=true` | Scope pinning to one registry, which is the control | `.npmrc` |
| A private proxy configured to proxy unknown names | The proxy forwards a typo-squatted or internal-looking name to the public registry | Artifactory, Nexus, Verdaccio |
| No lockfile committed for an application that installs at build time | Every build resolves fresh, so the resolved set can change without a commit | Any application repository |

## Worked Contrast

**Vulnerable: default registry plus an internal one, no scope pin, no hashes**

```ini
# .npmrc — internal scope is not mapped, so a miss falls back to the public registry
registry=https://registry.npmjs.org/
@acme:registry=https://npm.internal.example.com/
```

```text
# pip: extra-index-url does not replace PyPI, so a higher public version wins
pip install --extra-index-url https://pypi.internal.example.com/simple acme-utils==1.4.2
```

**Hardened: scope pinned with auth, hashes required, proxy refusing unknown names**

```ini
# .npmrc — the scope maps to exactly one registry, and auth is scoped to it
@acme:registry=https://npm.internal.example.com/
//npm.internal.example.com/:_authToken=${NPM_TOKEN}
always-auth=true
audit=false
fund=false
```

```text
# pip: a single index, hash-pinned requirements, no fallback
pip install --index-url https://pypi.internal.example.com/simple \
            --require-hashes -r requirements.lock
```

**Why this matters:** The left configuration lets a resolver answer an internal name from a registry anyone can publish to, and the Python form does it even when the internal index is reachable because `extra-index-url` adds rather than replaces. The right configuration maps the scope to exactly one registry with scoped auth, and the Python form uses one index with hash verification so the artifact must match the lock exactly.

## When It Is NOT This Issue

- **A public package with the same name as an internal one, where the build pins an exact version and an integrity hash.** Resolution cannot change without a commit to the lock.
- **A monorepo that resolves workspace packages locally.** The internal names never reach a registry.
- **`extra-index-url` used only to add a mirror of the same index.** The mirror serves the same content; the fallback is not to a third party.
- **An internal registry reachable and preferred, with the public one as a deliberate fallback for genuinely public packages.** The finding needs an internal name that is exposed.
- **A vendored dependency directory.** No resolver at build time.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ci-cd-and-dependency-attacks-dependency-confusion` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ci-cd-and-dependency-attacks-dependency-confusion` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ci-cd-and-dependency-attacks-dependency-confusion
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1357 | Mapping: T1195]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`ci-cd-and-dependency-attacks`](../ci-cd-and-dependency-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`ci-cd-and-dependency-attacks-pipeline-injection`](../ci-cd-and-dependency-attacks-pipeline-injection/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ci-cd-and-dependency-attacks-dependency-confusion` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1357, T1195`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/cisa_kev (8), OffsecCyber (4), bugbounty-hunter-v1 (3), SecEval/attck (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
