---
name: secrets-management-and-key-custody
description: "Manages secrets and keys: secret stores, rotation, scoping and custody models including HSM and KMS usage. Use when designing or reviewing credential and key handling."
family: application-security
tier: core
triggers: ["secrets management", "key custody", "vault", "kms"]
cwe: [CWE-798]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Secrets Management and Key Custody - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Secret management is the discipline of keeping long-lived credentials out of artefacts and making every secret short-lived, scoped, attributable, and rotatable. The review checks four properties per secret: where the material lives (vault, KMS, or environment), who can read it, whether use is logged with an identity, and whether rotation can happen without a redeploy. A secret that cannot be rotated under pressure is the real finding, because during an incident rotation is the only containment step that reliably works.

- **CWE-798 (Use of Hard-coded Credentials):** the presence of usable material in a place that travels — source, image layer, CI variable history, or a log.
- ASVS 5.0.0 V13 (Configuration) and V11 (Cryptography) cover secret storage and key lifecycle; the operational half is rotation evidence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the review is about the cryptographic construction rather than the key's custody **THEN** open `cryptography-design-review`.
2. **IF** a secret has leaked into git history **THEN** the first action is rotation, not history rewriting; rewriting without rotation leaves a usable credential.
3. **IF** the workload runs in Kubernetes or a cloud **THEN** prefer workload identity over static keys and check the cloud identity skill for the federation mechanics.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate secrets by consumer.** For each workload, list what it needs, where the material comes from, and what identity proves it. Environment variables inherited from a wider scope are the usual source of over-broad exposure.
2. **Check the custody boundary.** Material should live in a store that authenticates the reader and logs the read. If the app can read a secret without an attributable identity, the store is not a control, it is a database with better marketing.
3. **Choose the branch on lifetime.** Prefer no secret at all (workload identity, signed requests), then short-lived dynamic credentials, then static secrets with automated rotation. Static without rotation is the accept-with-control branch and needs an owner.
4. **Define the baseline-vs-probe differential.** Baseline: the workload starts and reads its secret. Probe: rotate the secret and restart without redeploying the config. The design holds only if the new value is picked up; a probe that requires a rebuild proves rotation is manual.
5. **State the stop condition and the proof.** Stop when every secret has a store, a reader identity, a rotation mechanism, and a successful rotation probe; proof is the vault audit entry showing the new version being read by the workload identity.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Credential in an image layer or build arg | Proves the secret travels with the artefact; anyone who can pull the image can read it, and layer deletion does not remove it. |
| CI variable readable by forked pull requests | Proves untrusted code can exfiltrate the secret; the workflow trigger is the control, not the variable's name. |
| Long-lived cloud access key in application config | Proves missing workload identity federation, so the key must be rotated by hand forever. |
| Secret store read with no audit identity | Proves use is unattributable; during an incident you cannot tell which workload consumed the credential. |

## Worked Contrast

**Vulnerable secret handling (material in the image, read at import time, no rotation path):**

```dockerfile
FROM python:3.13-slim
ARG STRIPE_KEY
ENV STRIPE_KEY=${STRIPE_KEY}
COPY app /app
RUN pip install -r /app/requirements.txt
CMD ["python", "-m", "app"]
```

**Hardened secret handling (no material in the image, mounted at runtime, rotatable):**

```dockerfile
FROM python:3.13-slim
RUN useradd -u 10001 -m appuser
COPY --chown=appuser:appuser app /app
USER appuser
# Secret is projected by the platform at runtime, not baked in:
#   vault-agent / CSI driver / workload identity token exchange
ENV STRIPE_KEY_FILE=/var/run/secrets/stripe/key
CMD ["python", "-m", "app"]
```

**Why this matters:** The first image bakes a live key into an environment layer that survives in the registry, and the app reads it at import time so rotation needs a rebuild. The second keeps the image free of material, reads a projected file per request (or caches with a short TTL), and lets the platform rotate the underlying credential without touching the artefact.

## When It Is NOT This Issue

- **Test key in a fixture that cannot reach production.** A documented fake key in a test fixture is noise; path-scope the scanner rule rather than rotating something that is not real.
- **Public identifier that looks like a secret.** Client ids, key ids, and publishable keys are meant to be public; only the paired secret is material.
- **Short-lived token in a log line.** A redacted or expired token in a debug log is lower severity than a static key; check the TTL before escalating.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `secrets-management-and-key-custody` based solely on surface keywords (`vault`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secrets-management-and-key-custody` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: secrets-management-and-key-custody
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-798`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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
- [`security-testing-in-ci-cd`](../security-testing-in-ci-cd/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secrets-management-and-key-custody` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-798`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 46 |
| Distinct dataset sources | 10 |
| Top sources | OffsecCyber (25), CYBER_CPT/oxdf (11), CYBER_CPT/ctf_search (3), cyber-security/security-code (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 11 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
