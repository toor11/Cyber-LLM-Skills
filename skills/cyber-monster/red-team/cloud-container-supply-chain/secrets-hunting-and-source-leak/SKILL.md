---
name: secrets-hunting-and-source-leak
description: Finds leaked secrets across repositories, CI configs, container images and public sources, then validates them. Use when looking for credential material to gain initial access or escalate.
family: cloud-container-supply-chain
tier: core
triggers: ["secret hunting", "leaked credentials", "github secret", "trufflehog", "source leak"]
cwe: [CWE-798]
owasp: []
attack: [T1552]
capec: [CAPEC-70]
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
---

# Secrets Hunting and Source Leak - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Secret leak review is a search problem with a precision problem. The mechanisms that produce leaks are stable: a credential committed to a repository and later removed still lives in the history and in every clone; a `.env` file copied into a container image; a key printed into a CI log; a token embedded in a frontend bundle; a post-install script in a compromised dependency that harvests `~/.npmrc` and cloud credentials and exfiltrates them — the 2025 Shai-Hulud campaign did exactly that across more than 500 npm packages, and CISA's advisory names rotating developer credentials and mandating phishing-resistant MFA as the response. The precision problem is that most high-entropy strings are not credentials: a hash in a lockfile, a base64 test fixture, a public identifier. The review therefore needs a verification step per candidate — a call to the provider's identity endpoint, or a check of the credential's prefix and length against the provider's documented format — before anything is reported, and the finding is the verified credential plus the reachable scope, not the string.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a candidate matches a provider's documented prefix and length **THEN** verify it against a read-only identity endpoint before reporting; an unverified match is a hypothesis.
2. **IF** the credential is in git history rather than the working tree **THEN** the finding includes the history rewrite or the rotation, and rotation is the only reliable remedy.
3. **IF** the leak path is a container image **THEN** the credential is in the image layers, so deleting the file in a later layer does not remove it.
4. **IF** the leak path is a CI log **THEN** the exposure is bounded by the log's retention and audience; state both.
5. **IF** the candidate is in a frontend bundle **THEN** it is public by definition, and the finding is that a secret was put in a client at all.
6. **IF** the mechanism is a malicious dependency rather than a developer mistake **THEN** start at [`npm-pypi-and-cargo-install-hook-supply-chain`](../npm-pypi-and-cargo-install-hook-supply-chain/SKILL.md).
7. **IF** every candidate fails verification or matches a documented public value **THEN** record the negative with the candidate count and the verification method.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the surfaces.** Working tree, full git history, container image layers, CI logs, build artefacts, and frontend bundles. Each has a different extraction method and a different retention.
2. **Triage by format.** Provider prefixes (`AKIA`, `ghp_`, `xoxb-`, `sk-`), length constraints, and checksum properties narrow the candidate set before any network call.
3. **Verify each candidate with a read-only call.** `sts:GetCallerIdentity`, a GitHub `/user` request, or the provider's documented introspection endpoint. A 200 with a valid identity is the proof; a 401 means the credential is revoked and the finding is historical.
4. **Define the baseline-vs-probe differential.** Baseline: the candidate string in its file, with its surrounding context. Probe: the identity the credential resolves to, and the permissions that identity holds. The differential is a credential that resolves to a live principal with scope.
5. **Name the stop condition.** Stop at the first verified credential and its reachable scope. Do not use the credential to access data.
6. **State the proof.** Report the file and commit, the credential type, the verified identity, the reachable permissions, and the remedy (rotate, revoke, purge history or accept the exposure). If no candidate verifies, record the negative with the count.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `AKIA` followed by 16 uppercase alphanumerics | An AWS access key ID format, which needs the paired secret to be usable | Git history, env files, CI logs |
| `ghp_` or `github_pat_` prefix | A GitHub token whose scope is readable from the API response | Repository contents, CI configuration |
| A `.env` file present in a container image layer | The credential is in the image, so it is in every registry copy | Container images |
| A high-entropy string in a frontend `.js` bundle | A credential shipped to clients, which is public regardless of intent | Static bundles, source maps |
| A `~/.npmrc` token referenced by a dependency's postinstall script | The credential-harvesting mechanism of the 2025 npm campaign | Package install hooks |
| A private key block (`BEGIN ... PRIVATE KEY`) | A key whose authority is the certificate or account it belongs to | Repositories, images, backups |

## Worked Contrast

**Vulnerable: credential committed, then deleted in a later commit, and baked into an image**

```dockerfile
# The .env file is copied into the image; deleting it in a later layer leaves the
# credential readable in the earlier layer, and it is also in git history.
FROM python:3.12-slim
WORKDIR /app
COPY .env .env
COPY . .
RUN pip install -r requirements.txt && rm .env
```

```text
git log --all -p -- .env   # the secret is still here after the deletion commit
```

**Hardened: no secret file in the image, runtime injection from a secret store, and history that never held one**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
# No .env, no COPY of credentials; the process reads them from the environment at
# runtime, which the platform injects from a secret manager.
USER 10001
ENTRYPOINT ["python", "-m", "src.main"]
```

```text
# .gitignore and a pre-commit guard, so the file never enters history
echo ".env" >> .gitignore
pre-commit install   # secret scanning hook
```

**Why this matters:** The left image carries the credential in a layer that no later deletion removes, and the repository history carries it after the deletion commit, so both copies survive a cleanup that looks complete. The right image contains only code, the credential arrives from a manager at runtime, and a pre-commit guard keeps it out of history in the first place.

## When It Is NOT This Issue

- **A high-entropy string in a lockfile's integrity field.** It is a content hash, not a credential.
- **A revoked token found in history.** The exposure is historical; the finding is the absence of rotation evidence.
- **A public identifier such as a client id without a secret.** Client ids are public by design in OAuth.
- **A test fixture with an obviously fake key** (`AKIAIOSFODNN7EXAMPLE`) — documentation, not a credential.
- **A base64-encoded non-secret such as a JWT with `alg: none` and no claims of value.** No authority to exercise.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `secrets-hunting-and-source-leak` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secrets-hunting-and-source-leak` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: secrets-hunting-and-source-leak
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-798 | Mapping: T1552]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secrets-hunting-and-source-leak` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-798, T1552`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 51 |
| Distinct dataset sources | 10 |
| Top sources | OffsecCyber (20), osint-tool-database (16), bugbounty-hunter-v1 (5), CYBER_CPT/sigmahq (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 16 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
