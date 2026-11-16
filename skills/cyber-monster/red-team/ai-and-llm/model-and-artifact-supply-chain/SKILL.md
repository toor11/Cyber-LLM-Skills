---
name: model-and-artifact-supply-chain
description: "Assesses model and artifact supply chains: untrusted model sources, pickle and serializer risk in weights, unsafe model hubs and dependency provenance. Use when ingesting third-party models or adapters."
family: ai-and-llm
tier: leaf
triggers: ["model supply chain", "unsafe pickle model", "model hub risk", "artifact provenance"]
cwe: [CWE-1426]
owasp: [LLM03:2025]
attack: []
capec: [CAPEC-437]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
---


# Model and Artifact Supply Chain - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)

## Mechanism and Preconditions

Model artefacts are executable data: a pickle loads arbitrary code, a tokenizer can be replaced, and a weights file that looks correct can carry a modified architecture. The audit question is provenance — where the artefact came from, whether its format is safe to load, and whether the hash that was verified is the hash that is loaded.

- **Format decides the load risk.** `pickle` deserialises executable bytecode; `safetensors` and `GGUF` are data-only and cannot execute on load. The format is the first finding, not the last.
- **Provenance must be cryptographic.** A model card's claim and a repository namespace are not evidence; a signed manifest or a recorded hash compared at load time is.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the artefact is a pickle **THEN** treat loading it as running untrusted code and prefer a converted `safetensors` build from a verified source.
2. **IF** the model is fetched at runtime **THEN** verify the hash after download and before load, because a namespace can be renamed or a tag moved.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the artefact source, its format, and the verification step between download and load — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** `safetensors` or GGUF artefacts with a recorded SHA-256, verified after download and before load, plus a signed provenance manifest
- **First Check:** `python -c "import hashlib; print(hashlib.sha256(open('weights.safetensors','rb').read()).hexdigest())"`

1. Confirm the target surface: every artefact the deployment loads (weights, tokenizer, config, adapters) and where each comes from.
2. Choose the branch: format review for pickle and custom loaders, provenance review for the source and its signing, and integrity review for the verification step.
3. Define the differential: load a verified artefact and a byte-modified copy; the differential is whether the pipeline detects the modification before inference.
4. Name the stop condition: every artefact has a recorded hash verified at load, and no pickle path remains in the production pipeline.
5. Prove it: the hash before and after download, the verification result, and the loader that consumed the file, so the chain from source to process is shown.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``safetensors` load instead of `torch.load`` | Removes the executable-deserialisation risk entirely; the file format cannot run code. |
| `SHA-256 recorded and compared at load` | Ties the artefact to the reviewed bytes; a tag or namespace can change, a hash cannot. |
| `Signed manifest or attestation` | Evidence of who built the artefact, which a model card does not provide. |
| `Tokenizer and config treated as artefacts` | A swapped tokenizer changes model behaviour without touching the weights. |

## Worked Contrast

**Loading a Pickle From a Mutable Namespace:**

```python
import torch

# BUG: a pickle deserialises arbitrary code, and the namespace or tag can be moved
state = torch.load("hf://some-org/model/pytorch_model.bin", map_location="cpu")
model.load_state_dict(state)
```

**Verified safetensors With a Recorded Hash:**

```python
import hashlib
import json

from safetensors.torch import load_file

EXPECTED = json.load(open("manifest.json", encoding="utf-8"))["weights_sha256"]
path = "model.safetensors"
actual = hashlib.sha256(open(path, "rb").read()).hexdigest()
if actual != EXPECTED:
    raise SystemExit("artefact hash mismatch")

state = load_file(path)
```

**Why this matters:** A pickle file can execute code during deserialisation, so a compromised namespace or a moved tag is code execution in the inference host, and nothing about the model card prevents it. Loading a data-only format after comparing its hash to a recorded manifest removes the execution path and binds the process to the bytes that were reviewed.

## When It Is NOT This Issue

- **Pickle in a trusted, air-gapped build.** The format risk remains, but the exposure differs; report it with the deployment context.
- **Hash mismatch caused by a re-download.** Retry once and compare; a transient failure is not a supply-chain compromise.
- **Model card with no signature.** Absence of a signature is a maturity gap; the finding is loading an unverified artefact in a pipeline that claims verification.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `model-and-artifact-supply-chain` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `model-and-artifact-supply-chain` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: model-and-artifact-supply-chain
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1426 | Mapping: LLM03:2025]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) - Blue Detection/Defense Counterpart
- [`llm-prompt-injection`](../llm-prompt-injection/SKILL.md) - AI and LLM (flagship)
- [`llm-jailbreak-and-guardrails`](../llm-jailbreak-and-guardrails/SKILL.md) - AI and LLM (core)
- [`rag-and-vector-store-attacks`](../rag-and-vector-store-attacks/SKILL.md) - AI and LLM (core)
- [`agentic-ai-and-mcp-security`](../agentic-ai-and-mcp-security/SKILL.md) - AI and LLM (core)
- [`ml-adversarial-and-data-poisoning`](../ml-adversarial-and-data-poisoning/SKILL.md) - AI and LLM (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `model-and-artifact-supply-chain` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1426`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/go_exploitdb (3), CYBER_CPT/gh_advisories (1), CYBER_CPT/osv (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
