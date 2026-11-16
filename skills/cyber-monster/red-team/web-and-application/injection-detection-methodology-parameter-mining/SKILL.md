---
name: injection-detection-methodology-parameter-mining
description: Injection parameter mining. Covers discovering undocumented parameters and headers worth testing through wordlists, JS analysis, and differential behaviour observation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["parameter mining", "hidden parameter", "param discovery", "undocumented parameter"]
cwe: [CWE-20]
owasp: [A03:2021]
attack: []
capec: [CAPEC-248]
related: [injection-detection-methodology, injection-detection-methodology-confirmation-discipline, sql-injection, cross-site-scripting]
parent: injection-detection-methodology
corpus_sparse: true
---

# Injection Detection Methodology Parameter Mining - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

This leaf discovers inputs the documentation and the visible interface never reveal, because an injection point cannot be tested if it is never sent. The method harvests candidate parameter and header names from client JavaScript bundles, source maps, API schemas, archived requests, and wordlists, then replays a known request with each candidate added individually and watches for a behavioural differential: a change in status, response length, timing, reflected content, or an error that shows the server consumed the new key. Many frameworks silently bind unknown query fields, body fields, or even request headers into a request object, so a hidden `debug`, `role`, `include`, or `callback` flag can change behaviour without appearing anywhere in the UI. The decision being tested is whether the application accepts and acts on parameters outside its published contract. The practitioner gains a list of consumed hidden inputs to feed into class-specific testing. Proof is a differential attributable to one added parameter that disappears when it is removed.

- **Precondition chain:** The application accepts request fields or headers beyond its documented contract, at least one undocumented field changes observable behaviour when added, a source of candidate names exists (JavaScript, schema, or wordlist), and the differential for an added field reverts when that field is removed.
- **Readable differential:** A known request without a candidate parameter versus the same request with one candidate added; a hidden parameter is consumed when the added version changes status, length, timing, or reflection and the change reverts when the parameter is dropped.
- **Empirical grounding:** CWE-20. Discovering undocumented parameters is a method rather than a single advisory; OWASP Top 10:2025 A05:2025 Injection is the enclosing category and SOURCES.md has nothing mining-specific, so grounding stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the candidate is not yet placed in an injection class **THEN** start at parent class [`injection-detection-methodology`](../injection-detection-methodology/SKILL.md) first
2. **IF** candidate names should come from the client JavaScript **THEN** switch to [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) to extract them from bundles and source maps
3. **IF** a discovered parameter is bound onto a model object **THEN** switch to [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) because the invariant becomes field authority
4. **IF** the candidate surface is request headers, not query or body fields **THEN** test header binding separately because several frameworks map headers into the request object
5. **IF** an added parameter changes behaviour only intermittently **THEN** confirm it with repeated control-isolated runs before treating it as consumed
6. **IF** the added parameter triggers a structural differential **THEN** route to the matching class skill rather than continuing to enumerate
7. **IF** a candidate needs rigorous proof beyond a single response **THEN** read [`injection-detection-methodology-confirmation-discipline`](../injection-detection-methodology-confirmation-discipline/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** no added parameter or header changes any observable behaviour **THEN** STOP and record a verified non-finding rather than reporting accepted-but-ignored keys

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Hidden fields are found by reading client JavaScript | [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) | Invariant is source extraction of names, not a live request differential |
| A discovered parameter is bound onto a model object | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Invariant becomes field authority once the hidden field is consumed |
| Need parent class methodology | [`injection-detection-methodology`](../injection-detection-methodology/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Gather candidate names from real sources.** Extract parameter and header tokens from JavaScript bundles, source maps, OpenAPI or GraphQL schemas, archived requests, and targeted wordlists, favouring names the application itself references.
2. **Capture a stable known request.** Record a request whose normal response is deterministic, so adding one candidate at a time produces a clean differential against it.
3. **Add exactly one candidate per request.** Replay the known request with a single new query field, body field, or header, holding everything else constant, because batching candidates hides which one was consumed.
4. **Watch the right signals.** Compare status, response length, timing, and reflected content; a consumed parameter usually moves one of these even when the response looks similar.
5. **Separate consumption from injection.** Confirm first that the parameter is acted upon at all; only then treat any structural differential it enables as a candidate for a class skill.
6. **Stop condition.** Halt when a candidate either (a) changes observable behaviour and the change reverts when the parameter is removed, (b) is accepted with no behavioural change across repeats, or (c) would require a destructive value to show any effect. Case (a) is a consumed hidden input, (b) is a non-finding, (c) is out of scope for mining.
7. **State what counts as proof.** Proof that a parameter is consumed is a reproducible behavioural differential tied to that one added field, reverting on its removal, plus where it appeared (query, body, or header). An accepted-but-inert key is not proof of anything testable.
8. **Close by routing and noting the contract gap.** Feed each consumed hidden input into the appropriate class skill and record that the application accepts fields outside its published contract, recommending a strict request schema. Verify by reproducing the add-and-revert differential once more.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A parameter name present in a JavaScript bundle but absent from the UI and docs | Proves a candidate hidden input worth replaying on any single-page-app backed stack |
| Adding one undocumented query field that changes response length or status | Proves the field is consumed by the server, the precondition for class-specific testing |
| A request header such as `X-Forwarded-Host` or `X-Original-URL` altering behaviour | Proves header binding into the request object on frameworks that trust proxy headers |
| A `debug`, `test`, or `admin` flag toggling verbose output or alternate logic | Proves a hidden mode that widens the attack surface beyond the documented contract |
| A `callback` or `format` parameter switching the response serialisation | Proves a content-negotiation hidden input that can route to JSONP or format-specific issues |
| An accepted parameter that produces no differential on any channel | Proves the key is inert, a verified non-finding rather than a lead |

## Worked Contrast

**Vulnerable pattern:**

```python
# Unknown query params are merged into options, so hidden flags take effect
def search(req):
    opts = {"q": "", "limit": 20}
    opts.update(req.params)      # debug, admin, include_drafts all silently honored
    return run_search(opts)
```

**Hardened pattern:**

```python
ALLOWED = {"q", "limit"}

def search(req):
    # Reject fields outside the published contract instead of merging them in
    unknown = set(req.params) - ALLOWED
    if unknown:
        raise ValueError("unknown parameters: %s" % sorted(unknown))
    opts = {"q": req.params.get("q", ""),
            "limit": int(req.params.get("limit", 20))}
    return run_search(opts)
```

**Why this matters:** The vulnerable handler merges every request field into its options, so undocumented flags silently change behaviour and become hidden injection surface. The fix pins a strict parameter contract and rejects unknown fields, which both closes the hidden surface and makes mining differentials impossible.

## When It Is NOT This Issue

- **Accepted but inert parameter:** a field the server stores nowhere and acts on never is not a hidden input worth testing.
- **Documented parameter rediscovered:** a key already in the API contract is not a mining finding even if the UI does not expose it.
- **Reflection without consumption:** a value echoed into the response but not used in any decision has no behaviour to differentiate.
- **Framework ignores unknown keys:** a strict schema that drops undeclared fields means no candidate can ever be consumed.
- **Differential from caching:** an apparent effect that vanishes with a cache buster was not produced by the added parameter.
- **Header stripped at the edge:** a candidate header rewritten or removed by a proxy never reaches the application to be bound.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `injection-detection-methodology-parameter-mining` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `injection-detection-methodology-parameter-mining` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: injection-detection-methodology-parameter-mining
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: A03:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`injection-detection-methodology`](../injection-detection-methodology/SKILL.md) - Web and Application (core)
- [`injection-detection-methodology-confirmation-discipline`](../injection-detection-methodology-confirmation-discipline/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `injection-detection-methodology-parameter-mining` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
