---
name: injection-detection-methodology
description: "Provides a systematic method for discovering injection points anywhere input is interpreted: parameter mining, boundary probing, arithmetic and boolean differentials, reflection analysis, and confirmation discipline. Use at the start of any web assessment before committing to a specific injection class."
family: web-and-application
tier: core
triggers: ["injection detection", "find injection", "parameter fuzzing", "input validation testing", "injection testing methodology"]
cwe: [CWE-20]
owasp: [A03:2021]
attack: []
capec: [CAPEC-248]
related: [injection-detection-methodology-parameter-mining, injection-detection-methodology-confirmation-discipline, sql-injection, cross-site-scripting]
---

# Injection Detection Methodology - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This is the discovery discipline that runs before any specific injection class is chosen: it systematically finds where request input is interpreted and whether a boundary crossing changes behaviour. The method inventories every input surface (query, body, headers, cookies, path segments, and hidden parameters), then sends structure-changing probes and reads the response for a differential: a reflection that renders differently, a boolean condition that flips the result set, an arithmetic expression that evaluates, an error class that leaks, or a timing or out-of-band signal. The decision being tested is whether untrusted input reaches an interpreter without a validation or encoding boundary, which is improper input validation rather than any one interpreter bug. The practitioner gains a confirmed, reproducible injection point and a routing decision toward the right class skill. The output is never a single anomaly; it is a differential tied to one changed variable that reverts when the boundary is restored.

- **Precondition chain:** An input surface exists and is reachable, the application interprets that input somewhere rather than treating it as opaque data, at least one feedback channel (reflection, boolean, arithmetic, error, timing, or out-of-band) is observable, and a boundary-changing probe produces a reverting differential against a baseline.
- **Readable differential:** A benign value versus a value that changes parse or evaluation structure; a candidate injection point exists when the response diverges in reflection, result set, error class, or timing and returns to baseline when the structural character is neutralised.
- **Empirical grounding:** CWE-20 Improper Input Validation anchors the discovery method, and OWASP Top 10:2025 files injection under A05:2025. SOURCES.md has no single advisory for the methodology itself, so grounding stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the goal is to enumerate undocumented inputs worth testing **THEN** switch to [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md) (1 hop)
2. **IF** a candidate anomaly needs to be proven beyond coincidence **THEN** switch to [`injection-detection-methodology-confirmation-discipline`](../injection-detection-methodology-confirmation-discipline/SKILL.md) (1 hop)
3. **IF** a candidate confirms as SQL grammar **THEN** switch to [`sql-injection`](../sql-injection/SKILL.md) because the invariant becomes a query parse boundary
4. **IF** the reflected value executes in the browser DOM **THEN** switch to [`cross-site-scripting`](../cross-site-scripting/SKILL.md) because the invariant is HTML and JS context encoding
5. **IF** only a blind out-of-band callback is available as a channel **THEN** switch to [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md) for the egress-oracle method
6. **IF** the input is interpreted by a shell, template, or expression evaluator **THEN** route to the matching command, SSTI, or expression-language class rather than continuing generically
7. **IF** the differential is only timing, not content **THEN** separate signal from jitter before escalating, keeping probes bounded
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** no reachable interpreter and no feedback channel survive inspection **THEN** STOP and classify the input as a verified non-finding rather than forcing a class

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A candidate injection confirms as SQL grammar | [`sql-injection`](../sql-injection/SKILL.md) | Invariant becomes a query parse boundary, a specific interpreter rather than generic input validation |
| The reflected value executes in the browser DOM | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | Invariant is HTML and JS context encoding, a different sink from server-side interpreters |
| Confirmation relies on a blind out-of-band callback | [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md) | Invariant is an egress oracle rather than an in-band response differential |
| Target matches `injection-detection-methodology-parameter-mining` | [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `injection-detection-methodology-confirmation-discipline` | [`injection-detection-methodology-confirmation-discipline`](../injection-detection-methodology-confirmation-discipline/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory every input surface.** Enumerate query parameters, body fields, headers, cookies, path segments, and any hidden parameters, recording where each is reflected or appears to influence a response, before choosing any probe.
2. **Establish which inputs are actually consumed.** Toggle each candidate and confirm it changes something observable, because an input the application ignores cannot be an injection point regardless of its value.
3. **Choose a feedback channel per input.** Match each candidate to the least intrusive channel that can falsify the hypothesis: reflection first, then boolean result-set change, then arithmetic evaluation, then error class, then timing, and out-of-band only when nothing in-band survives.
4. **Record a paired baseline.** Send two benign values and capture status, length, timing, and any reflection, so the natural variation between them defines a noise band that a probe must exceed.
5. **Send one structure-changing probe.** Introduce a single boundary character or expression that would change how the interpreter parses the input, holding every other field constant, and read the chosen channel.
6. **Stop condition.** Halt when the probe either (a) produces a differential that reverts when the structural character is neutralised, (b) stays inside the noise band across two baselines, or (c) would require a destructive or data-exfiltrating payload to advance. Case (a) is a confirmed candidate, (b) is a non-finding, (c) is out of scope for discovery.
7. **State what counts as proof.** Proof at the discovery stage is a reproducible differential tied to one changed structural character, plus the channel that carried it, enough to route to a class skill. It is not yet exploitation; a single anomaly without a revert is not proof.
8. **Close by routing and hardening.** Hand the confirmed candidate to the matching class skill and record the structural control the owning code needs (a typed boundary or contextual encoding at that sink). Verify the routing by reproducing the differential one more time before escalation.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A reflected value whose surrounding markup changes when a single boundary character is sent | Proves a reflection channel is open and the input reaches a renderer, routing toward XSS on any web stack |
| A boolean condition that flips the result set size for logically opposite values | Proves a result-influencing channel suited to SQL or NoSQL confirmation on data-driven routes |
| An arithmetic expression that the response evaluates rather than echoes | Proves an evaluation channel pointing at expression-language or template interpretation |
| A distinct error class leaking only for a structural character | Proves an error channel and an interpreter behind the input, the cheapest confirmation signal |
| A timing difference that scales with a server-side delay keyed to the input | Proves a timing channel usable where no content differential exists, requiring repeats to clear jitter |
| An out-of-band DNS or HTTP callback triggered only by a crafted input | Proves an egress channel for blind confirmation when the response is opaque |
| An input accepted and consumed but with no differential on any channel | Proves the surface is reachable yet validated, a verified non-finding rather than a lead |

## Worked Contrast

**Vulnerable pattern:**

```python
# One raw value flows to shell, SQL and HTML with no per-sink boundary
def render_report(req):
    name = req.params["name"]
    os.system("mkreport " + name)                       # shell sink
    rows = db.execute("SELECT * FROM r WHERE n='%s'" % name)  # sql sink
    return "<h1>" + name + "</h1>"                       # html sink
```

**Hardened pattern:**

```python
NAME_RE = re.compile(r"\A[\w .-]{1,64}\Z")

def render_report(req):
    name = req.params["name"]
    if not NAME_RE.fullmatch(name):                      # typed boundary at the edge
        raise ValueError("name outside accepted charset")
    subprocess.run(["mkreport", name], check=True)       # argv, no shell
    rows = db.execute("SELECT * FROM r WHERE n = ?", (name,))  # bound parameter
    return "<h1>" + html.escape(name) + "</h1>"          # contextual encoding
```

**Why this matters:** The vulnerable handler lets one unbounded value reach three interpreters, which is why the methodology probes several channels at once. The fix shows the structural answer the discovery points to: a typed boundary at intake plus a sink-appropriate control (argv, bound parameter, contextual encoding) at each interpreter.

## When It Is NOT This Issue

- **Accepted but inert input:** a parameter the application reads and discards has no interpreter behind it, so no channel will ever differ.
- **Reflection without interpretation:** a value echoed inside an attribute that the framework auto-encodes is reflected but not injectable; the revert test stays flat.
- **Noise mistaken for a differential:** a length or timing wobble within the two-baseline band is jitter, not a candidate injection point.
- **WAF block mistaken for a backend signal:** a vendor 403 means the probe was rejected before any interpreter, which is neither a finding nor proof of an unfiltered sink.
- **Differential that does not revert:** a change that persists when the structural character is neutralised is a logic or caching effect, not injection.
- **Client-only behaviour:** a value interpreted solely in the browser belongs to the DOM or client-side skills, not server-side injection discovery.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `injection-detection-methodology` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `injection-detection-methodology` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: injection-detection-methodology
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: A03:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md) - Web and Application (leaf)
- [`injection-detection-methodology-confirmation-discipline`](../injection-detection-methodology-confirmation-discipline/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `injection-detection-methodology` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 9 |
| Top sources | CYBER_CPT/nuclei_templates (3), OffsecCyber (2), bug-bounty-pentest-en (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 2 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
