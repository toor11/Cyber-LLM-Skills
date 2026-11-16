---
name: xxe-oob-exfiltration
description: Out-of-band XXE exfiltration. Covers blind XXE using external DTDs, parameter entities, error-based exfiltration, and DNS or HTTP callback channels for multi-line files. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["blind xxe", "xxe oob", "external dtd", "xxe exfiltration"]
cwe: [CWE-611]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-221]
related: [xxe, xxe-file-disclosure, xxe-ooxml-and-svg, xxe-parser-differential-bypass]
parent: xxe
---

# XXE Oob Exfiltration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Blind XXE exfiltration applies when the parser resolves entities but the application never reflects them, so the data has to leave through a side channel the attacker controls. The mechanism uses parameter entities declared in an external DTD: the parser fetches the DTD from the attacker's host, that DTD reads a local file into one parameter entity, then builds a second entity whose URL carries the file contents to a callback host. The decision point is whether the parser loads external DTDs and makes outbound network requests at all; if it does, the file contents arrive in a DNS or HTTP request or are folded into a parser error message. The gain is the same file and service reach as in-band XXE but without any response channel. Proof is a callback that carries file bytes, not merely a DNS lookup, since a bare lookup proves resolution rather than read.

- **Precondition chain:** The parser resolves external parameter entities and performs outbound requests, the application gives no in-band reflection, and the attacker has a reachable callback host to receive the DNS, HTTP, or error-folded data.
- **Readable differential:** A document with no external DTD is compared against one whose external DTD builds a data-carrying parameter entity; a finding exists when a callback arrives bearing file bytes, and it stops once external entity fetching is disabled.
- **Empirical grounding:** CWE-611 anchors this leaf under OWASP Top 10:2025 A05 Injection; SOURCES.md has no blind-XXE-specific product advisory, so this stays at taxonomy, with the structural fix being to disable external entity resolution and outbound parser network access.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as blind exfiltration **THEN** start at the parent class [`xxe`](../xxe/SKILL.md) (1 hop) for general triage
2. **IF** the response never reflects entity content **THEN** use an external DTD with a parameter entity and an assessor callback host
3. **IF** internal entities are blocked but parameter entities are not **THEN** nest the data-carrying entity inside an external DTD
4. **IF** only DNS egress is permitted from the parser **THEN** use a DNS-only callback to confirm resolution before attempting data carry
5. **IF** parser errors surface in the response **THEN** use error-based exfiltration to fold file bytes into an error message
6. **IF** a callback fires but carries no data **THEN** a bare DNS hit proves resolution only, so escalate to an HTTP callback that carries bytes
7. **IF** in-band reflection becomes available **THEN** route to [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** external entity fetching is disabled and no callback arrives **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The response reflects entities directly | [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) | In-band read removes the need for a callback channel entirely |
| A filter blocks the parameter entity | [`xxe-parser-differential-bypass`](../xxe-parser-differential-bypass/SKILL.md) | Getting past the filter is a separate invariant from the callback channel |
| The callback is a server fetch to internal hosts | [`ssrf`](../ssrf/SKILL.md) | Outbound reach to internal services pivots to the SSRF invariant |
| Need parent class methodology | [`xxe`](../xxe/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the parse and confirm the absence of reflection.** Verify the endpoint parses XML with entities on but returns nothing of the parsed content, which is what forces an out-of-band approach.
2. **Stand up a controlled callback host.** Prepare an assessor-controlled DNS and HTTP endpoint so any dereference can be observed and attributed to the server's egress.
3. **Confirm outbound resolution first.** Point a simple parameter entity at the callback host and watch for a DNS or HTTP hit before attempting to carry any data.
4. **Build the data-carrying DTD.** Use an external DTD that reads a benign local marker into one parameter entity and constructs a second entity whose callback URL includes that marker.
5. **Select the channel by egress policy.** If HTTP egress is allowed the callback can carry bytes directly; if only DNS is allowed, confirm resolution and, where parser errors return, fold bytes into an error instead.
6. **Stop condition.** Halt when the parser either (a) sends a callback carrying the benign marker and stops once external fetching is disabled, (b) makes no outbound request at all, or (c) would require exfiltrating real file contents to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a callback from the server's egress address that carries the benign marker value, or an error message containing the marker, tied to the external DTD; a bare DNS lookup with no data proves resolution only, not file read.
8. **Close with the structural fix.** Disable external DTD loading and parameter entity resolution and forbid outbound network access from the parser. Verify by replaying the external-DTD probe and seeing no callback arrive.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A parameter entity in an external DTD triggering an HTTP callback with a marker | Proves blind XXE with a data-carrying channel on the parsing tier, the core finding for this leaf |
| A DNS lookup for an assessor host with no accompanying data | Proves outbound resolution only, a precondition that is not yet file read |
| A benign file marker appearing in a parser error message | Proves error-based exfiltration where egress is restricted to the response channel |
| An external DTD fetch from the parser to an assessor host | Proves the parser loads external DTDs, the enabling behaviour for parameter-entity chaining |
| A nested parameter entity constructing a second entity at parse time | Proves parameter-entity support where internal general entities are blocked |
| No outbound request despite an accepted DOCTYPE | Proves external fetching is disabled, the inert non-finding state |
| Callback source address matching the server egress rather than the assessor resolver | Proves the server issued the request, distinguishing read from mere name resolution |

## Worked Contrast

**Vulnerable pattern:**

```python
import xml.sax


def parse(source):
    p = xml.sax.make_parser()
    # External general and parameter entities are fetched over the network, so
    # an external DTD can read a file and carry it to a callback host.
    p.setFeature(xml.sax.handler.feature_external_ges, True)
    p.setFeature(xml.sax.handler.feature_external_pes, True)
    p.parse(source)
```

**Hardened pattern:**

```python
import xml.sax


def parse(source):
    p = xml.sax.make_parser()
    # Refuse external entity fetches so no parameter-entity callback can leave
    # the process and no blind channel exists.
    p.setFeature(xml.sax.handler.feature_external_ges, False)
    p.setFeature(xml.sax.handler.feature_external_pes, False)
    p.parse(source)
```

**Why this matters:** The defect enables external general and parameter entity resolution, so an external DTD can read a file and smuggle it out over a callback. The structural control turns both features off, removing the outbound fetch that blind exfiltration depends on.

## When It Is NOT This Issue

- **DNS hit without data:** a lookup for the callback host proves the name was resolved, not that a file was read; only a callback carrying the marker counts.
- **Assessor-side resolution:** a callback whose source is the assessor's own recursive resolver, not the server egress, does not prove the server made the request.
- **External fetching disabled:** a parser that resolves internal entities but refuses external DTDs makes no callback, so an absent hit is a non-finding.
- **Egress fully blocked:** a network policy that drops all outbound traffic from the parser means the primitive cannot complete, which is reduced severity, not confirmed exfiltration.
- **In-band channel available:** if the response reflects entities, the finding belongs to the in-band file-disclosure leaf, not to the out-of-band channel.
- **Error echoes input not file:** a parser error that repeats the submitted DTD text without any marker value is echoing input, not exfiltrating a file.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `xxe-oob-exfiltration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `xxe-oob-exfiltration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: xxe-oob-exfiltration
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-611 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`xxe`](../xxe/SKILL.md) - Web and Application (core)
- [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) - Web and Application (leaf)
- [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md) - Web and Application (leaf)
- [`xxe-parser-differential-bypass`](../xxe-parser-differential-bypass/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `xxe-oob-exfiltration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-611, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 7 |
| Top sources | OffsecCyber (10), bugbounty-hunter-v1 (2), CYBER_CPT/nuclei_templates (2), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
