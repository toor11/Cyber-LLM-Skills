---
name: waf-bypass-and-payload-obfuscation-parser-differentials
description: "WAF parser differential exploitation. Covers differences between what the WAF parses and what the backend executes: content-type confusion, charset tricks, chunked bodies and duplicate parameters. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: web-and-application
tier: leaf
triggers: ["parser differential waf", "content type bypass", "charset bypass", "waf differential"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-13]
related: [waf-bypass-and-payload-obfuscation, waf-bypass-and-payload-obfuscation-encoding-layers, waf-bypass-and-payload-obfuscation-comment-and-whitespace, waf-bypass-and-payload-obfuscation-rule-specific-evasion]
parent: waf-bypass-and-payload-obfuscation
---

# WAF Bypass and Payload Obfuscation Parser Differentials - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This evasion exploits a disagreement about request structure, not about decoding. The WAF parses the body or parameters under one set of rules (a particular multipart boundary interpretation, a default charset, one value per duplicated key, or a length-delimited body) and matches signatures against the fields it extracted, while the origin's parser extracts different fields from the identical bytes. A content type the WAF does not model, a charset such as IBM037 that re-maps characters, a chunked body the edge treats as opaque, or a duplicated parameter resolved last-wins at the origin and first-wins at the edge all place the dangerous value in a field the filter never inspected. The security decision sits in whichever parser the sink trusts, and the attacker gains an uninspected channel. Proof is that the origin parsed and acted on a field the WAF did not extract.

- **Precondition chain:** The WAF and the origin run different request parsers, the attacker can select a container form (content type, charset, boundary, duplicate key, or transfer encoding) the two parse differently, and the dangerous value lands in the field the origin reads but the WAF did not.
- **Readable differential:** The payload placed in a field the WAF inspects versus the same payload placed in a field only the origin extracts under an alternate container; a finding exists when the origin acts on the second placement while the first is blocked, and it closes when both parsers extract the same fields.
- **Empirical grounding:** CWE-693 Protection Mechanism Failure is the taxonomy; the WAFFLED study (arXiv 2503.10846) catalogued 1,207 container-level parsing discrepancies across AWS, Azure, Cloud Armor, Cloudflare, and ModSecurity, and found over 90% of tested sites accept urlencoded and multipart bodies interchangeably, which is the exact disagreement this leaf exploits.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match this parser-differential leaf **THEN** start at parent class [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) (1 hop) first
2. **IF** the mutation is in how many times a value is decoded rather than which field holds it **THEN** switch to [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) (1 hop)
3. **IF** the disagreement is a chunked or content-length transfer framing between proxy and origin **THEN** treat it as request smuggling and read [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md)
4. **IF** a duplicated parameter is resolved differently by the framework than by the proxy **THEN** pivot to [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md)
5. **IF** the alternate charset folds characters into interpreter syntax **THEN** read [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) for the normalisation invariant
6. **IF** the uninspected field feeds a SQL sink behind a managed rule set **THEN** pivot to [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the WAF and the origin demonstrably parse the identical fields from the request **THEN** STOP and record a verified non-finding: there is no parser gap to carry a payload

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Transfer framing differs between proxy and origin | [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) | Different invariant: message boundaries, not field extraction inside one message |
| Duplicate keys resolved last-wins at origin, first-wins at edge | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Invariant is which value binds, a parameter-pollution and binding problem |
| Alternate charset re-maps bytes to syntax | [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) | Routes to the normalisation invariant rather than the parser invariant |
| Need parent class methodology | [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the parsers in the path and what each extracts.** Note the edge WAF's body model (does it parse multipart, JSON, and urlencoded alike?) and the origin framework's model, including default charset and duplicate-key resolution. The gap you seek is a field present in one model and absent in the other.
2. **Classify the container levers this endpoint exposes.** Content-type swap (urlencoded versus multipart versus JSON), charset parameter, multipart boundary quirks, duplicate parameters, and chunked bodies are independent levers; list which the endpoint accepts.
3. **Choose the lever from observed parsing, not assumption.** Send the same benign key in two containers and see which value the origin returns; divergence tells you the origin parsed a field the edge model would miss.
4. **Record a paired baseline.** Place a benign marker in the field the WAF inspects and capture the block or pass verdict and body length; this is the control the alternate placement must beat.
5. **Move the marker into the uninspected field under the alternate container.** Keep the payload bytes identical and change only the structural wrapper, so any change in origin behaviour is attributable to parser disagreement alone.
6. **Stop condition.** Halt when the alternate placement either (a) is parsed and acted on by the origin while the inspected placement is blocked, (b) is extracted identically by both parsers so no gap exists, or (c) would require delivering the live downstream exploit to prove impact. Outcome (a) confirms the differential, (b) is a non-finding, (c) is out of scope here.
7. **State what counts as proof.** Proof is the origin acting on a value carried in a field the WAF request log did not record, tied to one changed container lever, with the inspected form blocked and the alternate form accepted. A benign reflection of the alternate field value is sufficient; no exploit body is needed.
8. **Close with the structural fix.** Normalise the request to a single canonical parse before the filter runs (reject unknown content types and charsets, collapse duplicate keys to one deterministic value, make the edge and origin share one body parser), then replay the paired placements to confirm both are now inspected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| The same payload blocked as `application/x-www-form-urlencoded` but passed as `multipart/form-data` | Proves the WAF models one body type and the origin another, the core WAFFLED discrepancy on cloud WAFs |
| A `charset=ibm037` or other EBCDIC parameter changing which bytes the origin sees | Proves the edge matched ASCII bytes while the origin transcoded them to different characters |
| A duplicated parameter where the origin uses the last value and the proxy the first | Proves last-wins versus first-wins resolution, letting the payload hide in the copy the WAF ignored |
| A multipart part with a quoted or doubled boundary the WAF parses as body text | Proves boundary-parsing disagreement on stacks that tolerate malformed multipart |
| A chunked request body the edge forwards without reassembling | Proves the WAF treated the body as opaque while the origin dechunked and parsed it |
| The origin reflects a field value absent from the upstream WAF log for the same request | Proves the field was extracted only at the origin, confirming the uninspected channel |
| A JSON body accepted where the WAF rule set only parses form parameters | Proves content-type coverage gaps in the rule set regardless of the payload |

## Worked Contrast

**Vulnerable pattern:**

```python
def waf_body_check(request) -> bool:
    # Only form-urlencoded bodies are parsed and matched; others pass unseen
    if request.content_type == 'application/x-www-form-urlencoded':
        fields = urllib.parse.parse_qs(request.body)
        return any(BLOCK_PATTERN.search(v) for vs in fields.values() for v in vs)
    return False   # multipart, JSON, alternate charset: not inspected

def handle(request):
    if waf_body_check(request):
        return deny()
    return app.dispatch(request)   # origin parses multipart and JSON too
```

**Hardened pattern:**

```python
ALLOWED_TYPES = {'application/x-www-form-urlencoded', 'application/json'}

def normalize_and_check(request) -> bool:
    ctype = request.content_type.split(';')[0].strip()
    if ctype not in ALLOWED_TYPES:
        raise Reject('unsupported content type')      # no uninspected container
    fields = app.parse_like_origin(request)           # one shared parser
    collapsed = {k: fields.getlast(k) for k in fields}  # deterministic duplicates
    return any(BLOCK_PATTERN.search(v) for v in collapsed.values())

def handle(request):
    if normalize_and_check(request):
        return deny()
    return app.dispatch(request)
```

**Why this matters:** The defect is that the filter parsed only one body format while the origin accepted several, so a payload in a multipart or JSON field was never matched. The fix rejects container types the filter cannot model and runs the same parser and duplicate-key resolution the origin uses, so every field the sink reads is inspected.

## When It Is NOT This Issue

- **Both parsers agree:** if the edge and origin extract the same fields from every accepted container, moving the payload changes nothing and there is no differential.
- **Unsupported container rejected by the origin too:** a content type the WAF ignores but the origin also refuses with 415 carries no payload to a sink.
- **Reflected-only field with no sink:** a value the origin parses but only echoes into a non-executing context is a parsing quirk, not a filter bypass.
- **Proxy normalises before the WAF:** if an upstream component rewrites all bodies to one canonical form before inspection, the alternate container never reaches the matcher differently.
- **Detection-only WAF:** a rule set in monitor mode never blocked the inspected form, so the alternate form passing is not evidence of a bypass.
- **Duplicate key collapsed identically:** if both tiers dedupe to the same value, parameter duplication is inert.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `waf-bypass-and-payload-obfuscation-parser-differentials` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `waf-bypass-and-payload-obfuscation-parser-differentials` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: waf-bypass-and-payload-obfuscation-parser-differentials
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) - Web and Application (core)
- [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) - Web and Application (leaf)
- [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](../waf-bypass-and-payload-obfuscation-comment-and-whitespace/SKILL.md) - Web and Application (leaf)
- [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](../waf-bypass-and-payload-obfuscation-rule-specific-evasion/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `waf-bypass-and-payload-obfuscation-parser-differentials` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/gh_advisories (4), CYBER_CPT/expku (3), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
