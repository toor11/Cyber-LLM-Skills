---
name: xxe
description: Exploits XML external entity injection for file disclosure, SSRF, error-based exfiltration and denial of service, including OOXML, SOAP, SAML and SVG entry points and modern parser bypasses. Use when an application parses XML or a format built on XML.
family: web-and-application
tier: core
triggers: ["xxe", "xml external entity", "external entity", "xml injection", "doctype", "billion laughs"]
cwe: [CWE-611]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-221]
related: [xxe-file-disclosure, xxe-oob-exfiltration, xxe-ooxml-and-svg, sql-injection]
---

# XXE - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

XML external entity injection works because an XML parser, told to resolve a DOCTYPE, will dereference a SYSTEM identifier and splice whatever it fetches into the document the application then reads. The decision is made in the parser configuration: if external general and parameter entities are allowed, a declared entity can pull a local file through file://, reach an internal service through http://, or trigger expansion that exhausts the parser. Because the parser acts with the service account's file and network reach, the attacker borrows that position from a single import, upload, or API body. Impact splits by feedback channel: an in-band read reflects the entity in the response, a blind target needs an out-of-band callback, and office or SVG uploads carry the DOCTYPE inside a document part. Proof is a parser that dereferences an attacker entity, shown by a benign marker returning or a callback arriving, and the fix is to disable DTD and external entity resolution rather than to filter.

- **Precondition chain:** An attacker-controlled XML document reaches a parser, that parser resolves DOCTYPE and external entities, and a feedback channel exists, either in-band reflection or an out-of-band callback, to observe the dereference.
- **Readable differential:** The same request is sent with a plain document versus one declaring a SYSTEM entity; a finding exists when the entity dereferences, shown by a marker in the response or a callback, and it stops once DTD and external entity resolution are disabled.
- **Empirical grounding:** CWE-611 anchors this class under OWASP Top 10:2025 A05 Injection; SOURCES.md grounds the parser-differential members in CVE-2025-25291 and CVE-2025-25292, where two parsers consumed the same XML differently, and the structural fix is to disable external entity and DTD resolution in the parser configuration.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the entity read is reflected in the response **THEN** switch to [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) (1 hop)
2. **IF** no response reflects the entity content **THEN** switch to [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) (1 hop)
3. **IF** the entry point is an uploaded office or SVG document **THEN** switch to [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md) (1 hop)
4. **IF** a filter blocks the DOCTYPE or entities **THEN** switch to [`xxe-parser-differential-bypass`](../xxe-parser-differential-bypass/SKILL.md) (1 hop)
5. **IF** the entity reaches an internal service rather than a file **THEN** treat it as XXE-to-SSRF and confirm the fetch originates from the server
6. **IF** the entry point is a SOAP or SAML envelope **THEN** inspect the XML body of the message, not just form fields, for a DOCTYPE
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the parser rejects DOCTYPE and resolves no entities **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The transform or query is the real sink | [`xml-attacks-xxe-and-xslt`](../xml-attacks-xxe-and-xslt/SKILL.md) | XSLT and XPath neutralisation is a different invariant than entity resolution |
| The entity reaches an internal service | [`ssrf`](../ssrf/SKILL.md) | XXE-to-SSRF pivots to the server-side fetch-position invariant |
| Target matches `xxe-file-disclosure` | [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `xxe-oob-exfiltration` | [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `xxe-ooxml-and-svg` | [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `xxe-parser-differential-bypass` | [`xxe-parser-differential-bypass`](../xxe-parser-differential-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the XML parse and read its entity configuration.** Find the parser call and determine whether DOCTYPE, external general entities, and parameter entities are allowed; this configuration is the decision point, not any filter in front of it.
2. **Identify the feedback channel first.** Decide whether the response can reflect an entity in-band, whether only an out-of-band callback is possible, or whether the entry point is an uploaded document part.
3. **Record a benign baseline.** Submit a well-formed document with no DOCTYPE and capture the normal response so the entity probe has a reference.
4. **Probe entity processing non-destructively.** Declare a benign internal entity and confirm it expands in the output; only then escalate to a SYSTEM entity pointing at a benign local marker or an attacker-controlled callback host.
5. **Choose the branch from what returned.** If the marker reflects, it is in-band file disclosure; if only a callback arrives, it is blind and needs the out-of-band child; if the entry was a document, route to the office and SVG child.
6. **Stop condition.** Halt when the parser either (a) dereferences the attacker entity, shown by the marker reflecting or a callback arriving and reverting when resolution is disabled, (b) ignores the DOCTYPE entirely, or (c) would require reading real secrets or reaching a real internal service. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a parser dereferencing an attacker-declared entity, evidenced by a benign marker in the response or a callback from the server's egress address, plus the parser setting that allowed it; a DOCTYPE accepted without any dereference is not proof.
8. **Close with the structural fix.** Disable DTD processing and external general and parameter entity resolution in the parser, forbid network access, and bound entity expansion. Verify by replaying the entity probe and seeing the DOCTYPE rejected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A benign internal entity expanding in the response body | Proves the parser resolves entities at all, the minimal precondition before any SYSTEM entity is tried |
| A SYSTEM entity with file:// returning a benign marker in-band | Proves in-band file disclosure on the parsing tier, routed to the file-disclosure child |
| A parameter entity in an external DTD triggering a callback | Proves blind XXE where only an out-of-band channel confirms the dereference |
| A DOCTYPE inside an uploaded word/document.xml or SVG prolog | Proves the document-format entry point that the OOXML and SVG child owns |
| An http:// SYSTEM entity reaching an internal service | Proves XXE-to-SSRF where the parser issues the fetch from the server position |
| A parser accepting a DOCTYPE but never dereferencing the entity | Proves resolution is partly disabled, the inert state that is a non-finding |
| The same document parsed differently by two components | Proves a parser differential, the invariant owned by the bypass child and grounded in the ruby-saml advisories |

## Worked Contrast

**Vulnerable Pattern (spring-boot - xxe):**

```java
Document doc = factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));

        Map<String, String> result = new LinkedHashMap<>();
        NodeList nodes = doc.getElementsByTagName("setting");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element el = (Element) nodes.item(i);
```

**Fixed / Hardened Pattern (spring-boot - xxe):**

```java
}

    public static Map<String, String> parse(byte[] xml) throws ImportRejectedException {
        if (xml.length == 0 || xml.length > MAX_BYTES) {
            throw new ImportRejectedException(Reason.LIMITS);
        }
        String text = decodeUtf8(xml);
        Document doc;
        try {
            // A character stream makes the parser read exactly this text and ignore any
            // encoding="..." declaration, so the DOCTYPE check below sees what the parser saw.
            doc = newFactory().newDocumentBuilder().parse(new InputSource(new StringReader(text)));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            // Locale-independent classification; the parser message is never surfaced.
            boolean doctype = text.contains("<!DOCTYPE");
            throw new ImportRejectedException(doctype ? Reason.DOCTYPE_NOT_ALLOWED : Reason.MALFORMED, e);
```

**Why this matters:** In-band file read and SSRF from a single unauthenticated-or-low-privilege import request, bounded by the service account's file and network reach; no code execution.

## When It Is NOT This Issue

- **DOCTYPE accepted but no dereference:** a parser that tolerates a DOCTYPE yet resolves no external entity is not vulnerable; acceptance is not the same as dereference.
- **Entity resolution disabled:** a parser configured with external entities off expands a declared SYSTEM entity to nothing, so a marker that never returns is a non-finding.
- **Callback without the server as source:** an out-of-band hit that originates from the assessor's own resolver rather than the server's egress address proves resolution of a name, not that the server issued the request.
- **Non-XML body:** a JSON or form endpoint that never routes the payload to an XML parser cannot exhibit XXE even if it echoes a DOCTYPE-looking string.
- **Fetch blocked at egress:** an internal URL entity that is refused by network policy means the parser tried but could not reach, which is a reduced-severity defect, not confirmed impact.
- **Billion-laughs capped:** a parser that enforces an expansion limit and rejects nested entities is enforcing the control, so the expansion attempt is a non-finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `xxe` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `xxe` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: xxe
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-611 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) - Web and Application (leaf)
- [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) - Web and Application (leaf)
- [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `xxe` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-611, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 62 |
| Distinct dataset sources | 13 |
| Top sources | OffsecCyber (32), CYBER_CPT/ctf_search (7), CYBER_CPT/awesome_web_security (6), hackerone_disclosed_reports (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 1 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
