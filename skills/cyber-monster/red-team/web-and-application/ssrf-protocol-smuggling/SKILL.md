---
name: ssrf-protocol-smuggling
description: SSRF through non-HTTP protocol handlers. Covers gopher, dict, file, ftp, ldap, tftp and jar handlers to craft arbitrary TCP payloads, read local files, or reach services that only speak binary protocols. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["gopher ssrf", "dict ssrf", "file ssrf", "protocol smuggling ssrf"]
cwe: [CWE-918]
owasp: [A10:2021]
attack: [T1190]
capec: [CAPEC-664]
related: [ssrf, ssrf-cloud-metadata, ssrf-internal-service-pivot, ssrf-allowlist-bypass]
parent: ssrf
corpus_sparse: true
---

# SSRF Protocol Smuggling - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Protocol-smuggling SSRF abuses a fetch client that accepts non-HTTP URL schemes. Where the client honours `gopher://`, an attacker can hand-craft the exact bytes of a TCP payload and speak to a line-based service such as Redis or an internal API as if from the trusted host; `file://` turns the fetcher into a local file reader; `dict://`, `ldap://`, `tftp://`, and `jar://` each open a different downstream interaction. The security decision is the scheme allowlist: the validator usually reasons about hostnames and forgets that the connector URL library will act on whatever scheme it is given. The attacker gains arbitrary-protocol reach or local file disclosure rather than just an HTTP GET, so the fix is to restrict the connector to the single scheme the feature needs.

- **Precondition chain:** A request-controlled URL reaches a fetch client that supports non-HTTP schemes, no scheme allowlist constrains it to http or https, and the downstream protocol interaction or file read is observable or has a usable side effect.
- **Readable differential:** The same request with an http destination versus a gopher, dict, or file scheme; a finding exists when the alternate scheme produces a protocol interaction or file content that http cannot, and it closes when the connector rejects every scheme outside the allowlist.
- **Empirical grounding:** CWE-918 under OWASP Top 10:2025 A01:2025 Broken Access Control; SOURCES.md carries no SSRF-scheme-specific advisory, but CVE-2025-48913 (Apache CXF JndiHelper accepting ldap and rmi PROVIDER_URL) shows the same structural remedy, an allowlist of permitted protocols, applied to a related URI-scheme abuse.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to involve non-HTTP schemes **THEN** start at the parent class [`ssrf`](../ssrf/SKILL.md) first (1 hop)
2. **IF** the connector only supports http and https **THEN** classify as a non-finding for this scheme class and return to [`ssrf`](../ssrf/SKILL.md)
3. **IF** the client honours gopher **THEN** test a benign gopher interaction to a service you control before any internal target
4. **IF** the client honours file **THEN** confirm local file read with a world-readable path such as a hostname file
5. **IF** the scheme reaches a binary service **THEN** pair with [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) for the service inventory
6. **IF** the smuggled payload targets a JNDI or RMI URI **THEN** reclassify under [`jndi-injection`](../jndi-injection/SKILL.md); that is a lookup, not a fetch
7. **IF** no response is returned **THEN** switch to [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) (1 hop)
8. **IF** the goal is link-local metadata via a scheme trick **THEN** switch to [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
10. **IF** only http and https are honoured and no file read is possible **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Smuggled URI is a JNDI or RMI lookup | [`jndi-injection`](../jndi-injection/SKILL.md) | The sink is a directory lookup, not an HTTP fetch |
| Scheme reaches an internal binary service | [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) | Service reachability is the impact, a different invariant |
| No readable response | [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) | Confirmation moves out of band |
| Need parent class methodology | [`ssrf`](../ssrf/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Determine which schemes the connector supports.** Identify the URL library and whether it dispatches on scheme to handlers for gopher, dict, file, ldap, tftp, or jar; the supported set defines the attack surface.
2. **Classify the destination the scheme enables.** gopher crafts raw TCP bytes, file reads the local filesystem, dict queries a service, and ldap or jar reach their own handlers. Choose the scheme whose downstream is observable with the least action.
3. **Baseline with an http control.** Confirm the fetch behaves normally for http, so an alternate-scheme result is a clear deviation and not a parsing accident.
4. **Probe one alternate scheme non-destructively.** Use file to read a world-readable file you can predict, or gopher to echo a benign line to a listener you control, proving the scheme acts without touching real internal data.
5. **Attribute the interaction to the scheme, not a redirect.** Confirm the connector itself dispatched the scheme rather than following an http redirect, since only direct scheme support is this finding.
6. **Stop condition.** Halt when a scheme produces a protocol interaction or file read that http cannot, or is rejected for every non-http scheme, or would require writing to or driving a real internal service. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is an alternate-scheme request yielding file content from a predictable path or a crafted protocol exchange on a listener you control, plus the code line where the scheme is passed unchecked to the connector. An http fetch that merely fails for gopher is not proof.
8. **Close with the structural fix.** Restrict the connector to the single scheme the feature needs, reject every other scheme before resolution, and disable library handlers for file, gopher, and the rest, the same protocol-allowlist remedy applied to CVE-2025-48913. Verify by replaying the file and gopher probes against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `file://` returning local file content through the fetcher | Proves the connector dispatches the file handler, turning SSRF into local file disclosure |
| `gopher://` crafting raw bytes to a line-based service | Proves arbitrary TCP payload construction, the highest-impact scheme on clients that support it |
| `dict://` returning a service banner | Proves a non-HTTP query reached an internal service through the dict handler |
| `ldap://` or `jar://` accepted by the connector | Proves additional handlers are enabled, widening the downstream set beyond HTTP |
| `tftp://` issuing a UDP file request | Proves the client speaks a connectionless protocol the validator never considered |
| An http control that works while every alternate scheme is attempted | Proves the baseline so a scheme result is attributable, not a parsing artefact |
| A URL scheme passed to the connector with no allowlist check in code | Proves the missing scheme restriction, the root decision for this class |

## Worked Contrast

**Vulnerable pattern:**

```python
import urllib.request

def fetch_resource(url: str) -> bytes:
    # urlopen dispatches on scheme, so file://, ftp://, and others are honoured
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read()
```

**Hardened pattern:**

```python
import urllib.parse
import urllib.request

def fetch_resource(url: str) -> bytes:
    scheme = urllib.parse.urlsplit(url).scheme
    # Restrict the connector to the one scheme the feature needs
    if scheme not in {"https"}:
        raise ValueError("scheme not allowed")
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read()
```

**Why this matters:** The defect calls a connector that dispatches on scheme, so file:// reads local files and ftp:// reaches other services even though the feature only needs HTTPS. The fix rejects every scheme outside a single-entry allowlist before the connector runs, the same protocol-allowlist remedy that closed CVE-2025-48913.

## When It Is NOT This Issue

- **http and https-only client:** a connector that cannot dispatch other schemes is not vulnerable to smuggling regardless of host filtering.
- **Scheme rejected before resolution:** an allowlist that drops gopher and file up front closes the class even if a host check is weak.
- **file path outside readable scope:** a file scheme that only reaches a sandboxed directory is limited, not arbitrary disclosure.
- **Redirect to a scheme the client ignores:** a 302 to gopher the client will not follow is not direct scheme support.
- **JNDI or RMI lookup, not a fetch:** an ldap or rmi URI consumed by a directory lookup is deserialization or JNDI injection, not SSRF smuggling.
- **Listener never receives bytes:** a gopher attempt that produces no interaction on a controlled listener is unproven.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssrf-protocol-smuggling` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssrf-protocol-smuggling` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssrf-protocol-smuggling
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-918 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) - Web and Application (leaf)
- [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) - Web and Application (leaf)
- [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) - Web and Application (leaf)
- [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssrf-protocol-smuggling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-918, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
