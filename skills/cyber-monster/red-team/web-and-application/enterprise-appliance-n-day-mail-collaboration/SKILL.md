---
name: enterprise-appliance-n-day-mail-collaboration
description: Mail gateway and collaboration platform exploitation. Covers n-day exploitation of mail gateways, Exchange-style platforms and collaboration suites, including proxy and deserialization classes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["exchange exploit", "mail gateway exploit", "collaboration platform n-day"]
cwe: [CWE-1395]
owasp: [A06:2021]
attack: [T1190]
capec: [CAPEC-310]
related: [enterprise-appliance-and-n-day-exploitation, enterprise-appliance-n-day-vpn-remote-access, enterprise-appliance-and-n-day-exploitation-edge-network-devices, sql-injection]
parent: enterprise-appliance-and-n-day-exploitation
---

# Enterprise Appliance and N Day Exploitation Mail and Collaboration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This leaf covers n-day exploitation of mail gateways, Exchange-style mail platforms, and collaboration or file-transfer suites where a deployed build carries a known CVE. The recurring classes are proxy or path-confusion that reaches an internal handler (the ProxyShell pattern) and unsafe deserialization in a management or license endpoint, often pre-auth on an internet-facing portal. The security decision is patch state plus exposure of the webmail or management surface, since the platform trusts a request that routes to a privileged backend handler a patched build would block. The attacker gains mailbox access, command execution, or file read with the platform's authority. Confirmation is a version-and-behaviour match on a benign probe to the advisory's affected build.

- **Precondition chain:** a mail or collaboration platform exposes an identifiable build inside a known CVE's affected range, the webmail or management surface carrying the flaw is reachable, and no patch or vendor mitigation is applied.
- **Readable differential:** a benign request to the suspected proxy or management endpoint versus how a patched build routes it; a finding exists when the request reaches the privileged backend as the unpatched build would, and it closes when the fixed version or mitigation is applied.
- **Empirical grounding:** CWE-1395, OWASP A03 Software Supply Chain Failures, ATT&CK T1190. SOURCES carries no mail-gateway-specific appliance CVE, so the mail-proxy class stays at the CWE-1395 taxonomy level; the closest 2025 collaboration anchor is CVE-2025-10035 (GoAnywhere MFT unsafe deserialization, CISA KEV, fixed 7.8.4 / 7.6.3) for the file-transfer suite class.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to be a mail or collaboration n-day **THEN** start at parent class [`enterprise-appliance-and-n-day-exploitation`](../enterprise-appliance-and-n-day-exploitation/SKILL.md) (1 hop)
2. **IF** the flaw is proxy or path-confusion routing to a backend handler **THEN** focus on the autodiscover or OWA-style request path that reaches the privileged endpoint
3. **IF** the CVE class is unsafe deserialization in a license or management servlet **THEN** route to [`insecure-deserialization`](../insecure-deserialization/SKILL.md) for the gadget mechanics
4. **IF** the surface is an SMTP data-termination ambiguity **THEN** route to [`email-header-injection`](../email-header-injection/SKILL.md) for the CRLF and smuggling boundary
5. **IF** you need a trustworthy PoC for the platform CVE **THEN** route to [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md)
6. **IF** the exact platform build is unknown **THEN** fingerprint with [`web-fingerprinting-and-tech-detection`](../web-fingerprinting-and-tech-detection/SKILL.md) first
7. **IF** the webmail login is exposed but the backend may be segmented **THEN** confirm backend reachability before claiming exploitability
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the platform build is patched, or the vulnerable management or proxy surface is unreachable or mitigated **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| CVE class is unsafe deserialization in a servlet | [`insecure-deserialization`](../insecure-deserialization/SKILL.md) | Invariant is safe object reconstruction behind the collaboration platform |
| The surface is SMTP end-of-data ambiguity | [`email-header-injection`](../email-header-injection/SKILL.md) | Invariant is CRLF and data-termination handling, a mail-protocol parsing issue |
| You need a vetted PoC for the platform CVE | [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md) | Invariant is PoC provenance and version gating before exploitation |
| Need parent class methodology | [`enterprise-appliance-and-n-day-exploitation`](../enterprise-appliance-and-n-day-exploitation/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fingerprint the platform to an exact build.** Read webmail or login asset versions, autodiscover responses, and management banners; the build decides which mail or collaboration CVEs apply.
2. **Enumerate the exposed surface.** Identify reachable webmail (OWA-style), autodiscover, and management or license endpoints, and whether the privileged backend is segmented from the front end.
3. **Map the build to the advisory and locate the fixed routing or handler.** For a proxy or path-confusion CVE, read the patch to find the path normalisation the fix added; for a deserialization CVE, find the endpoint that reconstructs objects.
4. **Record a patched-reference baseline.** Capture how a fixed build routes a benign request to the suspect endpoint, including whether it reaches the backend or is rejected.
5. **Send a benign advisory-tied probe.** For the proxy class, issue the documented front-end path with an inert backend target and observe routing; for deserialization, probe the endpoint's reachability without sending a gadget, comparing to the patched baseline and changing only the routing artefact.
6. **Attribute the outcome to version and segmentation state.** Confirm the routing behaviour tracks the affected range and that the backend is actually reachable, not merely that the login page loads.
7. **Stop condition.** Stop when the platform either (a) routes the benign probe to the privileged backend as the unpatched build would and reverts on a fixed build, (b) matches the patched baseline or segments the backend away, or (c) would require sending a deserialization gadget or accessing real mailboxes to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a version-gated, non-destructive differential showing the front-end request reaching the privileged backend handler per the advisory, plus the platform build and advisory reference. An exposed webmail login alone is not proof.
9. **Close with the structural fix.** Apply the vendor's fixed build or mitigation, segment and authenticate the management or backend surface, and disable unneeded proxy endpoints, then re-run the advisory-tied probe against the patched platform.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An autodiscover or OWA-style path that routes to a privileged backend handler | Proves the proxy or path-confusion class on the mail platform, the ProxyShell-style reach |
| A management or license endpoint that reconstructs serialized objects | Proves an unsafe-deserialization surface on the collaboration suite backend |
| A platform build inside a published mail or collaboration CVE's affected range | Proves the patch precondition for a gateway or file-transfer n-day |
| An internet-exposed webmail or management portal | Proves front-end reachability, the first gate before backend exploitation |
| A segmented backend that the front-end request cannot reach | Proves a compensating control that can close the finding despite an affected build |
| A CISA KEV listing for the platform CVE | Proves active exploitation and prioritises patch verification over reproduction |

## Worked Contrast

**Vulnerable pattern:**

```python
def route(front_path, authenticated):
    # Path confusion: a crafted front-end path is forwarded to the backend verbatim
    if front_path.startswith("/autodiscover/"):
        backend = "http://backend.internal" + front_path
        return proxy_forward(backend)      # no normalisation, no backend auth
    return ("not found", 404)
```

**Hardened pattern:**

```python
import posixpath

def route(front_path, authenticated):
    # Normalise the path before any routing decision, then require backend auth
    norm = posixpath.normpath(front_path)
    if ".." in norm.split("/") or not norm.startswith("/autodiscover/"):
        return ("bad path", 400)
    if not authenticated:
        return ("unauthorised", 401)
    return proxy_forward("http://backend.internal" + norm)
```

**Why this matters:** The defective router forwards an un-normalised front-end path to the backend, so a path-confusion request reaches a privileged handler without authentication; the fixed router canonicalises the path, rejects traversal, and requires authentication before forwarding. The control is path normalisation plus backend authentication, the structural fix behind proxy-class mail-platform advisories.

## When It Is NOT This Issue

- **Patched build:** the platform is at or above the fixed version, so the proxy or deserialization path is closed.
- **Backend segmented:** the privileged backend is unreachable from the front end or tester, so the routing cannot complete.
- **Webmail login exposure only:** a reachable OWA or login page proves exposure, not that the vulnerable routing or endpoint is reachable.
- **Authentication enforced on the surface:** the management or proxy endpoint demands credentials a patched build requires, failing the pre-auth condition.
- **Different platform or version line:** a similar collaboration product that does not share the advisory's affected code is out of scope.
- **Mitigation applied:** a vendor workaround disabling the proxy endpoint or license servlet closes the path on an affected build.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `enterprise-appliance-n-day-mail-collaboration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `enterprise-appliance-n-day-mail-collaboration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: enterprise-appliance-n-day-mail-collaboration
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1395 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`enterprise-appliance-and-n-day-exploitation`](../enterprise-appliance-and-n-day-exploitation/SKILL.md) - Web and Application (core)
- [`enterprise-appliance-n-day-vpn-remote-access`](../enterprise-appliance-n-day-vpn-remote-access/SKILL.md) - Web and Application (leaf)
- [`enterprise-appliance-and-n-day-exploitation-edge-network-devices`](../enterprise-appliance-and-n-day-exploitation-edge-network-devices/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `enterprise-appliance-n-day-mail-collaboration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1395, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (5), CYBER_CPT/nuclei_templates (3), CYBER_CPT/blackhills (3), CYBER_CPT/oxdf (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
