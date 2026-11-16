---
name: ssrf-internal-service-pivot
description: SSRF to internal service access. Covers reaching internal-only HTTP services, admin panels, databases over HTTP interfaces, Kubernetes API, and Docker or Nomad sockets from a server-side fetch primitive. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["ssrf internal", "internal service ssrf", "pivot via ssrf", "kubernetes api ssrf"]
cwe: [CWE-918]
owasp: [A10:2021]
attack: [T1190]
capec: [CAPEC-664]
related: [ssrf, ssrf-cloud-metadata, ssrf-protocol-smuggling, ssrf-allowlist-bypass]
parent: ssrf
---

# SSRF Internal Service Pivot - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

An internal-service-pivot SSRF uses the server network position to reach services firewalled from the outside but trusting anything on the internal network. The fetch primitive becomes a client for an admin panel, a Kubernetes API server at kubernetes.default, a Docker daemon on 127.0.0.1:2375, or an HTTP-speaking datastore such as Elasticsearch on 9200. The security decision fails because these services authenticate by network location rather than by credential, so a request arriving from the trusted application host is honoured. The attacker gains read or control interaction with infrastructure never meant to be externally reachable, and the observable proof is a response fragment, a distinct status, or a status-code difference between an open and a closed internal port.

- **Precondition chain:** A request-controlled fetch can reach an internal address or hostname, an internal service there trusts network origin instead of a credential, and the response or a side effect is observable to the caller.
- **Readable differential:** A fetch to an internal service path versus an external control; a finding exists when the internal path returns service-specific content or a distinct open-port status while the control does not, and it closes when the fetch tier is network-segmented from the service.
- **Empirical grounding:** CWE-918 under OWASP Top 10:2025 A01:2025 Broken Access Control; GHSA-998c-x8hx-737r (Stirling-PDF URL-to-PDF SSRF, fixed 0.45.0) shows a server-side fetch reaching resources it should not, the same pivot shape.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to target internal services **THEN** start at the parent class [`ssrf`](../ssrf/SKILL.md) first (1 hop)
2. **IF** the fetch tier is network-segmented from internal services **THEN** classify as a non-finding; record segmentation as the control
3. **IF** an internal admin panel answers from the application host **THEN** treat the trust-by-network service as the primary finding
4. **IF** the target is the Kubernetes API at kubernetes.default **THEN** probe the API version path read-only before anything else
5. **IF** the target is the Docker socket on 127.0.0.1:2375 **THEN** confirm the version endpoint responds before claiming control
6. **IF** the service only speaks a binary protocol **THEN** switch to [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) (1 hop)
7. **IF** the target is link-local metadata **THEN** switch to [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) (1 hop)
8. **IF** no response body is returned **THEN** switch to [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
10. **IF** the fetch tier cannot reach any internal service after inspection **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Service speaks a binary protocol | [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) | Reaching it needs a crafted scheme payload, a different invariant |
| Target is link-local metadata | [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) | Impact is credential theft, not service interaction |
| No readable response from the pivot | [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) | Confirmation moves to out-of-band or port-error oracles |
| Need parent class methodology | [`ssrf`](../ssrf/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the fetch tier internal reach.** Determine which internal subnets, service hostnames, and loopback ports the component can address; a pivot is only possible where the fetch tier and the service share a trusted network.
2. **Inventory trust-by-network services.** List internal HTTP endpoints that authenticate by origin: admin consoles, kubernetes.default, the Docker socket on 2375, Elasticsearch on 9200, Redis over HTTP. These are the services that honour the application host.
3. **Baseline an external control fetch.** Confirm the server issues the request and capture its normal response so an internal response is a measurable deviation, not an assumption.
4. **Probe internal paths read-only.** Request a version or health path on each candidate, such as the Kubernetes version endpoint, the Docker version endpoint, or an Elasticsearch root, which returns service-identifying content without changing state.
5. **Use a port-status oracle where bodies are suppressed.** Compare an open internal port to a closed one by status or timing to prove reachability even when the response is not reflected.
6. **Stop condition.** Halt when a probe returns service-specific content or a distinct open-port status an external control cannot, or is refused identically for every internal address, or would require issuing a state-changing call to the service. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is an internal service identifying response or a reliable open-versus-closed port differential obtained through the server fetch, plus the code line that let the destination be request-controlled. An external redirect or a public response is not proof of internal reach.
8. **Close with the structural fix.** Segment the fetch tier from internal services, require real authentication on those services instead of network trust, resolve-and-pin destinations to a public allowlist, and deny loopback and RFC1918 ranges at the connector. Verify by replaying the internal version probes against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A Kubernetes API response from kubernetes.default via the fetch | Proves the cluster API trusts the pod network and is reachable through the SSRF, on Kubernetes workloads |
| A Docker daemon version response on 127.0.0.1:2375 | Proves an unauthenticated Docker socket is in reach, a control-plane pivot on container hosts |
| An Elasticsearch or datastore root returning cluster info on an internal port | Proves an HTTP-speaking datastore that trusts network origin is reachable |
| An internal admin panel rendering from the application host | Proves a trust-by-network console is exposed through the server fetch |
| An open-versus-closed internal port status or timing difference | Proves reachability as a low-noise oracle when bodies are suppressed, on any backend |
| An internal hostname resolving only inside the network answering the fetch | Proves split-horizon DNS reach, confirming the server sits inside the trusted zone |
| A redis-over-HTTP or memcached probe returning a protocol banner | Proves a cleartext internal service is addressable from the web tier |

## Worked Contrast

**Vulnerable pattern:**

```python
import requests

def render_report(request):
    # Operator passes a full URL; the tier sits on the internal network and trusts it
    target = request.GET["source"]
    return requests.get(target, timeout=5).text
```

**Hardened pattern:**

```python
import ipaddress
import socket
import urllib.parse
import requests

ALLOWED = {"reports.public.example"}

def render_report(request):
    target = request.GET["source"]
    parts = urllib.parse.urlsplit(target)
    if parts.scheme != "https" or parts.hostname not in ALLOWED:
        raise ValueError("source not allowed")
    addr = socket.getaddrinfo(parts.hostname, 443, proto=socket.IPPROTO_TCP)[0][4][0]
    if not ipaddress.ip_address(addr).is_global:
        raise ValueError("source resolves to a non-public address")
    return requests.get(target, timeout=5, allow_redirects=False).text
```

**Why this matters:** The defect lets an operator-supplied URL drive a fetch from a tier that lives on the internal network, so internal consoles and sockets that trust network origin answer. The fix constrains the source to a public allowlist, rejects non-global resolved addresses, and forbids redirects, while segmentation and real service authentication remove the network-trust assumption.

## When It Is NOT This Issue

- **Segmented fetch tier:** if network policy stops the component reaching internal services, the primitive is not exploitable for a pivot.
- **Service requires real auth:** an internal endpoint that demands a credential the attacker lacks is not reachable just because the port answers.
- **Public response only:** content from an external site is not internal reach even if the parameter accepted a URL.
- **Open port with no service parsing:** a TCP connect that never speaks the protocol proves a port is open, not that the service is usable.
- **Redirect to internal that the client does not follow:** a 302 the fetch client ignores does not reach the internal target.
- **Loopback that is the app itself:** reaching 127.0.0.1 on the app own port is self-scope, not a distinct internal service.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssrf-internal-service-pivot` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssrf-internal-service-pivot` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssrf-internal-service-pivot
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
- [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) - Web and Application (leaf)
- [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) - Web and Application (leaf)
- [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssrf-internal-service-pivot` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-918, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 35 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (14), hackerone_disclosed_reports (11), ctf-solver-dataset (5), bugbounty-hunter-v1 (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
