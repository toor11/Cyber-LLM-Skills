---
name: subdomain-takeover
description: Finds and claims dangling DNS records pointing at deprovisioned SaaS, cloud, CDN and PaaS resources, covering CNAME fingerprints, NS delegation abuse and verification. Use when enumerating subdomains or reviewing DNS records for stale targets.
family: web-and-application
tier: leaf
triggers: ["subdomain takeover", "dangling cname", "dangling dns", "unclaimed bucket", "ns takeover"]
cwe: [CWE-350]
owasp: []
attack: [T1584]
capec: [CAPEC-141]
related: [subdomain-takeover-cname-fingerprints, subdomain-takeover-ns-and-service-takeover, sql-injection, cross-site-scripting]
---

# Subdomain Takeover - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A subdomain takeover exists when a DNS record the domain still publishes points at a third-party resource the domain no longer owns, so an attacker who claims that resource serves content under the trusted name. The decision point is the ordering of deprovisioning: the DNS record outlives the service it referenced. The Cloud Security Alliance (April 2025) separates three dangling-record categories: a resolvable record whose target answers with the provider default or not-found page, a record whose target resolves to NXDOMAIN, and a record pointing at an unallocated address such as a released elastic IP. The attacker gains a valid-looking subdomain for phishing, cookie scoping, and CSP or allowlist abuse. Confirmation is a provider fingerprint on a record the organization no longer controls.

- **Precondition chain:** The zone still publishes a record (CNAME, A, or NS) for a name, the referenced third-party resource has been deprovisioned or never claimed, and the provider allows a new tenant to claim that exact resource or re-acquire that address.
- **Readable differential:** Resolve the name and fetch its target, comparing the provider unclaimed-resource fingerprint against a live owned response; a finding exists when the target returns the provider default or NXDOMAIN while the record still resolves, and it closes when the dangling record is removed from the zone.
- **Empirical grounding:** CWE-350 and MITRE ATT&CK T1584. The Cloud Security Alliance (April 2025) defines the dangling-DNS categories (resolvable dangling service, NXDOMAIN CNAME target, unallocated elastic IP), and the Hazy Hawk reporting documents dangling CNAME cloud-resource hijacking.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the dangling record is a CNAME pointing at a SaaS or CDN host **THEN** switch to [`subdomain-takeover-cname-fingerprints`](../subdomain-takeover-cname-fingerprints/SKILL.md) (1 hop)
2. **IF** the dangling record is an NS delegation or an expired service domain **THEN** switch to [`subdomain-takeover-ns-and-service-takeover`](../subdomain-takeover-ns-and-service-takeover/SKILL.md) (1 hop)
3. **IF** the record is an A record pointing at a released or unallocated cloud address **THEN** treat it as the unallocated-address category and test re-acquisition of the address in the same region
4. **IF** the target resolves but returns the provider default or not-found page **THEN** classify as the resolvable-dangling-service category and fingerprint the provider before any claim
5. **IF** the CNAME target itself returns NXDOMAIN **THEN** classify as the NXDOMAIN-target category and check whether the base service name can be registered
6. **IF** the subdomain only pins a local service reachable by its hostname **THEN** pivot to [`dns-rebinding-attacks`](../dns-rebinding-attacks/SKILL.md) because the fix there is Host-header allowlisting plus authentication for local services
7. **IF** the record is a dangling MX or TXT rather than a web host **THEN** assess mail and verification-token abuse rather than web content hosting
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the record resolves to a resource the organization still owns and controls **THEN** STOP and classify as a verified non-finding rather than claiming a dangling record

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Trusted subdomain then used to bypass a CSP or cookie allowlist | [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) | The onward invariant is policy allowlisting, not DNS ownership |
| Local service reachable by hostname and rebound to an internal IP | [`dns-rebinding-attacks`](../dns-rebinding-attacks/SKILL.md) | The flaw is Host-header trust for local services, fixed by allowlisting plus authentication |
| Takeover leveraged to host content that steals sessions | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | Impact shifts to script execution under the trusted origin, a different control |
| Target matches `subdomain-takeover-cname-fingerprints` | [`subdomain-takeover-cname-fingerprints`](../subdomain-takeover-cname-fingerprints/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `subdomain-takeover-ns-and-service-takeover` | [`subdomain-takeover-ns-and-service-takeover`](../subdomain-takeover-ns-and-service-takeover/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the zone records and resolve each terminal target.** For every subdomain record the type (CNAME, A, AAAA, NS, MX) and follow the CNAME chain to its final target, noting whether resolution ends in an address, a provider hostname, or NXDOMAIN.
2. **Classify the dangling category.** Place each candidate into one Cloud Security Alliance category: a resolvable record whose target serves the provider default page, a record whose target returns NXDOMAIN, or a record pointing at an unallocated address.
3. **Record an owned baseline.** Fetch a subdomain the organization still controls and capture its response and headers, so the provider unclaimed-resource fingerprint is distinguishable from a live site.
4. **Fingerprint the provider on the candidate.** Compare the candidate body, status, and server headers against the known unclaimed-resource signature for that provider, choosing the category from the previous step.
5. **Test claimability without serving content.** Determine whether the provider lets a new tenant register that exact resource name or re-acquire that address, which is the condition that turns a dangling record into a takeover.
6. **Stop condition.** Halt when the candidate either (a) shows a provider unclaimed fingerprint on a record the organization no longer controls and the resource is claimable, (b) resolves to an owned and live resource, or (c) would require serving real content to a third party to prove. Case (a) is the finding, (b) a non-finding, (c) exceeds non-destructive scope.
7. **State what counts as proof.** Proof is the provider fingerprint on a record you do not control plus evidence the resource is claimable: the dangling category identified, the provider signature captured, and a harmless ownership marker served only on an assessor-claimed resource. A generic 404 without a provider signature is not proof.
8. **Close with the structural fix.** Remove the DNS record from the zone before, not after, the referenced service is deprovisioned, and add a release checklist that deletes records as the first step. Verify by re-resolving the label and confirming NXDOMAIN for that name.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A CNAME still resolving to a provider host that serves an unclaimed-resource page | Proves the resolvable-dangling-service category on that SaaS or CDN provider |
| A CNAME whose target itself returns NXDOMAIN | Proves the NXDOMAIN-target category where the base service name may be re-registrable |
| An A record answering with a released cloud address that can be re-acquired | Proves the unallocated-address category on the cloud provider elastic IP pool |
| A provider-specific 404 or welcome page body on the subdomain | Proves the resource is unclaimed, the fingerprint standard for a takeover claim |
| The organization zone publishing the record while the service account no longer exists | Proves the deprovisioning-order defect that causes the dangling state |
| A dangling NS record delegating a label to a nameserver no longer authoritative | Proves whole-label control is possible, escalating beyond single-host content |
| A verification TXT record referencing a deprovisioned third-party service | Proves a stale trust token that may let an attacker re-verify the service |

## Worked Contrast

**Vulnerable pattern:**

```python
def decommission(service, dns):
    # Deletes the cloud resource first and leaves the DNS record published
    service.delete_bucket(name="assets-legacy")
    # The CNAME to the bucket host still resolves and is now claimable by anyone
    return "service removed"
```

**Hardened pattern:**

```python
def decommission(service, dns):
    # Remove the DNS record first so the name stops resolving to the provider
    dns.delete_record(name="assets-legacy.example.com", rtype="CNAME")
    dns.wait_until_nxdomain(name="assets-legacy.example.com")
    # Only then release the backing resource; no dangling pointer can exist
    service.delete_bucket(name="assets-legacy")
    return "record removed before service"
```

**Why this matters:** The defect deprovisions the backing resource while the zone still publishes the pointer, leaving a dangling record an attacker can claim. The fix inverts the order: the DNS record is deleted and confirmed NXDOMAIN before the resource is released, so the trusted name never points at an unowned resource.

## When It Is NOT This Issue

- **Generic 404 without a provider signature:** a plain not-found page lacking a known provider fingerprint is not evidence the resource is claimable; many live apps return 404 at the apex.
- **Resource still owned:** the subdomain resolves to a bucket or app the organization controls, so there is nothing to claim even when the content is a placeholder.
- **Wildcard DNS catch-all:** a `*` record answering every label makes unmapped names resolve without any dangling resource behind them.
- **Provider prevents reuse:** a provider that reserves the retired resource name to the original account means the fingerprint shows but the claim is impossible.
- **Parked registrar page:** a response from a registrar parking service on an expired apex domain is a different problem than a dangling subdomain record.
- **Internal-only zone:** a record in a split-horizon internal view that never resolves on the public Internet has no external takeover surface.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `subdomain-takeover` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `subdomain-takeover` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: subdomain-takeover
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-350 | Mapping: T1584]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`subdomain-takeover-cname-fingerprints`](../subdomain-takeover-cname-fingerprints/SKILL.md) - Web and Application (leaf)
- [`subdomain-takeover-ns-and-service-takeover`](../subdomain-takeover-ns-and-service-takeover/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `subdomain-takeover` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-350, T1584`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 45 |
| Distinct dataset sources | 6 |
| Top sources | bugbounty-hunter-v1 (19), hackerone_disclosed_reports (11), OffsecCyber (10), SecEval/owasp_wstg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
