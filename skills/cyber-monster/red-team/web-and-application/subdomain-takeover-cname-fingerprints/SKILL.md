---
name: subdomain-takeover-cname-fingerprints
description: CNAME fingerprint subdomain takeover. Covers fingerprinting unclaimed SaaS and cloud resources by CNAME target and error page signature, including provider-specific claim paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["cname takeover", "cname fingerprint", "dangling cname exploit"]
cwe: [CWE-350]
owasp: []
attack: [T1584]
capec: [CAPEC-141]
related: [subdomain-takeover, subdomain-takeover-ns-and-service-takeover, sql-injection, cross-site-scripting]
parent: subdomain-takeover
corpus_sparse: true
---

# Subdomain Takeover Cname Fingerprints - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

This leaf targets the resolvable-dangling-service category: a CNAME record that still resolves to a third-party provider host (S3, GitHub Pages, Heroku, Azure Websites, Fastly) whose backing resource was deleted, so the provider answers with a recognizable default or not-found page. Identification turns on the CNAME target and the provider error-page signature, because each provider emits a distinct body such as an S3 `NoSuchBucket` XML or a Pages 404. The decision point is matching the terminal CNAME host to a provider whose claim path lets a new tenant register the exact resource name embedded in that host. The attacker gains content control under the trusted subdomain. Confirmation is the provider fingerprint on a CNAME whose resource the organization no longer owns.

- **Precondition chain:** The subdomain is a CNAME to a provider host, the backing resource at that host is deleted or unclaimed, the provider serves a recognizable unclaimed-resource page, and the resource name is re-registrable by any tenant.
- **Readable differential:** Fetch the CNAME target and compare its body against the provider known unclaimed-resource signature versus a claimed-resource response; a finding exists when the signature matches on a name the organization no longer owns, and it closes when the CNAME is removed.
- **Empirical grounding:** CWE-350 and MITRE ATT&CK T1584. The Cloud Security Alliance (April 2025) resolvable-dangling-service category and the Hazy Hawk reporting on dangling CNAME cloud-resource hijacking anchor this leaf; the attached grounding note marks it corpus-sparse.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the CNAME target is an S3, CloudFront, or other AWS host **THEN** match the `NoSuchBucket` or distribution signature and check the bucket name against the region namespace
2. **IF** the CNAME target is a GitHub Pages or Netlify host **THEN** match the Pages 404 or Netlify not-found signature and test whether the repository or site name is claimable
3. **IF** the CNAME target is a Heroku, Azure Websites, or Fastly host **THEN** match the provider welcome or unknown-domain page and confirm the app name is free
4. **IF** the target profile is not yet confirmed as a CNAME fingerprint case **THEN** start at parent class [`subdomain-takeover`](../subdomain-takeover/SKILL.md) (1 hop)
5. **IF** the CNAME target returns NXDOMAIN rather than a provider page **THEN** switch to [`subdomain-takeover-ns-and-service-takeover`](../subdomain-takeover-ns-and-service-takeover/SKILL.md) (1 hop) for the delegation and service categories
6. **IF** the record is an A record to an unallocated address, not a CNAME **THEN** return to the parent for the unallocated-address category
7. **IF** the provider shows a fingerprint but reserves the name to the original owner **THEN** record a non-claimable dangling record and do not report a takeover
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the CNAME resolves to a provider resource the organization still owns **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target resolves to NXDOMAIN rather than a provider default page | [`subdomain-takeover-ns-and-service-takeover`](../subdomain-takeover-ns-and-service-takeover/SKILL.md) | The NXDOMAIN and service category needs delegation-aware handling, not page fingerprinting |
| The claimed subdomain is then used to defeat a CSP allowlist | [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) | The onward invariant is policy allowlisting rather than resource ownership |
| Content on the claimed host runs script against the parent origin | [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) | Impact becomes persistent script execution, a distinct control |
| Need parent class methodology | [`subdomain-takeover`](../subdomain-takeover/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Collect the terminal CNAME target for each subdomain.** Resolve the chain and record the final provider hostname, because the fingerprint class is decided by that host such as `s3.amazonaws.com`, `github.io`, `herokudns.com`, or `azurewebsites.net`.
2. **Map the host to a provider and its signature.** Associate the CNAME target with the provider known unclaimed-resource page: an S3 `NoSuchBucket` XML, a GitHub Pages 404, a Heroku `No such app`, or an Azure default page.
3. **Record a claimed-resource baseline.** Fetch a known-owned resource on the same provider and capture its body so the unclaimed signature is distinguishable from live content.
4. **Fetch the candidate and match the signature.** Request the subdomain over HTTP and HTTPS and compare the body, status, and headers against the provider signature from the mapping step.
5. **Extract the claimable resource identifier.** Parse the bucket, repository, or app name out of the CNAME target and confirm through a read-only provider API or console whether that identifier is currently unregistered.
6. **Stop condition.** Halt when the candidate (a) matches a provider unclaimed signature and the resource name is free, (b) matches live owned content, or (c) would require creating the resource and serving third-party content to prove. Case (a) confirms, (b) is a non-finding, (c) exceeds non-destructive scope.
7. **State what counts as proof.** Proof is the provider signature on a CNAME the organization no longer controls plus a read-only availability check showing the resource name is free, captured as the CNAME target, the matched signature string, and the availability result. A bare 404 with no provider signature does not qualify.
8. **Close with the structural fix.** Delete the CNAME from the zone before releasing the provider resource, and where the provider supports it keep a verification binding that reserves the name to the account. Verify by re-resolving the label to NXDOMAIN.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An S3 `NoSuchBucket` XML body on a CNAME to an `s3.amazonaws.com` host | Proves the resolvable-dangling-service category on AWS with a re-registrable bucket name |
| A GitHub Pages 'there isn't a site here' body on a `github.io` CNAME | Proves an unclaimed Pages site whose repository name may be claimable |
| A Heroku `No such app` page on a `herokudns.com` CNAME | Proves an unclaimed Heroku app name on the Heroku platform |
| An Azure `azurewebsites.net` default page on a dangling CNAME | Proves an unclaimed App Service name on Azure |
| A Fastly unknown-domain error on a CNAME to a Fastly edge | Proves an unconfigured service on the Fastly CDN that may accept the domain |
| The CNAME target embedding a resource name a read-only API reports as free | Proves claimability, the second half of the fingerprint proof standard |
| A claimed-owned baseline returning live content while the candidate returns the signature | Proves the difference is unclaimed state, not a provider-wide outage |

## Worked Contrast

**Vulnerable pattern:**

```python
def retire_site(provider, zone):
    # Removes the GitHub Pages site but keeps the CNAME to org.github.io
    provider.delete_pages_site(repo="marketing-legacy")
    # marketing.example.com -> org.github.io still resolves and is claimable
    return "pages site deleted"
```

**Hardened pattern:**

```python
def retire_site(provider, zone):
    # Remove the CNAME first so the label stops resolving to github.io
    zone.delete_record(name="marketing.example.com", rtype="CNAME")
    zone.assert_nxdomain(name="marketing.example.com")
    # Then delete the Pages site; the label never points at a free repo
    provider.delete_pages_site(repo="marketing-legacy")
    return "cname removed before pages site"
```

**Why this matters:** The defect deletes the provider resource but leaves the CNAME, so anyone who recreates the repository serves content under the trusted label. The fix removes the CNAME and confirms NXDOMAIN before deleting the Pages site, eliminating the fingerprintable dangling target.

## When It Is NOT This Issue

- **Provider-wide outage:** a `NoSuchBucket` or 503 during a provider incident can look like a dangling record; re-test after the incident and against an owned baseline.
- **Name reserved to the owner:** providers that bind a verified domain to the account show the fingerprint but will not let others claim the resource name.
- **Live site returning a path 404:** a path-level 404 on an owned site is not a provider unclaimed-resource signature; match the exact provider body.
- **CNAME to an internal or owned host:** a CNAME to another owned domain is not a third-party dangling record.
- **Stale fingerprint database:** matching against an outdated signature set can misclassify a provider new default page; verify the current signature.
- **Already claimed by the organization:** the resource is unclaimed in the public namespace but the organization holds it under a different account; confirm ownership before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `subdomain-takeover-cname-fingerprints` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `subdomain-takeover-cname-fingerprints` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: subdomain-takeover-cname-fingerprints
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-350 | Mapping: T1584]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`subdomain-takeover`](../subdomain-takeover/SKILL.md) - Web and Application (leaf)
- [`subdomain-takeover-ns-and-service-takeover`](../subdomain-takeover-ns-and-service-takeover/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `subdomain-takeover-cname-fingerprints` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-350, T1584`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
