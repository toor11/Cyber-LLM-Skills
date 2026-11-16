---
name: subdomain-takeover-ns-and-service-takeover
description: NS delegation and service level takeover. Covers takeover through expired or dangling NS delegations and through deprovisioned services that still resolve. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["ns takeover", "nameserver takeover", "dangling ns", "delegation takeover"]
cwe: [CWE-350]
owasp: []
attack: [T1584]
capec: [CAPEC-141]
related: [subdomain-takeover, subdomain-takeover-cname-fingerprints, sql-injection, cross-site-scripting]
parent: subdomain-takeover
---

# Subdomain Takeover Ns and Service Takeover - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This leaf covers two higher-impact dangling categories: a dangling NS delegation and a deprovisioned service that still resolves. An NS takeover arises when a label is delegated to nameservers the organization no longer controls (a lapsed DNS-hosting account or an expired nameserver domain), letting whoever registers those nameservers answer authoritatively for the entire delegated label and every record beneath it. A service-level takeover arises when the record points at an expired service domain or an unallocated address such as a released elastic IP that an attacker can re-acquire. The decision point is whether the authority for the name, rather than a single host content, has been abandoned; NS control yields the whole subtree including new certificate issuance and MX. Confirmation is a nameserver or provider fingerprint on a delegation or address the organization no longer controls.

- **Precondition chain:** The parent zone delegates a label via NS or publishes a record to infrastructure the organization no longer owns, that nameserver account, domain, or address is re-registrable, and no higher authority overrides the stale delegation.
- **Readable differential:** Query the delegated label at the parent nameservers versus at the delegated nameservers; a finding exists when the delegated nameservers are unregistered or re-acquirable while the parent still delegates to them, and it closes when the NS or service record is removed from the parent zone.
- **Empirical grounding:** CWE-350 and MITRE ATT&CK T1584. The Cloud Security Alliance (April 2025) NXDOMAIN-target and unallocated-address categories plus the delegation case anchor this leaf, with the Hazy Hawk reporting on cloud-resource hijacking.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the label is delegated by NS records to a lapsed DNS-hosting account **THEN** test whether those nameserver names are re-registrable at the hosting provider to gain authority over the whole label
2. **IF** the delegated nameserver domain itself has expired **THEN** check registrar availability of that nameserver domain, which would hand over the subtree
3. **IF** the record points at an expired third-party service domain **THEN** classify as a service-level takeover and test re-registration of the service identifier
4. **IF** the record is an A record to a released elastic IP **THEN** treat it as the unallocated-address category and attempt to re-acquire the address in the same region and account tier
5. **IF** the target profile is not yet confirmed as NS or service takeover **THEN** start at parent class [`subdomain-takeover`](../subdomain-takeover/SKILL.md) (1 hop)
6. **IF** the dangling record is a CNAME to a provider default page **THEN** switch to [`subdomain-takeover-cname-fingerprints`](../subdomain-takeover-cname-fingerprints/SKILL.md) (1 hop)
7. **IF** the delegation resolves to nameservers the organization still controls **THEN** record a healthy delegation and do not report a takeover
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every delegated nameserver and service resolves to owned infrastructure **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The dangling record is a CNAME with a provider default page | [`subdomain-takeover-cname-fingerprints`](../subdomain-takeover-cname-fingerprints/SKILL.md) | That is the resolvable-service category identified by page signature, not by delegation |
| Authority over the label is used to intercept mail via a forged MX | [`email-header-injection`](../email-header-injection/SKILL.md) | The onward invariant is mail routing and header trust, not DNS ownership |
| The reacquired address fronts an internal service reachable by hostname | [`dns-rebinding-attacks`](../dns-rebinding-attacks/SKILL.md) | The flaw becomes Host-header trust for local services, fixed by allowlisting plus authentication |
| Need parent class methodology | [`subdomain-takeover`](../subdomain-takeover/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Separate the delegation from the content.** For each label read the parent zone NS set and compare it to the NS set the delegated nameservers themselves return, and note any service record alongside such as an A to an elastic IP or a CNAME to a service domain.
2. **Classify the abandonment.** Decide whether authority is dangling (NS pointing at a lapsed hosting account or an expired nameserver domain) or the service is dangling (an expired service domain or a released address), because the claim path differs.
3. **Record an authoritative baseline.** Query a healthy delegated label and capture which nameservers answer and with what SOA, so a lame or unregistered delegation stands out.
4. **Probe the delegated authority.** Query the delegated nameservers directly for the label; a SERVFAIL, REFUSED, or lame response indicates they no longer serve the zone, and a registrar or provider check shows whether they are re-acquirable.
5. **Test re-acquisition without taking authority.** Check, read-only, whether the nameserver names, the service domain, or the elastic IP can be registered or allocated by a new tenant, the condition that enables the takeover.
6. **Stop condition.** Halt when the delegation or service (a) points at infrastructure the organization no longer controls and that infrastructure is re-acquirable, (b) resolves through owned nameservers and services, or (c) would require actually taking authority or routing mail to prove. Case (a) confirms, (b) is a non-finding, (c) exceeds non-destructive scope.
7. **State what counts as proof.** Proof is a nameserver or provider fingerprint on a delegation or address you do not control plus a read-only availability result, captured as the parent NS set, the delegated response code, and the registrability check. A transient SERVFAIL without a registrability finding is not proof.
8. **Close with the structural fix.** Remove the stale NS delegation or service record from the parent zone before the referenced nameservers, service, or address are released, and renew or transfer delegated nameserver domains under organizational control. Verify by confirming the parent no longer delegates the label and it resolves NXDOMAIN.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Parent NS records delegating a label to nameservers that return SERVFAIL or REFUSED | Proves a lame delegation where re-registering the nameserver grants authority over the whole label |
| A delegated nameserver whose domain is expired and registrable | Proves whole-subtree takeover is possible, beyond single-host content |
| An A record pointing at a released elastic IP in a known cloud range | Proves the unallocated-address service category on that cloud provider |
| A CNAME or SRV to an expired service domain that is now registrable | Proves a service-level takeover through re-registration of the service identifier |
| The delegated nameservers belonging to a cancelled DNS-hosting account | Proves the authority is abandoned at the provider, the root cause of NS takeover |
| An MX pointing at a deprovisioned mail service domain | Proves mail interception is possible if the service name is re-registered |
| The parent SOA and the delegated SOA disagreeing on authority | Proves the delegation is stale rather than a transient resolver error |

## Worked Contrast

**Vulnerable pattern:**

```python
def offboard_zone(registrar, dns_host):
    # Cancels the DNS-hosting account while the parent still delegates via NS
    dns_host.close_account(zone="legacy.example.com")
    # Parent NS still points at ns1/ns2 of the closed account, now re-registrable
    return "dns hosting closed"
```

**Hardened pattern:**

```python
def offboard_zone(registrar, dns_host):
    # Remove the NS delegation from the parent zone first
    registrar.delete_delegation(label="legacy", parent="example.com")
    registrar.assert_no_ns(label="legacy", parent="example.com")
    # Only then close the hosting account; no authority is left dangling
    dns_host.close_account(zone="legacy.example.com")
    return "delegation removed before account closure"
```

**Why this matters:** The defect closes the delegated nameserver account while the parent still delegates to it, letting an attacker who re-registers those nameservers serve the entire subtree. The fix removes the NS delegation from the parent and confirms its absence before closing the account, so no abandoned authority remains.

## When It Is NOT This Issue

- **Transient SERVFAIL:** a one-off resolver failure is not a dangling delegation; re-query across resolvers and confirm registrability before reporting.
- **Owned nameservers:** the label delegates to the organization own nameservers that are simply misconfigured, which is an availability bug, not a takeover.
- **Glue-record lag:** a recently changed delegation may show stale glue briefly; verify against the registry, not just a cache.
- **Non-registrable provider nameservers:** some providers reserve nameserver hostnames to the account, so a lame delegation cannot actually be claimed.
- **Elastic IP still in the account:** an A record to an address the organization still holds is not unallocated even when the instance is stopped.
- **Internal split-horizon delegation:** an NS delegation only present in an internal view has no public takeover path.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `subdomain-takeover-ns-and-service-takeover` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `subdomain-takeover-ns-and-service-takeover` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: subdomain-takeover-ns-and-service-takeover
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-350 | Mapping: T1584]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`subdomain-takeover`](../subdomain-takeover/SKILL.md) - Web and Application (leaf)
- [`subdomain-takeover-cname-fingerprints`](../subdomain-takeover-cname-fingerprints/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `subdomain-takeover-ns-and-service-takeover` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-350, T1584`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/expku (2), hackerone_disclosed_reports (1), CYBER_CPT/blackhills (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
