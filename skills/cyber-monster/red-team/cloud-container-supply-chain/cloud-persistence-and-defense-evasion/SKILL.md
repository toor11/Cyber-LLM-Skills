---
name: cloud-persistence-and-defense-evasion
description: "Establishes and hides persistence in cloud environments: extra access keys, backdoor roles, trust modifications and audit log gaps. Use when demonstrating durable cloud access."
family: cloud-container-supply-chain
tier: leaf
triggers: ["cloud persistence", "iam backdoor", "cloud defense evasion", "audit log gap"]
cwe: [CWE-269]
owasp: []
attack: [T1098]
capec: [CAPEC-563]
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
corpus_sparse: true
---

# Cloud Persistence and Defense Evasion - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Persistence in a cloud estate means a credential or a grant that survives the incident response that removes the original access. The mechanisms are enumerable per provider and each has a detection surface. New credentials: `iam:CreateAccessKey` on another user, an additional login profile, an app registration secret or certificate in Entra, a service-account key in GCP. Additional grants: a new role assignment, a trust policy edit that adds a principal, a federated credential that names an attacker-controlled subject. Compute persistence: a Lambda function with a scheduled trigger, a container image with a startup hook, a startup script in an instance template, a Systems Manager association. Federation persistence: a SAML identity provider added to the tenant, a domain federation change, an OAuth application consented with `AllPrincipals`. Defence evasion in this context is mostly log-side: stopping CloudTrail, excluding an account from an organisation trail, disabling a GuardDuty detector, or changing a diagnostic setting, all of which are configuration writes with their own audit records. The review question is which of these mechanisms is possible given the primitive set, and which detection surface would catch it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a principal can create credentials for another identity **THEN** that is persistent access and the finding is the primitive, not any specific key.
2. **IF** a principal can write trust policies or federation configuration **THEN** the persistence survives credential rotation; rank it above key creation.
3. **IF** the concern is log-side evasion **THEN** enumerate the trail, detector, and diagnostic-setting write permissions separately, because they are a distinct primitive set.
4. **IF** the mechanism is a scheduled compute resource **THEN** the detection surface is the resource type's create event, not the runtime.
5. **IF** the question is how to remove persistence **THEN** this skill names the objects; the response procedure belongs to the blue-team incident-response family.
6. **IF** the estate uses Identity Center **THEN** check for additional permission sets and assignments, which are less visible than IAM roles.
7. **IF** the question is which primitives enable the persistence in the first place **THEN** start at [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) for the permission graph and return here for the object inventory.
8. **IF** the mechanism is a new key on a service account rather than an IAM user **THEN** work through [`gcp-attacks`](../gcp-attacks/SKILL.md) for the constraint and key inventory.
9. **IF** no principal holds a credential-creation, trust-write, or logging-write primitive **THEN** record `Verified Safe` with the primitive list you checked.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the persistence primitives held.** Credential creation, trust and federation writes, scheduled compute, and logging writes. Each is a small action set and each maps to a specific object type.
2. **Map each to its detection surface.** Key creation is an audit event with the key id; trust writes are policy-change events; scheduled compute is a create event for the resource; logging writes are configuration events.
3. **Choose the branch.** Credential persistence, grant persistence, compute persistence, or log evasion.
4. **Define the baseline-vs-probe differential.** Baseline: the inventory of credentials, grants, and scheduled resources for an identity, as recorded before the review. Probe: the same inventory today. A new object that no change record explains is the persistence.
5. **Name the stop condition.** Stop at the first unexplained persistent object reachable by an attacker-held principal. Do not delete anything, and do not create a key to prove the primitive.
6. **State the proof.** Report the object type, the identifier, the creating principal, the timestamp, and the detection event that recorded it. If the primitive is held but no object exists, report the capability with the enumeration that would find it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A second access key on an IAM user | A credential that survives revocation of the first | AWS IAM, `iam:CreateAccessKey` |
| A role trust policy naming an external account root | A grant that survives credential rotation and is invisible in identity policy review | AWS role trust policies |
| An Entra app registration secret or certificate added by a non-owner | Application persistence that survives user password resets | Entra app registrations |
| A `System.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write` grant | The ability to add an external subject to an identity | Azure workload identity |
| A Lambda function with an `events.amazonaws.com` schedule rule | Compute persistence that runs without any inbound path | EventBridge, Lambda |
| A trail with `IsMultiRegionTrail` false or an excluded account | Log-side evasion: events in that scope are not recorded | CloudTrail organisation trails |

## Worked Contrast

**Vulnerable: credential and trust persistence available to a single role**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["iam:CreateAccessKey", "iam:CreateLoginProfile"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["iam:UpdateAssumeRolePolicy"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["cloudtrail:StopLogging", "cloudtrail:UpdateTrail"], "Resource": "*"}
  ]
}
```

**Hardened: no credential creation, no trust writes, logging protected by a separate custody boundary**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["iam:GetRole", "iam:ListAttachedRolePolicies"],
     "Resource": "arn:aws:iam::111122223333:role/api-*"},
    {"Sid": "DenyLogTamper", "Effect": "Deny",
     "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"],
     "Resource": "*"}
  ]
}
```

**Why this matters:** The left policy lets one compromised role create a second credential, add itself to any role's trust, and stop the trail that would record either — three independent persistence paths and the means to hide them. The right policy grants only read access to the roles in scope and adds an explicit deny on logging changes, so persistence needs a principal outside this role and the trail records every attempt.

## When It Is NOT This Issue

- **A second access key created during a documented rotation.** The rotation record explains it; check the ticket before the finding.
- **A trust policy that names a specific role ARN in a partner account with an external id.** That is a designed integration.
- **A scheduled Lambda that the deployment pipeline created and that appears in the infrastructure-as-code state.** Explained by code.
- **A diagnostic setting changed by the platform team during an incident.** Check the change record.
- **`iam:CreateAccessKey` held by an identity that is itself the account's break-glass principal.** The custody argument matters more than the primitive.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cloud-persistence-and-defense-evasion` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cloud-persistence-and-defense-evasion` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cloud-persistence-and-defense-evasion
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1098]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-persistence-and-defense-evasion` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1098`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
