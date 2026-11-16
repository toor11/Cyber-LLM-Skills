---
name: cross-site-scripting-csp-bypass
description: "XSS under Content Security Policy. Covers reaching script execution when CSP blocks inline script: JSONP endpoints, whitelisted CDN abuse, script gadgets, nonce prediction or reuse, and base-uri gaps. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: web-and-application
tier: leaf
triggers: ["csp bypass xss", "xss with csp", "nonce bypass", "jsonp xss", "script gadget xss"]
cwe: [CWE-79]
owasp: [A03:2021, A05:2025]
attack: [T1059]
capec: [CAPEC-63]
related: [cross-site-scripting, cross-site-scripting-reflected, cross-site-scripting-stored, cross-site-scripting-dom]
parent: cross-site-scripting
---

# Cross Site Scripting CSP Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

An injection point exists but a Content-Security-Policy is meant to stop the script from running, so the work is reaching execution despite the policy rather than finding the injection. Host-allowlist policies fail structurally: an allowed host that serves a JSONP or callback-style endpoint, or a bundled copy of a template library like AngularJS, turns the allowlist into an execution gadget, and PortSwigger's allowlist-gadget dataset shows how widespread those hosts are. Other structural gaps are a missing base-uri that lets an injected base tag retarget relative scripts, and a missing form-action, which does not inherit from default-src, so a password form can post cross-origin with no JavaScript at all. The security decision is the policy shape: a per-response nonce with strict-dynamic ignores host allowlists, and require-trusted-types-for 'script' is required to enforce Trusted Types. Confirmation is reaching script execution or credential egress while the policy header is present.

- **Precondition chain:** An injection sink exists under an active CSP, the policy relies on a host allowlist or omits base-uri or form-action, an allowed host exposes a JSONP, callback, or bundled framework gadget (or no nonce and strict-dynamic are used), and execution or credential egress is reachable without an inline-script exception.
- **Readable differential:** The injected payload under the deployed host-allowlist policy versus under a nonce-plus-strict-dynamic policy; a finding exists when the gadget or form-action gap yields execution or credential egress with the header present, and it closes once the policy is a per-response nonce with strict-dynamic and explicit base-uri and form-action.
- **Empirical grounding:** CWE-79 under OWASP Top 10:2025 A05:2025 Injection; PortSwigger's 'Blind trust: stealing credentials through CSP' documents allowlist gadgets and form-action not inheriting from default-src, and per caniuse require-trusted-types-for 'script' is required to enforce Trusted Types, which a pass-through default policy or trusted-types * defeats.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be execution under an active CSP **THEN** start at the parent class [`cross-site-scripting`](../cross-site-scripting/SKILL.md) first
2. **IF** no CSP header is present at all on the response **THEN** drop back to the core injection invariant and read [`cross-site-scripting`](../cross-site-scripting/SKILL.md)
3. **IF** an allowlisted script-src host serves a JSONP or callback endpoint **THEN** treat the allowed host as an execution gadget and target that endpoint
4. **IF** an allowlisted host serves a bundled AngularJS or template library copy **THEN** treat the framework copy as a gadget and test its expression sink
5. **IF** form-action is unset so a password form can post cross-origin **THEN** test credential egress with no JavaScript, since form-action does not inherit from default-src
6. **IF** a script-src host is itself dangling or takeoverable **THEN** confirm DNS ownership and read [`subdomain-takeover`](../subdomain-takeover/SKILL.md)
7. **IF** execution rides a JavaScript framework prototype gadget **THEN** treat the sink gadget and read [`prototype-pollution`](../prototype-pollution/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** a per-response nonce with strict-dynamic is enforced and base-uri and form-action are set **THEN** STOP and record a verified non-finding because the host-allowlist gadgets no longer apply

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| No policy is present at all | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | Routes back to the core injection invariant without a policy layer |
| An allowlisted script-src host is takeoverable | [`subdomain-takeover`](../subdomain-takeover/SKILL.md) | Invariant is DNS ownership of a script-src host |
| Execution relies on a framework prototype gadget | [`prototype-pollution`](../prototype-pollution/SKILL.md) | Invariant is a sink gadget reached without inline script |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Parse the deployed policy directive by directive.** Read script-src, object-src, base-uri, and form-action from the response header, and record whether execution is gated by a host allowlist or by a per-response nonce with strict-dynamic.
2. **Classify each allowed host as a potential gadget.** For every script-src host, check whether it serves a JSONP or callback endpoint or a bundled template-library copy, because those convert the allowlist into an execution path.
3. **Identify the missing-directive gaps.** Note a missing base-uri that allows an injected base tag to retarget scripts, and a missing form-action, which does not inherit from default-src and therefore leaves cross-origin form posts unrestricted.
4. **Record a policy-present baseline.** Confirm that a plain inline script is blocked and a violation report fires, so you know the policy is actually enforcing before testing a bypass.
5. **Apply the gadget-versus-nonce differential.** Load script through an allowed-host JSONP or framework gadget, or exfiltrate via the form-action gap, and compare behaviour against what a nonce-plus-strict-dynamic policy would allow; success with the header present selects the finding.
6. **Stop condition.** Halt when the probe either (a) reaches execution or credential egress under the live policy and would be blocked by a per-response nonce with strict-dynamic, (b) is blocked by the current policy with no gadget or directive gap, or (c) would require exfiltrating real credentials to demonstrate. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a benign script execution or a benign cross-origin form post occurring while the CSP header is present, tied to a named allowed-host gadget or a missing base-uri or form-action, plus the directive that permitted it. A blocked inline attempt is not proof of a bypass.
8. **Close with the structural fix and verify.** Replace the host allowlist with a per-response nonce and strict-dynamic, set object-src 'none', base-uri 'none', and an explicit form-action, and add require-trusted-types-for 'script', then replay the gadget and confirm it is now blocked.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A script-src host that also serves a JSONP endpoint with a callback parameter | Proves an allowlist-gadget execution path on any policy that trusts a callback-serving host |
| An allowlisted CDN hosting a bundled AngularJS or template library copy | Proves a framework-gadget bypass where the trusted host's own code evaluates an expression sink |
| A policy with no base-uri directive | Proves an injected base tag can retarget relative script URLs to an attacker origin |
| A policy with no form-action directive | Proves cross-origin credential egress with no JavaScript because form-action does not inherit from default-src |
| script-src using a host allowlist instead of a per-response nonce with strict-dynamic | Proves the policy shape that allowlist gadgets defeat, the structural weakness this skill targets |
| trusted-types * or a pass-through default policy with require-trusted-types-for absent | Proves Trusted Types is not enforced, leaving DOM sink injection unguarded |
| An inline script blocked and reported while a gadget-loaded script runs | Proves the policy enforces yet is bypassed through an allowed host, the defining evidence here |

## Worked Contrast

**Vulnerable pattern:**

```http
Content-Security-Policy: default-src 'self';
  script-src 'self' https://cdn.example https://accounts.example;
  object-src 'none'
# script-src trusts a host that also serves a JSONP callback, and no form-action
# is set, so default-src does not cover form posts and a password form can post
# cross-origin with no script at all
```

**Hardened pattern:**

```http
Content-Security-Policy: script-src 'nonce-rAnd0mPerResponse' 'strict-dynamic';
  object-src 'none'; base-uri 'none'; form-action 'self';
  require-trusted-types-for 'script'
# a fresh per-response nonce with strict-dynamic ignores host allowlists and JSONP
# gadgets; form-action 'self' is declared explicitly because it never inherits from
# default-src, and Trusted Types enforcement guards the DOM sinks
```

**Why this matters:** The vulnerable policy gates execution on a host allowlist, so an allowed host's JSONP endpoint becomes a script gadget, and because form-action is unset a credential form can post anywhere. The fixed policy ties execution to a per-response nonce with strict-dynamic, which disregards host allowlists, and declares base-uri, form-action, and require-trusted-types-for explicitly.

## When It Is NOT This Issue

- **Nonce plus strict-dynamic enforced:** a policy that gates scripts on a fresh per-response nonce with strict-dynamic is not bypassable through host-allowlist gadgets.
- **Blocked inline attempt:** an inline script that the policy refuses and reports is the policy working, not a demonstrated bypass.
- **Report-only policy:** a Content-Security-Policy-Report-Only header does not block anything, so a 'bypass' of it changes no security outcome.
- **Allowed host serves no gadget:** a script-src host with no JSONP, callback, or bundled framework copy offers no execution path even though it is allowlisted.
- **Static nonce reused across responses:** a predictable or reused nonce is its own weakness but must be shown reusable before claiming a bypass.
- **No injection sink at all:** a strong or weak CSP is irrelevant if there is no point where attacker input reaches the page.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cross-site-scripting-csp-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cross-site-scripting-csp-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cross-site-scripting-csp-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-79 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cross-site-scripting-csp-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (4), CYBER_CPT/go_exploitdb (3), hackerone_disclosed_reports (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
