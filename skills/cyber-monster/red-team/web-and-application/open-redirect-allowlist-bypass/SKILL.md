---
name: open-redirect-allowlist-bypass
description: Open redirect allowlist bypass. Covers defeating allowlist checks with subdomain tricks, userinfo, scheme-relative URLs, backslash and encoding differentials. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["open redirect bypass", "redirect allowlist bypass", "url parsing bypass"]
cwe: [CWE-601]
owasp: [A01:2021]
attack: []
capec: [CAPEC-178]
related: [open-redirect, open-redirect-chain-to-token-theft, sql-injection, cross-site-scripting]
parent: open-redirect
---

# Open Redirect Allowlist Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

The application already tries to confine redirect destinations to its own hosts, but the allowlist comparison and the browser's URL parser disagree on where the host actually is. A suffix test matches evil-target.example, a substring test matches anything containing the brand, a userinfo form hides the real authority after an @, and a URL-encoded or backslash form is validated in one shape and resolved in another. The decision point is string comparison against the destination, performed before the value is fully normalised. The attacker supplies a URL that satisfies the flawed check yet navigates off-site, so the gain is identical to a bare open redirect but through a control that looked present. Confirmation is that one encoded or userinfo form navigates off-domain while the same literal foreign host is rejected.

- **Precondition chain:** A redirect allowlist exists, the comparison is a suffix, substring, or pre-decode check rather than exact host membership, and at least one encoding or authority form resolves to a foreign host after the check passes.
- **Readable differential:** A literal foreign host that the allowlist rejects versus an encoded, userinfo, or subdomain form of the same host that it accepts; reverting to exact-host membership after full normalisation rejects both.
- **Empirical grounding:** CWE-601 under OWASP Top 10:2025 A01 Broken Access Control; CVE-2025-40927 (CGI::Simple HTTP response splitting bypassed through URL-encoded values) shows existing validation defeated by encoding, and RFC 9700 mandates exact-match destination allowlists rather than prefix or suffix checks.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match an allowlist bypass **THEN** start at parent class [`open-redirect`](../open-redirect/SKILL.md) for general triage
2. **IF** the allowlist is a suffix or `endsWith` test on the host **THEN** probe `target.example.<attacker>` and `nottarget.example` to separate suffix matching from exact membership
3. **IF** the check parses only up to the first `@` or misreads userinfo **THEN** probe `https://target.example@<attacker>` to expose authority confusion
4. **IF** validation runs before URL decoding **THEN** probe single and double percent-encoded authority forms that reintroduce the foreign host after decode
5. **IF** the same host-parsing gap appears in a server-side fetcher **THEN** route to [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) where validation and resolution disagree in the connector
6. **IF** the bypass depends on Unicode, best-fit, or case folding **THEN** route to [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) for normalisation-before-comparison
7. **IF** a confirmed off-site redirect can feed an OAuth code leak **THEN** route to [`open-redirect-chain-to-token-theft`](../open-redirect-chain-to-token-theft/SKILL.md) to assess token impact
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every encoded, userinfo, and subdomain form resolves back to an allowed host **THEN** STOP and record the allowlist as a working control rather than forcing a bypass

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The same host-parsing gap appears in a server-side fetcher | [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) | Validation versus resolution disagreement in the connector, not the browser |
| The bypass relies on Unicode or best-fit character mapping | [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) | The invariant is normalisation before comparison, a charset decision |
| A confirmed off-site redirect is chained into an OAuth code leak | [`open-redirect-chain-to-token-theft`](../open-redirect-chain-to-token-theft/SKILL.md) | Impact shifts from navigation to authorization-code theft |
| Need parent class methodology | [`open-redirect`](../open-redirect/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the allowlist comparison itself.** Find whether the code uses `endsWith`, `contains`, a regex, or exact set membership, and whether it runs on the raw value or a parsed host. The shape of the comparison is the branch selector.
2. **Determine the normalisation order.** Establish whether decoding, lowercasing, and host parsing happen before or after the check. A check that precedes decoding is the single most productive gap.
3. **Record a rejection baseline.** Send a plainly foreign host and confirm it is refused, capturing the exact status and Location. Without a confirmed rejection there is nothing to bypass.
4. **Attack the comparison, not the destination.** For a suffix test send `target.example.<attacker>`; for a substring test send `<attacker>/?target.example`; for userinfo send `trusted@attacker`; for a pre-decode check send percent-encoded authority. Each form targets one specific flaw in the comparison.
5. **Escalate encoding one layer at a time.** Try single, then double percent-encoding, then backslash and mixed forms, stopping at the first that both passes the check and navigates off-site.
6. **Stop condition.** Halt when a probe either (a) passes the allowlist and lands the browser on a foreign host, reverting when exact membership is enforced, (b) is rejected in every encoded and authority form, or (c) would require live victim interaction to demonstrate impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single destination value that the allowlist accepts yet resolves to an attacker host, paired with the exact comparison line and a demonstration that the literal foreign host is rejected. Passing the check without off-site navigation is not proof.
8. **Close with the structural fix and verify it.** Parse the URL, normalise and lowercase the host, then require exact membership in a closed host set, rejecting userinfo and scheme-relative forms outright; re-run every bypass form to confirm each now fails.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A host check implemented as `endsWith("target.example")` | Proves a suffix comparison that `target.example.<attacker>` satisfies, a false-authority gap on any hand-rolled validator |
| A `contains` or regex check that matches the brand anywhere in the URL | Proves a substring comparison bypassable by placing the brand in a path or query on any stack |
| A `trusted@attacker` userinfo form accepted by the check | Proves the validator parsed userinfo as the host, a URL-authority confusion common in manual parsing |
| A percent-encoded authority accepted because validation precedes decoding | Proves a validate-before-decode ordering bug that reintroduces the foreign host after the check |
| A backslash form accepted by the server but normalised to a slash by the browser | Proves a parser differential between the comparison and the navigating client |
| The literal foreign host is rejected while an encoded sibling is accepted | Proves the bypass is in the comparison shape, not an absent control, on this specific endpoint |

## Worked Contrast

**Vulnerable pattern:**

```python
from urllib.parse import urlsplit
from flask import request, redirect

def go():
    target = request.args.get("redirect", "/")
    host = urlsplit(target).hostname or ""
    # Suffix check: both 'nottarget.example' and 'target.example.evil' slip through
    if host.endswith("target.example"):
        return redirect(target)
    return redirect("/")
```

**Hardened pattern:**

```python
from urllib.parse import urlsplit
from flask import request, redirect

ALLOWED_HOSTS = {"target.example", "www.target.example"}

def go():
    target = request.args.get("redirect", "/")
    parts = urlsplit(target)
    host = (parts.hostname or "").lower()
    # Exact host membership after full parse; userinfo and scheme-relative forms cannot satisfy it
    if parts.scheme in {"http", "https"} and host in ALLOWED_HOSTS and not target.startswith("//"):
        return redirect(target)
    return redirect("/")
```

**Why this matters:** The vulnerable suffix test confuses where the host ends; the fix parses the URL, lowercases the host, and requires exact membership in a closed set, so brand-prefixed subdomains, userinfo authorities, and scheme-relative forms all fail.

## When It Is NOT This Issue

- **Exact membership already enforced:** the host is compared against a closed set after parsing, so every encoded and userinfo form is refused.
- **Encoded form rejected before decode too:** the value is canonicalised first, so a double-encoded authority never reaches a weaker check.
- **Brand string in path only:** a URL containing the brand in its path but with a foreign host is already rejected by the host-level check.
- **Bypass passes the check but stays on-origin:** a form that satisfies the comparison yet still resolves to an in-app host carries no off-site impact.
- **Allowlist is for display, not redirect:** the matched value styles a link label but a separate server-side route decides the actual destination.
- **Punycode already normalised:** an internationalised look-alike host is converted and compared in a canonical form, closing the homograph angle.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `open-redirect-allowlist-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `open-redirect-allowlist-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: open-redirect-allowlist-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-601 | Mapping: A01:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`open-redirect`](../open-redirect/SKILL.md) - Web and Application (leaf)
- [`open-redirect-chain-to-token-theft`](../open-redirect-chain-to-token-theft/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `open-redirect-allowlist-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-601`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/nuclei_templates (1), CYBER_CPT/go_exploitdb (1), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
