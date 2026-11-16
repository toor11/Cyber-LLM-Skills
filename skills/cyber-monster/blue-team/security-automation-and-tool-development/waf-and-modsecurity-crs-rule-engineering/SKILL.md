---
name: waf-and-modsecurity-crs-rule-engineering
description: "Authors and regression-tests ModSecurity SecLang / OWASP CRS rules and AWS/Cloudflare WAF expressions: scoping phase/variable targets (`ARGS`, `REQUEST_HEADERS`), setting anomaly scores, writing surgical path/parameter false-positive exclusions (`ctl:ruleRemoveTargetById`), and testing via `ftw`/`go-ftw`. Use when engineering WAF rules without breaking app traffic."
family: security-automation-and-tool-development
tier: leaf
triggers: ["modsecurity rule", "owasp crs tuning", "go-ftw waf test", "ruleRemoveTargetById"]
cwe: [CWE-693]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# WAF and ModSecurity CRS Rule Engineering - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **leaf** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

The CRS is an anomaly-scoring model, not a list of blocks. Individual rules detect and increment a score variable; a final evaluation rule in `REQUEST-949-BLOCKING-EVALUATION.conf` compares the accumulated inbound score against `tx.inbound_anomaly_score_threshold` and blocks when it is reached. That architecture dictates the tuning method: removing a detection rule's target is the surgical fix, while disabling the evaluation rule removes the whole control. Scores increment per severity (`tx.critical_anomaly_score` 5, `error` 4, `warning` 3, `notice` 2 by default), and since 4.x they accumulate per paranoia level (`tx.anomaly_score_pl1` and so on) before being summed at blocking time. The paranoia variables were also renamed in CRS 4: `tx.paranoia_level` became `tx.blocking_paranoia_level`, with a new companion `tx.detection_paranoia_level` that lets you run higher-PL rules without their score contributing. Exclusions are executed with `ctl:ruleRemoveTargetById=<rule_id>;<VARIABLE>` inside a rule scoped to the phase where that variable is populated — phase 1 for request headers and URI, phase 2 for body arguments — and a `ctl` on the wrong phase removes nothing without erroring. Verification uses `go-ftw` (the maintained successor to the Python `ftw`), with a config pointing at the WAF's audit log and the server under test, and ModSecurity kept in `DetectionOnly` so the test run produces log entries without blocking traffic.

- **CWE-693 (Protection Mechanism Failure):** disabling a detection rule or the evaluation rule to silence one false positive removes protection across every request, not just the troublesome endpoint.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are excluding a false positive **THEN** use `ctl:ruleRemoveTargetById=<id>;<VARIABLE>` scoped to the narrowest path, and never disable the rule or the blocking evaluation rule.
2. **IF** you write a `ctl` for an argument **THEN** put it in phase 2 (body arguments do not exist in phase 1) and confirm it names the exact `ARGS:<name>` target.
3. **IF** you tune paranoia **THEN** use `tx.blocking_paranoia_level` (CRS 4) and, when evaluating a higher PL without impact, `tx.detection_paranoia_level`; `tx.paranoia_level` is the CRS 3 name.
4. **IF** you regression-test **THEN** run `go-ftw` against a ModSecurity in `DetectionOnly` mode with a config that names the audit log, and include a passing case for the request you just excluded.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `waf-and-modsecurity-crs-rule-engineering` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable rule and test shapes | [`QUERIES.md`](QUERIES.md) | Scoped exclusions, anomaly increments, go-ftw invocation |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `go-ftw`, ModSecurity, CRS configuration points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Over-broad exclusion and wrong-phase incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Bypass-window handoff when a WAF rule is loosened |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** OWASP CRS 4.x on ModSecurity (SecLang rules, `tx.anomaly_score_pl*`, `ctl:ruleRemoveTargetById`), regression-tested with `go-ftw` in `DetectionOnly` mode
- **Mandatory Self-Validation Command:** `go-ftw check -d tests/regression/tests` then `go-ftw run -d tests/regression/tests --config .ftw.apache.yaml`

1. **Confirm the inputs.** Establish the CRS version and paranoia level in force, the exact rule IDs firing on the false positive, the phase in which the affected variable exists, and whether the WAF is in blocking or detection mode. Confirm a rollback path before changing anything.
2. **Choose the branch.** Single argument on one endpoint → targeted `ctl:ruleRemoveTargetById` on that path. Whole endpoint legitimately needs a narrower rule set → move the exclusion to a path scope rather than a global one. Genuine attack traffic → do not exclude; fix the application and keep the rule.
3. **Define how to validate the change.** Run the existing regression suite to confirm no previously-blocked attack now passes, then add a case with the legitimate request that must no longer trigger the specific rule, and a case with a real attack against the same endpoint that must still trigger.
4. **Name the stop condition.** Stop when an exclusion is global rather than path-scoped, when a `ctl` is placed in a phase where the variable is not populated, when the exclusion suppresses the blocking evaluation rule, when paranoia is lowered to silence a case, or when the regression suite shows a rule no longer firing on attack traffic.
5. **State what counts as a working tool.** A working rule set passes the full regression suite plus the new pair of cases (legitimate request allowed, attack still blocked), and every exclusion names a rule id, a variable, and a path. The change record states the CRS version and paranoia level it was validated against.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ctl:ruleRemoveTargetById=<id>;ARGS:<name>` inside a path-scoped rule | Proves the exclusion is surgical: one rule, one variable, one endpoint |
| Phase matching the variable (1 for headers/URI, 2 for body) | Proves the `ctl` executes where the target exists |
| `setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'` | Proves the detection rule contributes score rather than blocking directly |
| `tx.blocking_paranoia_level` / `tx.detection_paranoia_level` (CRS 4) | Proves the paranoia configuration uses current variable names |
| `go-ftw` pass on both the excluded-request case and the attack case | Proves the exception did not become a bypass |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```apache
# ANTI-PATTERN: turns the rule off globally, disables the evaluation rule, and uses
# the CRS 3 paranoia variable name.
SecRuleRemoveById 942100
SecRuleRemoveById 949110
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=1"
```

**Production-Grade Starter Skeleton (USE):**

```apache
# Exclude one rule's inspection of one argument on one endpoint, in phase 2 where
# body arguments exist. Nothing else changes, and the evaluation rule still runs.
SecRule REQUEST_URI "@beginsWith /api/v2/report" \
    "id:1000100,phase:2,pass,nolog,\
    msg:'FP exclusion: rich-text report body',\
    ctl:ruleRemoveTargetById=942100;ARGS:report_html,\
    ctl:ruleRemoveTargetById=942200;ARGS:report_html"

# CRS 4 paranoia configuration uses blocking_paranoia_level, not paranoia_level.
SecAction "id:900000,phase:1,pass,nolog,\
    setvar:tx.blocking_paranoia_level=2"
```

```yaml
# go-ftw case: the legitimate request must pass, and the same endpoint must still block an attack.
meta:
  author: detection-engineering
  description: Rich-text report endpoint allows HTML but still blocks SQL injection
rule_id: 1000100
tests:
  - test_title: legitimate rich text accepted
    stages:
      - stage:
          input:
            dest_addr: 127.0.0.1
            port: 80
            method: POST
            uri: /api/v2/report
            headers:
              Host: localhost
            data: "report_html=<p>quarterly summary</p>"
          output:
            status: 200
  - test_title: SQL injection still blocked on the same endpoint
    stages:
      - stage:
          input:
            dest_addr: 127.0.0.1
            port: 80
            method: POST
            uri: /api/v2/report
            headers:
              Host: localhost
            data: "report_html=1' UNION SELECT password FROM users--"
          output:
            status: 403
```

**Why this matters:** the exclusion removes one rule's view of one argument on one path, in the phase where that argument exists — and the paired test case proves the same endpoint still blocks the attack class the exclusion was near.

## When It Is NOT This Issue

- **An exclusion has no effect and no error appears** — the `ctl` was placed in a phase where the variable is not yet populated; body arguments require phase 2.
- **Traffic is blocked by rule 949110 with a low score** — the threshold or the per-severity increments were changed, not the detection rules; check `tx.inbound_anomaly_score_threshold` before disabling anything.
- **A legitimate XML or JSON body trips an injection rule** — the rule's target needs excluding for that specific argument, not the parser; excluding `REQUEST_BODY` wholesale removes detection for everything on that endpoint.
- **`go-ftw` cases fail only in CI** — the CI container may run a different CRS version or a different paranoia level; record both with the test run.
- **The suite passes but production still blocks** — the WAF in production is in blocking mode while the test target was in `DetectionOnly`; the rule logic is identical but the pipeline config differs.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER recommend removing the blocking evaluation rule (949110) to fix a false positive; disable or scope the specific detection instead.
- NEVER present a global `SecRuleRemoveById` as a targeted tuning change.
- NEVER use `tx.paranoia_level` for a CRS 4 deployment; the variable was renamed.
- NEVER claim a rule change is safe without a regression run that includes both the excluded request and an attack against the same endpoint.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** CRS version, paranoia level, firing rule IDs, and the phase of the affected variable for `waf-and-modsecurity-crs-rule-engineering` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The exclusion, score change, or test case is specific and runnable (no generic 'tune the WAF' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: waf-and-modsecurity-crs-rule-engineering
- **Target Stack & Schema**: OWASP CRS 4.x on ModSecurity, go-ftw regression suite in DetectionOnly
- **Safety, Scope & Exit-Code Guards**: [Path-scoped exclusions, phase-correct ctl, evaluation rule untouched, regression gate]
- **False-Positive & Edge-Case Handling**: [Wrong-phase ctl, low-score blocks, rich-text bodies, version drift between CI and production]
- **Implementation**:
  [Runnable SecLang rule and go-ftw case following the Starter Skeleton]
- **Self-Validation Command**: `go-ftw check -d tests/regression/tests`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`suricata-lua-and-rule-qa-tooling`](../suricata-lua-and-rule-qa-tooling/SKILL.md) - The network-IDS rule QA harness with the same regression discipline
- [`ci-cd-security-gate-and-sarif-tooling`](../ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Gates that carry security findings into the pipeline
- [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) - Tracks whether the WAF rules still cover their technique
- [`iac-rego-opa-and-checkov-policy-development`](../iac-rego-opa-and-checkov-policy-development/SKILL.md) - Prevents the insecure defaults that WAF rules mitigate

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `waf-and-modsecurity-crs-rule-engineering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
