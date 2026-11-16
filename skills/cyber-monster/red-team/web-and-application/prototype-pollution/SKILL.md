---
name: prototype-pollution
description: Exploits JavaScript prototype pollution in Node and browser contexts, from merge and clone sinks to gadget chains that reach RCE or DOM XSS. Use when an application deep-merges user JSON, parses query strings into objects, or uses recursive assignment.
family: web-and-application
tier: core
triggers: ["prototype pollution", "proto pollution", "object pollution", "__proto__", "constructor prototype"]
cwe: [CWE-1321]
owasp: [A08:2021]
attack: []
capec: [CAPEC-460]
related: [prototype-pollution-server-side, prototype-pollution-client-side-gadgets, prototype-pollution-rce-chains, sql-injection]
---

# Prototype Pollution - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

In JavaScript every object delegates to Object.prototype, so a recursive merge, clone, path-set helper, or query-string parser that walks attacker-controlled keys can write to __proto__, constructor.prototype, or constructor and set a property on the shared prototype. Once polluted, that property is visible to every object that does not define its own, so later code reading an unset option receives the attacker's value. The security decision is the recursive assignment that fails to reject the special keys. Depending on what later reads the polluted key, the attacker gains a tampered default that flips authorization, feeds a DOM sink for XSS, crashes a worker, or supplies an option that reaches code execution.

- **Precondition chain:** a sink recursively assigns nested keys from untrusted input (deep merge, clone, path-set, or query parser), the key walk does not reject __proto__, constructor, or prototype, the prototype is mutable rather than a null-prototype object or Map, and some later code path reads an attribute it never set.
- **Readable differential:** send a request that sets __proto__.<probe> versus one that sets a normal nested key; pollution is proven when a fresh unrelated object or a reflected default suddenly exposes <probe>, and it clears when the merge rejects the special keys.
- **Empirical grounding:** This maps to CWE-1321 under OWASP Top 10:2025 A08 Software or Data Integrity Failures; SOURCES.md contains no prototype-pollution-specific advisory, so grounding stays at the CWE-1321 taxonomy rather than attaching a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the sink is a Node merge, clone, or path-set on server JSON **THEN** switch to [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) (1 hop)
2. **IF** the pollution must reach a DOM sink to become script execution **THEN** switch to [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md) (1 hop)
3. **IF** a polluted key feeds child_process or a template engine toward execution **THEN** switch to [`prototype-pollution-rce-chains`](../prototype-pollution-rce-chains/SKILL.md) (1 hop)
4. **IF** the entry point is a query-string or form parser that builds nested objects from bracket keys **THEN** test a[__proto__][x] style keys against that parser's object output
5. **IF** the sink is a known deep-merge or defaults library **THEN** confirm the library version's key handling first, since patched merges reject __proto__
6. **IF** only side effects are observable and nothing is reflected **THEN** switch the oracle to a status or behaviour change on a property the app reads but never sets
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no recursive key-walking sink exists and the object is a null-prototype object or a Map **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Polluted key lands in a DOM sink like innerHTML or script src | [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) | The resulting bug is a DOM XSS gadget, a different sink invariant than the prototype write |
| Polluted default flips a mass-assignment or binding guard | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Impact is unauthorized property setting, not prototype mutation itself |
| Pollution reaches a server-side template or eval gadget | [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) | Execution flows through dynamic evaluation, a distinct invariant |
| Target matches `prototype-pollution-server-side` | [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `prototype-pollution-client-side-gadgets` | [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `prototype-pollution-rce-chains` | [`prototype-pollution-rce-chains`](../prototype-pollution-rce-chains/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Locate the recursive assignment sink and classify it as a deep merge, a clone, a path-set, or a query-string parser that builds nested objects.
2. Pick a non-destructive canary property name that the application never legitimately sets, so any later appearance is attributable to pollution.
3. Read a fresh empty object or a reflected default before polluting, to record the clean baseline.
4. Send the __proto__.<canary> probe through the sink, then read a brand-new object or a reflected default to see whether the canary leaked.
5. Isolate which key form worked, __proto__ versus constructor.prototype, because an incomplete blocklist often stops one but not the other.
6. Define the baseline-versus-probe differential explicitly: a fresh object gains the canary only after the probe and loses it once the merge rejects the special keys.
7. **Stop condition.** Stop when (a) a fresh unrelated object exposes the canary, proving global prototype mutation, (b) no fresh object leaks the canary across both key forms, or (c) proving further would corrupt shared production state; (a) is confirmation, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a newly created object carrying an attribute the attacker set through __proto__, reverting when the sink rejects the keys or builds null-prototype objects. Close with rejecting __proto__, constructor, and prototype, using Object.create(null) or Map, freezing Object.prototype as defence in depth, and re-running the canary probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| _.merge, deepmerge, or recursive Object.assign over user JSON | Proves a prototype write sink in Node where nested keys are walked without a guard |
| A query parser producing obj.__proto__ from a[__proto__][b] | Proves the parser walks special keys, a pollution source distinct from the merge itself |
| A fresh empty object suddenly carrying an attacker property | Proves global Object.prototype mutation rather than a local own-property write |
| constructor.prototype path accepted after __proto__ is blocked | Proves the key blocklist is incomplete on this stack |
| A reflected config default changing after the probe | Proves a readable side channel confirming pollution without a fresh-object check |
| Null-prototype objects or Map used at the sink | Proves the branch is closed because there is no shared prototype to mutate |

## Worked Contrast

**Vulnerable pattern:**

```javascript
function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === "object" && source[key] !== null) {
      merge(target[key] = target[key] || {}, source[key]);
    } else {
      target[key] = source[key];   // __proto__ walked like any other key
    }
  }
  return target;
}
app.post("/prefs", (req, res) => res.json(merge({}, req.body)));
```

**Hardened pattern:**

```javascript
const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);

function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN.has(key)) continue;              // never walk prototype keys
    if (typeof source[key] === "object" && source[key] !== null) {
      merge(target[key] = target[key] || Object.create(null), source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
app.post("/prefs", (req, res) => res.json(merge(Object.create(null), req.body)));
```

**Why this matters:** The defect recurses through every key including __proto__, so a nested __proto__ object writes onto the shared prototype. The fix skips the three dangerous keys and builds objects with a null prototype, so even a crafted body cannot reach Object.prototype.

## When It Is NOT This Issue

- **Null-prototype or Map sink:** a merge target created with Object.create(null) or a Map has no shared prototype to pollute.
- **Patched merge library:** a defaults or merge helper that already rejects __proto__ and constructor is not a write sink.
- **Self-only config with no later read:** a polluted key no downstream code reads changes nothing observable.
- **Frozen Object.prototype:** a process that freezes the prototype blocks the write even if the key is walked.
- **Own-property write, not prototype:** a probe that sets a property on the target object but not a fresh object is not pollution.
- **Reflection echo only:** an endpoint that echoes input back without a fresh-object leak has not actually polluted anything.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `prototype-pollution` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `prototype-pollution` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: prototype-pollution
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1321 | Mapping: A08:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) - Web and Application (leaf)
- [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md) - Web and Application (leaf)
- [`prototype-pollution-rce-chains`](../prototype-pollution-rce-chains/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `prototype-pollution` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1321`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 58 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (32), CYBER_CPT/gh_advisories (10), hackerone_disclosed_reports (6), CYBER_CPT/hacktricks (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
