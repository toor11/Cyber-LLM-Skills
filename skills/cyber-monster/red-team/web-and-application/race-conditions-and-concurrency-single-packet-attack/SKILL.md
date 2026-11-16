---
name: race-conditions-and-concurrency-single-packet-attack
description: Single-packet and last-byte synchronization attacks. Covers HTTP/2 single-packet attack mechanics and last-byte sync to land concurrent requests within the same processing window. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["single packet attack", "last byte sync", "race exploit technique"]
cwe: [CWE-362]
owasp: [A04:2021]
attack: []
capec: [CAPEC-26]
related: [race-conditions-and-concurrency, race-conditions-and-concurrency-limit-bypass, sql-injection, cross-site-scripting]
parent: race-conditions-and-concurrency
corpus_sparse: true
---

# Race Conditions and Concurrency Single Packet Attack - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

This delivery-technique variant removes network jitter so requests arrive together and a time-of-check to time-of-use window becomes exploitable. The HTTP/2 single-packet attack places the final byte of roughly twenty to thirty concurrent streams into one TCP packet, so the server dequeues them within microseconds; for HTTP/1.1, last-byte synchronization sends every request except its final byte, then releases the withheld bytes together over pipelined connections. The first-sequence-sync extension pushes the single-packet idea past the roughly 65,535-byte TCP window by pre-sending request bodies and synchronizing only the final sequence, enabling on the order of ten thousand requests. The security decision is wire-level request alignment, and the attacker gains a window short enough to defeat a check-then-act that jitter would otherwise hide.

- **Precondition chain:** the target has a non-atomic check-then-act, the transport allows HTTP/2 multiplexing or HTTP/1.1 pipelining to the origin, no front proxy re-serializes or buffers requests into order, and the achievable alignment is tighter than the server-side window.
- **Readable differential:** send the same N requests spaced out versus aligned in one packet; the technique works when only the aligned burst produces the impossible committed state, proving that arrival timing, not payload, is the deciding variable.
- **Empirical grounding:** This maps to CWE-362 under OWASP Top 10:2025 A06; the single-packet attack is the PortSwigger research, and the first-sequence-sync extension past the 65,535-byte limit (about ten thousand requests in roughly 166 ms) is the GMO Flatt Beyond the Limit work.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target window is not yet confirmed non-atomic **THEN** start at parent class [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) (1 hop) to confirm a check-then-act exists
2. **IF** the origin negotiates HTTP/2 over ALPN **THEN** use the single-packet attack to carry the concurrent streams in one packet
3. **IF** the origin speaks only HTTP/1.1 **THEN** use last-byte synchronization over pipelined keep-alive connections
4. **IF** the race needs far more than thirty requests **THEN** use first-sequence-sync to exceed the TCP window and scale to thousands
5. **IF** a CDN or proxy buffers whole requests before forwarding **THEN** test whether re-serialization defeats alignment before investing in a burst
6. **IF** round-trip jitter is unknown **THEN** warm the connections and measure baseline jitter against the target window
7. **IF** Turbo Intruder offers multiple engines **THEN** select the single-packet engine for HTTP/2 or the pipelined engine for HTTP/1.1
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** aligned and spaced bursts produce the same result, so timing is not the variable **THEN** STOP and classify as a verified non-finding for this technique

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| You have the window but need a business target to hit | [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md) | Shifts from synchronization to the limited-resource invariant |
| The origin only speaks HTTP/1.1 and buffers requests | [`http-request-smuggling`](../http-request-smuggling/SKILL.md) | A desync may be needed to reach the origin unbuffered, a different invariant |
| HTTP/2 framing or flow control is the lever | [`http2-specific-attacks`](../http2-specific-attacks/SKILL.md) | Focus is the HTTP/2 protocol surface rather than the race target |
| Need parent class methodology | [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Confirm a candidate non-atomic endpoint exists, carried over from the parent skill rather than assumed.
2. Choose the transport: the single-packet attack when the origin offers HTTP/2, otherwise last-byte synchronization over pipelined HTTP/1.1.
3. Warm the connections and measure baseline round-trip jitter so you know whether the window is landable.
4. Align N requests in one packet, or use first-sequence-sync when N must exceed the TCP window.
5. Define the baseline-versus-probe differential: fire the aligned burst against a spaced control of the same requests.
6. Choose the branch from evidence: an impossible committed state only under alignment, no divergence either way, or a front proxy that re-serializes.
7. **Stop condition.** Stop when (a) the impossible committed state appears only under aligned delivery, (b) alignment makes no difference because the target commits atomically, or (c) the burst would commit real transactions; (a) confirms the technique landed, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is the impossible committed value appearing under the aligned burst and not under the spaced control, with the delivery method recorded. The structural remedy lives at the datastore as an atomic guard; the technique only reveals it, so verify the guard by re-running the aligned burst.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| The origin negotiating HTTP/2 via ALPN h2 | Proves single-packet delivery is available on this transport |
| Turbo Intruder reporting all last bytes in one frame | Proves the requests were aligned into a single packet |
| A divergence that appears only in the aligned burst | Proves arrival timing is the deciding variable, not the payload |
| A front CDN that buffers whole requests before forwarding | Proves re-serialization that blocks the window regardless of client alignment |
| Measured jitter smaller than the server-side window | Proves the race is landable with the achievable alignment |
| first-sequence-sync completing on the order of ten thousand requests | Proves the extension past the 65,535-byte TCP window is in play |

## Worked Contrast

**Vulnerable pattern:**

```python
# Per-process in-memory guard assumes requests are handled one at a time.
_claimed = set()

def claim_once(token):
    if token in _claimed:          # check against local memory
        return False
    # Under HTTP/2 multiplexing many workers run this with the same token concurrently.
    _claimed.add(token)            # act, not shared or atomic across workers
    return True
```

**Hardened pattern:**

```python
import redis

r = redis.Redis()

def claim_once(token):
    # Atomic set-if-absent at the shared datastore; multiplexed requests serialize here.
    first = r.set(name=f"claim:{token}", value="1", nx=True, ex=86400)
    return bool(first)
```

**Why this matters:** The defect guards a one-time token in per-worker memory, which an aligned single-packet burst defeats because concurrent workers each see an empty set. The fix moves the guard to an atomic SET NX at a shared store, so exactly one of the aligned requests wins regardless of how tightly they arrive.

## When It Is NOT This Issue

- **Buffering proxy re-serializes:** an origin reached only through a proxy that buffers whole requests cannot be aligned.
- **Endpoint already atomic:** if the commit is a single conditional operation, alignment changes nothing.
- **No HTTP/2 and pipelining stripped:** without multiplexing or pipelining the burst cannot be synchronized.
- **Divergence also occurs when spaced:** a difference that appears without alignment is not a race.
- **Client-side concurrency only:** a harness measuring its own thread timing, not server commits, proves nothing.
- **Window larger than achievable alignment:** if the server window exceeds measured jitter headroom, the burst will not land.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `race-conditions-and-concurrency-single-packet-attack` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `race-conditions-and-concurrency-single-packet-attack` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: race-conditions-and-concurrency-single-packet-attack
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-362 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) - Web and Application (core)
- [`race-conditions-and-concurrency-limit-bypass`](../race-conditions-and-concurrency-limit-bypass/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `race-conditions-and-concurrency-single-packet-attack` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-362`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
