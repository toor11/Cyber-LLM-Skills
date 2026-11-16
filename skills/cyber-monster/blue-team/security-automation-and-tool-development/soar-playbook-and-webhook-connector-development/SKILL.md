---
name: soar-playbook-and-webhook-connector-development
description: "Engineers resilient SOAR playbooks and Python webhook connectors: HMAC webhook signature verification, idempotency keys, exponential-backoff retries, blast-radius allowlists (never auto-isolate DCs/DNS/core infra), and mandatory human-in-the-loop approval gates for destructive containment. Use when building automated SOC response workflows."
family: security-automation-and-tool-development
tier: flagship
triggers: ["soar playbook script", "soc webhook connector", "automated containment safety", "idempotent soar"]
cwe: [CWE-284, CWE-345]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# SOAR Playbook and Webhook Connector Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **flagship** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Automated response is the one place where a defect changes system state rather than producing a bad report, so the engineering problem is not "call the containment API" but "prove this call is authorized, unique, and reversible". A webhook receiver has four obligations before it acts: verify the sender's HMAC over the raw request body (not the re-serialized JSON, which changes bytes), reject replays by timestamp window and nonce, deduplicate by an idempotency key so a retried delivery does not perform the action twice, and scope the action against a blast-radius allowlist that excludes domain controllers, DNS, hypervisors, and management planes regardless of what the payload says. Destructive actions additionally require human-in-the-loop approval: the playbook prepares the action, records the approver identity and timestamp, and only then executes — a gate that is procedural, not advisory. Outbound calls need exponential backoff with jitter and a bounded retry budget, because a containment API that returns 429 or 503 is not "failed", it is "retry"; treating the two identically either double-executes or abandons the action. Every step writes an append-only audit record (request id, decision, actor, result) so the response itself is reviewable after the fact.

- **CWE-284 (Improper Access Control):** an unauthenticated or unscoped webhook can trigger containment; the control must live in the receiver, not in the caller's good behaviour.
- **CWE-345 (Insufficient Verification of Data Authenticity):** without HMAC verification and replay protection, anyone who learns the URL can drive the playbook.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you receive a webhook **THEN** compute the HMAC over the raw body bytes and compare with `hmac.compare_digest`, enforce a timestamp window (a few minutes), and reject a reused nonce before parsing the payload at all.
2. **IF** the action is destructive (isolate, disable account, block IP, delete resource) **THEN** require an approval token recorded with approver identity and time, and default to dry-run when the token is absent.
3. **IF** the target is on the protected list (domain controller, DNS, hypervisor, CI/CD control plane, identity provider) **THEN** refuse and route to a human; the allowlist is evaluated server-side against the resolved asset, never against the payload's own claim.
4. **IF** an outbound call returns 429/5xx/timeout **THEN** retry with exponential backoff and jitter up to a bounded budget, and make the action idempotent by key so a retry after a timeout cannot double-execute.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `soar-playbook-and-webhook-connector-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable receiver and retry shapes | [`QUERIES.md`](QUERIES.md) | HMAC verification, idempotency store, backoff, approval gate |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `hmac`, `http.server`/`requests`, platform API notes |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Double-execution and protected-asset incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Response-workflow handoff during an incident |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11 webhook receiver using `hmac`/`hashlib.compare_digest` over raw body, a bounded idempotency store, `requests` with exponential backoff and jitter, and an explicit approval gate record
- **Mandatory Self-Validation Command:** `python -m py_compile soar_connector.py`

1. **Confirm the inputs.** Establish the sender's signing scheme (header name, algorithm, timestamp field), the retry semantics of the platform calling you, the inventory of protected assets, the approval mechanism, and where the audit log lands. Confirm which actions the playbook may take and which are dry-run only.
2. **Choose the branch.** Notification-only playbook → no approval gate, still verify HMAC. Reversible containment → idempotent execution with dry-run default. Destructive or cross-boundary → approval gate plus protected-asset refusal plus audit. Each branch changes what the receiver must record before acting.
3. **Define how to validate the playbook.** Four fixtures: a correctly signed request (accepted), a request with a tampered body (rejected 401), a replay of an accepted request (rejected as duplicate without re-executing), and a request targeting a protected asset (refused and routed). Add a simulated 429 to prove backoff retries rather than abandoning.
4. **Name the stop condition.** Stop when signature verification fails, when the timestamp is outside the window, when the idempotency key was already executed, when the resolved target is protected, when the approval token is missing for a destructive action, or when the retry budget is exhausted.
5. **State what counts as a working tool.** A working connector exits `0` only when the request was authentic, unique, approved where required, scoped to a non-protected asset, and fully audited; `1` for a policy refusal; `2` for an unverifiable request or a transport failure after the retry budget. The audit record exists for every outcome, including refusals.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `hmac.compare_digest(expected, received)` over raw body bytes | Proves the payload is authentic and unmodified; comparing re-serialized JSON breaks on key ordering |
| Timestamp window plus nonce/idempotency key store | Proves replay and duplicate delivery cannot execute the action twice |
| Protected-asset check against internal inventory | Proves the blast-radius rule is enforced server-side, not trusted from the payload |
| Approval record with approver and timestamp | Proves human authorization exists for destructive steps and is auditable |
| Retry with exponential backoff plus jitter, bounded | Proves 429/5xx is treated as transient while a genuine failure still stops |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: no signature check, no dedup, no scoping, and it isolates whatever
# host the payload names - including a domain controller.
import json
from http.server import BaseHTTPRequestHandler

import requests

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        requests.post(
            "https://edr.example/api/isolate",
            json={"host": payload["host"]},
            headers={"Authorization": "Bearer static-token"},
            timeout=5,
        )
        self.send_response(200)
        self.end_headers()
```

**Production-Grade Starter Skeleton (USE):**

```python
# soar_connector.py - Exit 0 executed, 1 policy refusal, 2 unverifiable or transport exhausted
import hashlib
import hmac
import json
import random
import sys
import time
import uuid

import requests

SHARED_SECRET = b"replace-from-secret-store"
MAX_SKEW_SECONDS = 300
PROTECTED_HOSTNAMES = {"dc01", "dc02", "dns01", "hyperv01", "idp01"}
RETRY_BUDGET = 4
EXECUTED_KEYS: dict[str, str] = {}

def verify(raw_body: bytes, signature_hex: str, timestamp: str) -> bool:
    try:
        age = abs(int(time.time()) - int(timestamp))
    except (TypeError, ValueError):
        return False
    if age > MAX_SKEW_SECONDS:
        return False
    expected = hmac.new(SHARED_SECRET, timestamp.encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)

def is_protected(host: str) -> bool:
    return host.split(".")[0].lower() in PROTECTED_HOSTNAMES

def approved(payload: dict) -> bool:
    approval = payload.get("approval") or {}
    return bool(approval.get("approver")) and bool(approval.get("token"))

def call_with_backoff(url: str, body: dict, headers: dict) -> int:
    delay = 0.5
    for attempt in range(1, RETRY_BUDGET + 1):
        try:
            resp = requests.post(url, json=body, headers=headers, timeout=10)
        except requests.RequestException:
            resp = None
        if resp is not None and resp.status_code < 400:
            return resp.status_code
        if resp is not None and resp.status_code not in (429, 500, 502, 503, 504):
            return resp.status_code
        if attempt == RETRY_BUDGET:
            break
        time.sleep(delay + random.uniform(0, delay / 2))
        delay *= 2
    return 0

def handle(raw_body: bytes, signature_hex: str, timestamp: str) -> int:
    if not verify(raw_body, signature_hex, timestamp):
        print(json.dumps({"decision": "reject", "reason": "signature_or_skew"}))
        return 2
    payload = json.loads(raw_body)
    key = payload.get("idempotency_key") or str(uuid.uuid4())
    if key in EXECUTED_KEYS:
        print(json.dumps({"decision": "duplicate", "key": key, "prior": EXECUTED_KEYS[key]}))
        return 0
    host = payload.get("host", "")
    if is_protected(host):
        print(json.dumps({"decision": "refuse", "reason": "protected_asset", "host": host}))
        return 1
    if payload.get("action") == "isolate" and not approved(payload):
        print(json.dumps({"decision": "refuse", "reason": "missing_approval", "host": host}))
        return 1
    status = call_with_backoff(
        "https://edr.example/api/isolate",
        {"host": host, "reason": payload.get("reason", "")},
        {"Authorization": "Bearer " + "runtime-token"},
    )
    EXECUTED_KEYS[key] = "executed" if status else "failed"
    print(json.dumps({"decision": "execute", "key": key, "host": host, "status": status}))
    return 0 if status else 2

if __name__ == "__main__":
    body = sys.stdin.buffer.read()
    raise SystemExit(handle(body, sys.argv[1], sys.argv[2]))
```

**Why this matters:** authenticity, replay, scope, and approval are each checked before any state change, and the idempotency key makes the retry path safe — so a duplicate webhook delivery cannot isolate a host twice or isolate a domain controller at all.

## When It Is NOT This Issue

- **A webhook is rejected as unsigned but the sender insists it signed** — the receiver hashed the re-serialized JSON instead of the raw body; key order and whitespace change the digest.
- **The same isolation appears twice in the EDR audit log** — the platform retried a delivery that had already succeeded (usually after a timeout), and the connector had no idempotency store.
- **A containment action was refused on a protected host** — that is the allowlist working; the correct next step is a human decision, not adding the host to the exception list.
- **Repeated 429s look like an outage** — the target is rate limiting and backoff is required; escalating to "containment failed" abandons an action that would have succeeded on retry.
- **An approval gate "does not trigger"** — the action name in the payload does not match the gated action list; the gate keys on action identity, so a renamed action bypasses it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER compare an HMAC against a re-serialized payload; hash the raw request body.
- NEVER place a static long-lived token in receiver source; load credentials at runtime from a secret store.
- NEVER present an isolation or account-disable automation without a protected-asset refusal path and an approval record.
- NEVER treat a 429/5xx as a permanent failure in a containment playbook without exhausting a bounded retry budget.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Signing scheme, retry semantics, protected-asset inventory, and approval mechanism for `soar-playbook-and-webhook-connector-development` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The receiver, gate, or retry policy is specific and runnable (no generic 'add approval' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: soar-playbook-and-webhook-connector-development
- **Target Stack & Schema**: Python 3.11 webhook receiver with HMAC-over-raw-body, idempotency store, approval gate, bounded backoff
- **Safety, Scope & Exit-Code Guards**: [Signature and skew checks, protected-asset refusal, approval record, retry budget, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Duplicate delivery, rate limiting, renamed actions, replayed nonce]
- **Implementation**:
  [Runnable connector following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile soar_connector.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`edr-api-triage-and-containment-scripting`](../edr-api-triage-and-containment-scripting/SKILL.md) - The vendor API layer this playbook calls
- [`siem-query-transpiler-and-enrichment-scripting`](../siem-query-transpiler-and-enrichment-scripting/SKILL.md) - Supplies the enriched alert that triggers the playbook
- [`syslog-and-cloudtrail-stream-parsers`](../syslog-and-cloudtrail-stream-parsers/SKILL.md) - Source of the control-plane events worth automating on
- [`stix-taxii-and-misp-ioc-pipeline-scripting`](../stix-taxii-and-misp-ioc-pipeline-scripting/SKILL.md) - IOC feeds that may drive blocking actions

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `soar-playbook-and-webhook-connector-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
