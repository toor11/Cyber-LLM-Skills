---
name: edr-api-triage-and-containment-scripting
description: "Develops vendor-agnostic EDR API triage and guarded response CLI tools (Microsoft Defender, CrowdStrike FalconPy, SentinelOne): fetching host timelines, process trees, and isolation status with dry-run defaults, audit logging, and two-person approval tokens. Use when scripting EDR investigations."
family: security-automation-and-tool-development
tier: leaf
triggers: ["edr api script", "falconpy triage", "defender api python", "guarded host isolation script"]
cwe: [CWE-284]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# EDR API Triage and Containment Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **leaf** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Vendor EDR APIs differ in surface but converge on a small set of primitives: find a host, read its timeline, read its process tree, read whether it is already contained, and perform a containment action. The differences that matter operationally are identity and scope. CrowdStrike's FalconPy authenticates with `client_id`/`client_secret` and exposes containment through the Real Time Response service class — `init_session(device_id=...)` opens a session before any RTR command, and `batch_init_sessions(host_ids=[...])` does it for many hosts — while host lookup lives in the `Hosts` class; using the wrong class is a common and silent error because both accept the same credentials. Microsoft's Defender for Endpoint API uses OAuth tokens and a `POST /api/machines/{id}/isolate` endpoint whose body carries `Comment` and `IsolationType` (`Full`, `Selective`, or `UnManagedDevice`), with strict rate limits. Regardless of vendor, a defensive CLI has the same five obligations: read-only by default with `--dry-run`, an allowlist of host identifiers rather than free-text targets, a two-person approval token for any state change, an append-only audit line per action (actor, target, action, result, request id), and a resolution step that maps a hostname to the vendor's host id through the API rather than trusting the caller's string. Rate limits are the operational constraint — a triage run over hundreds of hosts must batch and back off, not loop single calls.

- **CWE-284 (Improper Access Control):** a containment script whose only gate is a command-line flag is an unauthenticated response capability in practice.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are writing a containment CLI **THEN** default to `--dry-run`, require `--target-id` values resolved from the API, and require an approval token for `--execute`; a missing token is a refusal, not a prompt.
2. **IF** the vendor is CrowdStrike **THEN** use FalconPy's `Hosts` class for lookup and `RealTimeResponse` for `init_session`/`batch_init_sessions`, and remember RTR commands require an active session first.
3. **IF** the vendor is Microsoft Defender for Endpoint **THEN** isolate with `POST /api/machines/{id}/isolate` carrying `Comment` and `IsolationType` (`Full`/`Selective`/`UnManagedDevice`), and respect the documented per-minute and per-hour rate limits.
4. **IF** you are reading rather than acting **THEN** batch lookups and treat 429 as backpressure — retry with backoff instead of marking the host as unknown.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `edr-api-triage-and-containment-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable triage and containment shapes | [`QUERIES.md`](QUERIES.md) | Dry-run flow, host resolution, isolation call, audit line |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | FalconPy classes, Defender endpoint, rate limits |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Wrong-class and unprotected-target incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Containment-scope handoff during live response |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** vendor EDR REST APIs via `falconpy` (`Hosts`, `RealTimeResponse`) or `requests` against Defender for Endpoint, with a dry-run default, approval token, and append-only audit log
- **Mandatory Self-Validation Command:** `python -m py_compile edr_triage.py`

1. **Confirm the inputs.** Establish the vendor and API family, the credential source (secret store, never source), the host identifier form the API expects, the rate limits, and who can issue approval tokens. Confirm whether the target is already isolated — re-isolating changes nothing and hides a failed first attempt.
2. **Choose the branch.** Read-only triage → host lookup plus timeline, batched. Containment → approval token plus protected-host refusal plus audit. Release → the inverse action with its own approval, because un-isolating is also a state change.
3. **Define how to validate the script.** Run with `--dry-run` and assert the plan lists the resolved host id and the intended action without calling the write endpoint. Then test against a lab host: approved containment succeeds, unapproved is refused, a protected host is refused, and a second run against an isolated host reports "already contained" rather than issuing a duplicate action.
4. **Name the stop condition.** Stop when the host id cannot be resolved, when the host is on the protected list, when the approval token is absent or expired, when the API returns 429 beyond the retry budget, or when the host is already in the requested state.
5. **State what counts as a working tool.** A working CLI exits `0` when the requested state is confirmed by a follow-up read, `1` when a policy refusal occurred (protected host, missing approval, already in state), and `2` on authentication or transport failure. Every invocation writes an audit line, including refusals and dry runs.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `--dry-run` plan naming resolved host ids | Proves the action would target the intended host, before any write call |
| FalconPy `Hosts` for lookup and `RealTimeResponse.init_session` for RTR | Proves the right service class per operation; credentials alone do not imply the right class |
| `IsolationType` value in the Defender request body | Proves the isolation scope (`Full` vs `Selective`) was an explicit decision |
| Post-action read showing `isolated: true` | Proves the action took effect rather than merely returning 2xx |
| Audit line with actor, target, action, request id | Proves the response action is attributable and reviewable |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: no dry-run, hostname used directly as the API id, credentials inline,
# no approval, no audit, and re-isolation fires blindly.
import requests

def isolate(hostname: str) -> None:
    requests.post(
        f"https://api.security.microsoft.com/api/machines/{hostname}/isolate",
        json={"Comment": "soc", "IsolationType": "Full"},
        headers={"Authorization": "Bearer hardcoded-token"},
        timeout=10,
    )
    print("isolated", hostname)
```

**Production-Grade Starter Skeleton (USE):**

```python
# edr_triage.py - Exit 0 state confirmed, 1 policy refusal, 2 auth/transport failure
import argparse
import datetime as dt
import json
import os
import sys
import time

import requests

BASE = "https://api.security.microsoft.com/api"
PROTECTED_TAGS = {"domain-controller", "dns", "hypervisor", "identity-provider"}
RETRY_BUDGET = 4

def audit(record: dict) -> None:
    record["ts"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    print(json.dumps({"audit": record}), file=sys.stderr)

def headers() -> dict:
    token = os.environ.get("MDE_TOKEN")
    if not token:
        raise RuntimeError("MDE_TOKEN is not set; load it from the secret store")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def resolve_machine(hostname: str) -> dict | None:
    resp = requests.get(f"{BASE}/machines", params={"$filter": f"computerDnsName eq '{hostname}'"},
                        headers=headers(), timeout=15)
    resp.raise_for_status()
    items = resp.json().get("value", [])
    return items[0] if items else None

def is_protected(machine: dict) -> bool:
    tags = {str(t).lower() for t in (machine.get("machineTags") or [])}
    name = (machine.get("computerDnsName") or "").split(".")[0].lower()
    return bool(tags & PROTECTED_TAGS) or name.startswith(("dc", "dns", "hyper"))

def post_with_backoff(url: str, body: dict) -> int:
    delay = 1.0
    for attempt in range(1, RETRY_BUDGET + 1):
        resp = requests.post(url, json=body, headers=headers(), timeout=20)
        if resp.status_code < 400:
            return resp.status_code
        if resp.status_code != 429 and resp.status_code < 500:
            return resp.status_code
        if attempt == RETRY_BUDGET:
            return resp.status_code
        time.sleep(delay)
        delay *= 2
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description="Guarded EDR triage and containment")
    ap.add_argument("--hostname", required=True)
    ap.add_argument("--action", choices=["report", "isolate", "release"], default="report")
    ap.add_argument("--isolation-type", choices=["Full", "Selective"], default="Full")
    ap.add_argument("--approval-token", default="")
    ap.add_argument("--execute", action="store_true", default=False,
                    help="without this flag the tool stays in dry-run")
    args = ap.parse_args()

    try:
        machine = resolve_machine(args.hostname)
    except (requests.RequestException, RuntimeError) as exc:
        audit({"actor": "edr_triage", "target": args.hostname, "action": args.action,
               "result": "error", "detail": str(exc)})
        return 2
    if machine is None:
        audit({"actor": "edr_triage", "target": args.hostname, "action": args.action,
               "result": "unresolved"})
        return 1

    machine_id = machine["id"]
    already = bool(machine.get("isIsolated"))
    plan = {"target": args.hostname, "machine_id": machine_id,
            "action": args.action, "already_isolated": already,
            "dry_run": not args.execute}
    if args.action == "report":
        audit({**plan, "result": "reported", "risk": machine.get("riskScore")})
        return 0
    if is_protected(machine):
        audit({**plan, "result": "refused", "reason": "protected_asset"})
        return 1
    if args.execute and not args.approval_token:
        audit({**plan, "result": "refused", "reason": "missing_approval"})
        return 1
    if args.action == "isolate" and already:
        audit({**plan, "result": "no_change", "reason": "already_isolated"})
        return 1
    if not args.execute:
        audit({**plan, "result": "planned"})
        return 0

    if args.action == "isolate":
        status = post_with_backoff(f"{BASE}/machines/{machine_id}/isolate",
                                   {"Comment": f"approved: {args.approval_token[:6]}",
                                    "IsolationType": args.isolation_type})
    else:
        status = post_with_backoff(f"{BASE}/machines/{machine_id}/unisolate",
                                   {"Comment": f"approved: {args.approval_token[:6]}"})
    audit({**plan, "result": "submitted", "http_status": status})
    return 0 if status < 400 else 2

if __name__ == "__main__":
    raise SystemExit(main())
```

**Why this matters:** the hostname is resolved to the API's own identifier before anything is written, dry-run is the default, and every refusal path writes an audit line — so a protected or already-contained host produces a recorded decision rather than a duplicate state change.

## When It Is NOT This Issue

- **An isolation call returns 2xx but the host is still online** — the action is asynchronous; confirm with a follow-up read of `isIsolated` instead of trusting the submission status.
- **A Defender call returns 403 with a valid token** — some endpoints require tokens issued for the legacy audience; a URL and a token can both look right and still be mismatched.
- **FalconPy returns "no session" for a containment command** — RTR commands need `init_session`/`batch_init_sessions` first; credentials alone do not open a session.
- **The script reports a host as unknown during a mass event** — 429 rate limiting is being treated as "not found"; back off and retry before concluding anything about the host.
- **A host is isolated twice** — the first attempt succeeded but the response was lost, and the script has no already-contained check.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER place API tokens or client secrets in source; load them from the environment or a secret store.
- NEVER present a containment helper without a dry-run default and a protected-asset refusal path.
- NEVER claim a class, endpoint, or permission name you have not confirmed against the vendor's current API documentation.
- NEVER treat a 429 as "host not found" or as a permanent failure inside a triage loop.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Vendor and API family, identifier form, rate limits, and approval authority for `edr-api-triage-and-containment-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The triage CLI or containment gate is specific and runnable (no generic 'isolate the host' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: edr-api-triage-and-containment-scripting
- **Target Stack & Schema**: falconpy Hosts/RealTimeResponse or Defender for Endpoint REST, dry-run default with approval tokens
- **Safety, Scope & Exit-Code Guards**: [Resolved target ids, protected-asset refusal, approval token, backoff, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Already-contained hosts, 429 backpressure, async action confirmation, audience-mismatched tokens]
- **Implementation**:
  [Runnable CLI following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile edr_triage.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`soar-playbook-and-webhook-connector-development`](../soar-playbook-and-webhook-connector-development/SKILL.md) - The orchestration layer that calls this CLI with approval gates
- [`siem-query-transpiler-and-enrichment-scripting`](../siem-query-transpiler-and-enrichment-scripting/SKILL.md) - Supplies alert context for the triage decision
- [`windows-evtx-and-powershell-audit-scripting`](../windows-evtx-and-powershell-audit-scripting/SKILL.md) - Host-side execution evidence to corroborate EDR telemetry
- [`volatility3-plugin-and-memory-triage-scripting`](../volatility3-plugin-and-memory-triage-scripting/SKILL.md) - Offline confirmation of in-memory findings before containment

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `edr-api-triage-and-containment-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
