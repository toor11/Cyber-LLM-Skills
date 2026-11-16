---
name: nmap-nse-audit-script-authoring
description: "Develops safe Lua Nmap Scripting Engine (NSE) scripts in the safe, discovery, and version categories: portrule/hostrule predicates, shortport, http/tls/smb stdnse libraries, and structured XML/table output. Use when writing non-intrusive service banner or configuration audit scripts."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["nmap nse script", "write nse lua", "shortport", "stdnse output_table", "nmap script authoring"]
cwe: [CWE-200]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting, openapi-and-graphql-schema-auditor-scripting]
corpus_sparse: true
---


# Nmap NSE Audit Script Authoring - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Writing an Nmap Scripting Engine script that runs inside Nmap's own scan lifecycle: declare `categories = {"safe", "discovery"}` so the script only runs when the operator asks for those, use `shortport.http` to gate on a service, perform one bounded request, and return a `stdnse.output_table`. The value is that the probe inherits Nmap's host discovery, port state, and timing model instead of reinventing them.

- **Category is the safety contract.** A script in `safe` must not change server state; anything that writes belongs in `intrusive` and the operator opts in.
- **Output is structured.** `stdnse.output_table` and `stdnse.format_output` produce machine-readable results, which is what makes a script usable across a range.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the script needs HTTP **THEN** use `http.get` or `http.pipeline_go` from the http library rather than raw sockets, so redirects and TLS are handled.
2. **IF** the script needs credentials **THEN** take them from script arguments and never embed them, because NSE scripts are shared.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a target port with a known service, a script category that matches the intended intrusiveness, and one request — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Nmap 7.9x NSE Lua 5.3 with `shortport`, `http`, `stdnse`, `nmap.address_family`, `categories = {"safe", "discovery"}`
- **Mandatory Self-Validation Command:** `nmap --script ./audit.nse --script-args safe=1 -p 443 target.example`

1. Confirm the target surface: identify the port rule (`shortport.http` or a port number), the service, and whether the probe needs TLS.
2. Choose the branch: `prerule` for host-level checks, `hostrule` for cross-port logic, `portrule` for one service probe.
3. Define the differential: run the script against a host known to exhibit the condition and one known not to; the output table must differ in exactly the field under test.
4. Name the stop condition: one request per port with an explicit timeout, so a slow service cannot stall the scan.
5. Prove it: return the response status, the matched field, and the byte count in the output table, so the result is reproducible with `-p` and the same script args.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `categories = {"safe", "discovery"}` | Declares intrusiveness; `safe` scripts must not alter server state. |
| `shortport.http` | Gates the script on an HTTP-like service across the common ports and TLS variants. |
| `stdnse.output_table()` | Structured return value that Nmap formats consistently and other tools can parse. |
| `http.get(host, port, path)` | Bounded single request with Nmap's own timeout and redirect handling. |

## Worked Contrast

**Script That Ignores Categories and Returns a String:**

```lua
local stdnse = require "stdnse"

action = function(host, port)
  local sock = nmap.new_socket()
  sock:connect(host.ip, port.number)  -- BUG: no category, no timeout, mutates nothing but blocks
  return "done"                      -- BUG: string output, no evidence
end
```

**Categorised Script With a Structured Result:**

```lua
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local resp = http.get(host, port, "/")
  if not resp then
    return nil
  end
  local out = stdnse.output_table()
  out.status = resp.status
  out.server = resp.header["server"]
  out.bytes = #(resp.body or "")
  return out
end
```

**Why this matters:** A script with no category can be selected by an operator's `-sC` default and then run against every host with no opt-in, and a bare string result cannot be compared between hosts. Declaring `safe`/`discovery`, gating on the service, and returning a table makes the script's intrusiveness explicit and its output diffable.

## When It Is NOT This Issue

- **Script in `intrusive` never run.** A finding that requires an intrusive script is not observed during a default scan; the absence of output proves nothing.
- **Port filtered rather than closed.** A filtered port means the probe never reached the service; the script's silence is a firewall artefact.
- **Version detection mismatch.** Nmap's service guess can differ from the real server; confirm with a direct request.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `shortport.http` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `nmap-nse-audit-script-authoring` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: nmap-nse-audit-script-authoring
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `shortport.http`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile nmap_nse_audit_script.py; python nmap_nse_audit_script.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`async-http-and-dns-audit-scripting`](../async-http-and-dns-audit-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `nmap-nse-audit-script-authoring` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | OffsecCyber (1), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
