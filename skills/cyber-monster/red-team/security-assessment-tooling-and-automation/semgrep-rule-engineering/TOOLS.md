# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`semgrep-rule-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Semgrep 1.1xx rule schema (`rules:`, `mode: taint`, `pattern-sources`, `pattern-sanitizers`, `pattern-sinks`, `paths:`, `focus-metavariable`).
- **Validation Gate:** `semgrep --validate --config rule.yaml && semgrep --test rule.yaml`.
- Recent releases added built-in taint propagators for `--pro-intrafile` scans and `metavariable-type` on class metavariables; rules relying on explicit propagators for containers may report more without them.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `semgrep` | `semgrep --validate --config rule.yaml` | Schema and syntax validation without scanning | Cross-platform |
| `semgrep` | `semgrep --test rule.yaml` | Run the inline ruleid/ok fixtures | Cross-platform |
| `semgrep` | `semgrep --config rule.yaml --sarif --output=out.sarif src/` | Produce a SARIF document for the merge pipeline | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```yaml
rules:
  - id: python-raw-sql-taint
    mode: taint
    languages: [python]
    severity: ERROR
    message: Untrusted request data reaches cursor.execute without binding.
    paths:
      include: ["src/**"]
    pattern-sources:
      - pattern: flask.request.args.get(...)
    pattern-sanitizers:
      - pattern: int(...)
    pattern-sinks:
      - patterns:
          - pattern: $CURSOR.execute($SQL, ...)
          - focus-metavariable: $SQL
```
