# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`nuclei-template-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Nuclei v3 template schema; `requests:` was replaced by `http:` and is deprecated.
- **Validation Gate:** `nuclei -validate -t template.yaml` before any run, then a two-host differential.
- `matchers-condition` defaults to OR: an unset condition with two matchers is the most common cause of template false positives.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nuclei` | `nuclei -validate -t template.yaml` | Schema and syntax validation without sending traffic | Cross-platform |
| `nuclei` | `nuclei -t template.yaml -u https://target.example -jsonl -o out.jsonl` | Single-target run with machine-readable output | Cross-platform |
| `nuclei` | `nuclei -t template.yaml -l hosts.txt -rate-limit 10` | Rate-limited run across an authorised host list | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```yaml
id: exposed-config-metadata
info:
  name: Application config metadata exposed
  severity: low
  author: audit
http:
  - method: GET
    path:
      - "{{BaseURL}}/config.json"
    max-redirects: 0
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: header
        words:
          - application/json
      - type: dsl
        dsl:
          - "contains(body, '\"buildId\"')"
    extractors:
      - type: regex
        part: body
        regex:
          - '"buildId"\s*:\s*"([^"]+)"'
        group: 1
```
