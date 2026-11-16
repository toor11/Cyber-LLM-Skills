# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-modeling`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `pytm` | `python -m pytm.threatmodel --dfd --seq model.py` | Generate a data-flow diagram from a declarative model so the diagram and the element list cannot diverge | Cross-platform |
| `threagile` | `threagile -model model.yaml -output-dir out -generate-report-pdf` | Validate a YAML model against built-in rules and emit a risk register | Cross-platform |
| `OWASP Threat Dragon` | open the `.json` model file in the desktop app or web instance | Reviewer-facing diagram with per-element threat links | Desktop/web |
| `graphviz` | `dot -Tsvg dfd.dot -o dfd.svg` | Render the diagram you actually ship alongside the model | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```yaml
# threagile-compatible minimum: boundaries carry the control, assets carry the data class.
technical_assets:
  checkout-api:
    usage: business
    technology: web-service
    internet: true
    data_assets: [order_pii]
    communication_links:
      to_payments:
        target: payments-svc
        protocol: https
        authentication: mtls
trust_boundaries:
  - {id: edge, description: "public to edge"}
  - {id: payments, description: "checkout to payments"}
```

## Verification

- The model file parses with the tool's own validator before you circulate a diagram; a model that fails validation is not evidence.
- Every `communication_link` names its authentication, because an unnamed link is the finding.
- The rendered diagram and the shipped model come from the same file, so a reviewer cannot be shown a stale picture.
