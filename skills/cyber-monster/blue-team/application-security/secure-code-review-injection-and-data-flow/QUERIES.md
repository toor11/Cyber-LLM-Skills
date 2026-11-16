# Detection Queries and Telemetry Artifacts

> Sub-skill: [`secure-code-review-injection-and-data-flow`](SKILL.md) | Family: **Application Security**

Source-to-sink queries for the injection branch. Each row narrows the candidate list; the finding still needs the differential.

## Source Inventory

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Request-bound names | framework binding sites (`request.args`, `req.query`, `@RequestParam`) | Every bound name traced to at least one sink or marked display-only |
| Deserialised bodies | `json.loads`, `yaml.load`, `unmarshal`, `ObjectMapper.readValue` | Typed target or explicit schema; no polymorphic type selection from input |
| Third-party responses | HTTP client call sites used to build queries or paths | Treated as untrusted; validated before use |

## Sink Grammar

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Identifier sinks | `ORDER BY`/`GROUP BY` interpolation, `Table(`, dynamic column maps | Closed allowlist at every site |
| Command sinks | `shell=True`, `exec(`, backticks, `Runtime.exec` with one string | Argv-array form only |
| Path sinks | `open(`/`send_file` with a joined path | Resolved and prefix-checked |
| Template sinks | `render_template_string`, `Template(`, `eval` of template text | Static template with a context object |

## Differential

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Grammar break | quote, backtick, `${}`, `{{7*7}}` in a bound field | Same response class as the benign value |
| Traversal | `../` and encoded variants against a path parameter | 404 with no filesystem error |
| Operator object | JSON body field as `{"$ne": null}` | Schema rejection, no query executed |

## Telemetry Prerequisites

- The framework's binding configuration, so the source list is complete.
- A test instance with a seeded record whose value contains every metacharacter the sinks care about.
- Response and error-log capture, because the differential often shows up as an error class rather than a body change.

## Deployment Gates

- No sink is cleared without naming its inert form and the line where it runs.
- Re-run the differential after any change to validation middleware, since a reordered chain is the usual regression.
