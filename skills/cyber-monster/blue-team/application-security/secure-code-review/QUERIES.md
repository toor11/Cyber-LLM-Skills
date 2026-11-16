# Detection Queries and Telemetry Artifacts

> Sub-skill: [`secure-code-review`](SKILL.md) | Family: **Application Security**

Repository and pipeline checks that produce review evidence. Each row states the artefact you collect and what a true positive looks like; a query that returns rows without a witness path is a lead, not a finding.

## Entry Point Inventory

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Route table dump | framework route registry (`flask routes`, `manage.py show_urls`, `Routes` in Rails, `@RequestMapping` scan) | Every handler that binds request data appears with its middleware chain |
| Authorization decorator coverage | handler list minus handlers carrying an auth decorator/dependency | Empty for authenticated blueprints; non-empty only for routes documented as public |
| Server Action / resolver inventory | files containing `'use server'` or GraphQL `@Query`/`@Mutation` | Each one has an in-body authorisation call, not just a parent layout guard |

## Sink Classification

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Interpolated SQL | grep for `f"SELECT`, `% (`, `+ " WHERE`, `query(` with template literal | Match whose interpolated segment is a request variable or identifier, not a module constant |
| Template source construction | `render_template_string`, `Template(`, `eval` of template text, `dangerouslySetInnerHTML` | Match where the template *source*, not the context, is caller-controlled |
| Shell invocation | `shell=True`, `child_process.exec(`, `Runtime.exec(String)`, backticks | Match where the command string is built from request data; argv-array calls are excluded |
| Deserialisation | `pickle.loads`, `yaml.load` without `SafeLoader`, `readObject`, `TypeNameHandling.All` | Match on a request-derived byte stream, not on internal caches |

## Differential Probes

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Tenant swap | second-tenant object id in the path while authenticated as tenant A | `404`/`403` under the fixed build; `200` with foreign body under the vulnerable build |
| Metacharacter inertness | quote, `../`, `;`, `$()` in a field the sink consumes | Byte-identical response and no new error class in logs |
| Content-type confusion | same payload as JSON, form, and multipart | All three rejected identically when validation is at the boundary |

## Telemetry Prerequisites

- Read access to the repository at the reviewed commit, including the deployment config the app actually loads (not the sample).
- The framework's routing table can be dumped, so entry points come from configuration rather than from a hand-written list.
- A running instance or test harness where a two-account differential can be replayed without touching production data.

## Deployment Gates

- Attach the witness path (request, file:line sink, missing predicate) to every finding; findings without one are downgraded to questions.
- Record cleared sinks with the reason they are inert so a later refactor does not 'fix' them into a vulnerability.
