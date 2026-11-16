# Detection Queries and Telemetry Artifacts

> Sub-skill: [`secure-code-review-language-specific-review`](SKILL.md) | Family: **Application Security**

Language-construct checks. Each row names the pattern to search and what a hit proves.

## Deserialisation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Ruby | `YAML.load`, `Marshal.load`, `Oj.load` without mode | Object instantiation from the supplied bytes |
| Python | `pickle.load(s)`, `dill`, `torch.load` without `weights_only` | Code execution at load |
| Java | `readObject`, `XStream`, `TypeNameHandling` equivalents | Gadget chain reachable from the stream |
| PHP | `unserialize`, `phar://` stream wrappers | Magic-method execution during deserialisation |

## Object Model

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Prototype pollution | recursive merge, `Object.assign` from parsed JSON, `lodash.merge` on request bodies | Write through the prototype chain |
| Mass assignment | `setattr`, `update_attributes` without permit, `ShouldBind` into an entity | Caller sets a protected attribute |

## Filesystem and Paths

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Go | `filepath.Join` with request data, `os.Open` on a joined path | Traversal outside the base directory |
| Ruby/Python | `send_file`, `open(` with a joined path | Same class; check the prefix comparison after resolution |

## Telemetry Prerequisites

- The exact language and library versions, because several safe defaults are version-gated.
- A dependency inventory for the language, since gadget availability depends on libraries present.
- The ability to submit the probe payload to a staging instance, not only to read the source.

## Deployment Gates

- The construct list is reviewed on language or major-version upgrade, not once per project.
- Every hit is dispositioned with the inert form or the reachability argument; no silent passes.
